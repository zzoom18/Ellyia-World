import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { verify, issueToken, readToken, mint, tierByName, TIERS, SELLABLE_TIERS, TRIAL_TIER } from './lib/keys.js';
import { verifyGoogleToken } from './lib/google.js';
import { hashPassword, checkPassword, passwordProblem } from './lib/password.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, 'public');
/* Reported by /api/health, so "which build is live?" is one URL away when a
   deploy looks like it did not take. */
let APP_VERSION = 'unknown';
try { APP_VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version || APP_VERSION; } catch { /* keep 'unknown' */ }

const PORT = Number(process.env.PORT) || 3000;
const KEY_SECRET = process.env.KEY_SECRET;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const TOKEN_DAYS = Number(process.env.TOKEN_DAYS) || 90;
const REVOKED = new Set(
  (process.env.REVOKED_KEYS || '').split(',').map((k) => k.trim().toUpperCase()).filter(Boolean)
);
// Comma-separated origins, or "*" for any. The app is served from this same
// origin by default, so the list only matters if you host the page elsewhere.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map((o) => o.trim()).filter(Boolean);
const TRIAL_DAYS = Number(process.env.TRIAL_DAYS) || 7;
// Most redeploys (a fresh tarball extracted over the app folder, a container
// rebuild) replace ROOT entirely, so a DATA_DIR inside it silently loses
// every registration and every child's saved stars on the next deploy. The
// account's actual home directory is not part of that app folder and is not
// touched by re-extracting it, so it survives a redeploy without needing a
// DATA_DIR environment variable to be set anywhere — which matters on hosts
// (Hostinger's Node.js hosting among them) that don't expose one to set.
const DATA_DIR = process.env.DATA_DIR || path.join(os.homedir(), '.papercub-data');
const REGISTRATIONS = path.join(DATA_DIR, 'registrations.jsonl');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const GRANTS_FILE = path.join(DATA_DIR, 'grants.json');
const WRITINGS_FILE = path.join(DATA_DIR, 'writings.json');
const PASSWORDS_FILE = path.join(DATA_DIR, 'passwords.json');

/* One-time move for anyone upgrading from before this default changed: if a
 * host happens to keep the app folder across deploys (rather than the usual
 * fresh-copy-every-time), registrations and progress saved under the old
 * default — inside the app folder — would otherwise go silently unread the
 * moment this new default takes over. Only runs when nobody has set DATA_DIR
 * themselves, and only copies once (it never overwrites an already-started
 * new location). A no-op wherever the old folder never existed. */
(function migrateLegacyDataDir() {
  if (process.env.DATA_DIR) return;
  const legacy = path.join(ROOT, 'data');
  try {
    if (fs.existsSync(legacy) && !fs.existsSync(DATA_DIR)) {
      fs.cpSync(legacy, DATA_DIR, { recursive: true });
      console.log(`[data] migrated ${legacy} -> ${DATA_DIR}`);
    }
  } catch (err) {
    console.error('[data] legacy migration failed:', err.message);
  }
})();
// Optional: POST each signup somewhere else too (a mailing list, a sheet).
const REGISTRATION_WEBHOOK = process.env.REGISTRATION_WEBHOOK || '';

if (!KEY_SECRET) {
  console.error('KEY_SECRET is not set. Generate one with: openssl rand -hex 32');
  process.exit(1);
}
if (KEY_SECRET.length < 32) {
  console.error('KEY_SECRET is too short — use at least 32 characters.');
  process.exit(1);
}

/* ---------- settings and grants ----------
   Who gets what is a runtime decision, not a deploy-time one: the owner flips
   open access on or off from the admin page without touching the server. */
let settings = { openAccess: true, defaultTier: 'full', adsEnabled: true, adsEveryRounds: 10 };
let grants = {};   // email -> tier id, set per person from the admin page

/* What every device is told about the ad break on sign-in/verify: whether it
   runs at all, and how many finished rounds apart. A per-account override
   (progress.adsDisabled, set by POST /api/admin/account) can still turn it
   off for one child even while this stays on for everyone else. */
function adsConfig() {
  return {
    enabled: settings.adsEnabled !== false,
    everyRounds: Math.max(1, Math.min(100, Math.floor(Number(settings.adsEveryRounds)) || 10))
  };
}
// A child's own sentence, waiting for a parent to look at it before it can
// ever appear to anyone else. Nothing here is shown to another family until
// its status is 'approved'.
let writings = [];
/* Account passwords, keyed by the same hash of the address the progress files
   use, so this file does not read as a mailing list either. Values are scrypt
   records from lib/password.js — never the password itself. An account with no
   entry here signs in by email alone, as every account did before passwords
   existed; the first password it sets closes that door. */
let passwords = {};

function loadStore(){
  try {
    const raw = JSON.parse(fs.readFileSync(PASSWORDS_FILE, 'utf8'));
    if (raw && typeof raw === 'object') passwords = raw;
  } catch { /* none yet */ }
  try {
    const raw = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    if (raw && typeof raw === 'object') settings = { ...settings, ...raw };
  } catch { /* first run, or unreadable — the defaults stand */ }
  try {
    const raw = JSON.parse(fs.readFileSync(GRANTS_FILE, 'utf8'));
    if (raw && typeof raw === 'object') grants = raw;
  } catch { /* none yet */ }
  try {
    const raw = JSON.parse(fs.readFileSync(WRITINGS_FILE, 'utf8'));
    if (Array.isArray(raw)) writings = raw;
  } catch { /* none yet */ }
}
function persist(file, value){
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
    return true;
  } catch (err) {
    console.error('[store] could not write', path.basename(file) + ':', err.message);
    return false;
  }
}
loadStore();

/** What this person is entitled to right now, in this order: a personal grant,
 *  then open access, then the ordinary free trial. */
function entitlementFor(email) {
  const granted = grants[String(email || '').toLowerCase()];
  if (granted) {
    try { return { tier: tierByName(granted), days: TOKEN_DAYS, reason: 'granted' }; }
    catch { /* a tier that no longer exists — fall through */ }
  }
  if (settings.openAccess) {
    try { return { tier: tierByName(settings.defaultTier), days: TOKEN_DAYS, reason: 'open' }; }
    catch { return { tier: 3, days: TOKEN_DAYS, reason: 'open' }; }
  }
  return { tier: TRIAL_TIER, days: TRIAL_DAYS, reason: 'trial' };
}

/* ---------- rate limiting ----------
   A wrong key should cost the guesser real time. In-memory is the right scope:
   one instance, and a restart clearing the counters is harmless. */
const attempts = new Map();
const WINDOW_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 12;

function rateLimited(ip) {
  const now = Date.now();
  const hits = (attempts.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  attempts.set(ip, hits);
  return hits.length >= MAX_ATTEMPTS;
}
function recordAttempt(ip) {
  const hits = attempts.get(ip) || [];
  hits.push(Date.now());
  attempts.set(ip, hits);
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, hits] of attempts) {
    const live = hits.filter((t) => now - t < WINDOW_MS);
    if (live.length) attempts.set(ip, live);
    else attempts.delete(ip);
  }
}, WINDOW_MS).unref();

/* ---------- plumbing ---------- */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8'
};

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function corsHeaders(req) {
  const origin = req.headers.origin;
  if (!origin) return {};
  const allowed = ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin);
  if (!allowed) return {};
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-headers': 'content-type,authorization',
    'access-control-allow-methods': 'POST,GET,OPTIONS',
    'vary': 'Origin'
  };
}

function sendJson(req, res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...corsHeaders(req)
  });
  res.end(payload);
}

function readBody(req, limit = 8 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('invalid json'));
      }
    });
    req.on('error', reject);
  });
}

function serveStatic(req, res, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : decodeURIComponent(urlPath).replace(/^\/+/, '');
  const file = path.join(PUBLIC, rel);
  // Never serve anything outside public/, whatever the path contains.
  if (!file.startsWith(PUBLIC + path.sep) && file !== path.join(PUBLIC, 'index.html')) {
    res.writeHead(403).end('Forbidden');
    return;
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      // Unknown paths fall through to the app, so deep links keep working.
      fs.readFile(path.join(PUBLIC, 'index.html'), (e2, html) => {
        if (e2) return res.writeHead(404).end('Not found');
        res.writeHead(200, { 'content-type': MIME['.html'], 'cache-control': 'no-cache' }).end(html);
      });
      return;
    }
    const ext = path.extname(file).toLowerCase();
    // index.html and content.js are one unit: the page calls into the banks the
    // script defines. A browser holding yesterday's content.js beside today's
    // HTML gets "PC is not defined" and a dead page, so neither is ever cached.
    // Only truly static assets (images, fonts) get a long life.
    const mustRevalidate = ext === '.html' || ext === '.js' || ext === '.webmanifest';
    res.writeHead(200, {
      'content-type': MIME[ext] || 'application/octet-stream',
      'cache-control': mustRevalidate ? 'no-cache' : 'public, max-age=86400',
      'x-content-type-options': 'nosniff'
    });
    res.end(data);
  });
}

/* ---------- registrations ---------- */

// Separate from the activation limiter: signing up is a different action with
// a different sensible ceiling.
const signups = new Map();
const SIGNUP_WINDOW_MS = 24 * 60 * 60 * 1000;
// A school, a childcare centre or a family on shared wifi all arrive from one
// address. Five a day turned honest classrooms away, so the ceiling is set
// where it still stops a script but never a real group of children.
const MAX_SIGNUPS = 40;

function signupLimited(ip) {
  const now = Date.now();
  const hits = (signups.get(ip) || []).filter((t) => now - t < SIGNUP_WINDOW_MS);
  signups.set(ip, hits);
  return hits.length >= MAX_SIGNUPS;
}

function looksLikeEmail(value) {
  const email = String(value || '').trim();
  if (email.length < 6 || email.length > 254) return false;
  // Deliberately loose: the only thing that really proves an address is sending
  // to it, and rejecting unusual-but-valid addresses costs a sale.
  return /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(email);
}

function recordRegistration(entry) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.appendFileSync(REGISTRATIONS, JSON.stringify(entry) + '\n');
  } catch (err) {
    // A full or read-only disk must not cost us the signup — the parent still
    // gets their trial, we just lose the mailing-list row.
    console.error('[register] could not save registration:', err.message);
  }
  if (REGISTRATION_WEBHOOK) {
    fetch(REGISTRATION_WEBHOOK, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(entry)
    }).catch((err) => console.error('[register] webhook failed:', err.message));
  }
}

/* ---------- routes ---------- */

async function handleRegister(req, res) {
  const ip = clientIp(req);
  if (signupLimited(ip)) {
    return sendJson(req, res, 429, {
      ok: false,
      error: 'too_many_signups',
      message: 'That is a lot of trials from one place. Get in touch and we will sort you out.'
    });
  }

  let body;
  try {
    body = await readBody(req);
  } catch {
    return sendJson(req, res, 400, { ok: false, error: 'bad_request' });
  }

  const name = String(body.name || '').trim().slice(0, 60);
  const email = String(body.email || '').trim().slice(0, 254);

  if (!name) {
    return sendJson(req, res, 400, { ok: false, error: 'name_required', message: 'Please tell us your name.' });
  }
  if (!looksLikeEmail(email)) {
    return sendJson(req, res, 400, { ok: false, error: 'email_invalid', message: 'That email address does not look right.' });
  }
  if (readProgress(email.toLowerCase())?.banned) {
    return sendJson(req, res, 403, { ok: false, error: 'banned', message: 'This account has been suspended.' });
  }

  /* The password, if the account has one, is the only thing that proves this
     is the same family and not just someone who knows the address. Accounts
     from before passwords existed have none, and still sign in by email
     alone until they set one (the profile sheet asks them to). A brand-new
     sign-up chooses one on the spot. */
  const password = typeof body.password === 'string' ? body.password : '';
  const stored = passwordOf(email);
  let passwordSet = false;
  if (stored) {
    if (rateLimited(ip)) {
      return sendJson(req, res, 429, { ok: false, error: 'too_many_attempts',
        message: 'Too many tries. Please wait ten minutes and try again.' });
    }
    if (!password) {
      return sendJson(req, res, 401, { ok: false, error: 'password_required',
        message: 'This account has a password. Please type it to sign in.' });
    }
    if (!checkPassword(password, stored)) {
      recordAttempt(ip);
      return sendJson(req, res, 401, { ok: false, error: 'wrong_password',
        message: 'That password does not match. Please try again.' });
    }
  } else if (password || body.mode === 'new') {
    const problem = passwordProblem(password);
    if (problem) return sendJson(req, res, 400, { ok: false, error: 'password_invalid', message: problem });
    if (!setPassword(email, password)) {
      return sendJson(req, res, 500, { ok: false, error: 'password_not_saved',
        message: 'We could not save that password. Please try again in a moment.' });
    }
    passwordSet = true;
  }

  signups.set(ip, [...(signups.get(ip) || []), Date.now()]);

  const ent = entitlementFor(email);
  const token = issueToken(KEY_SECRET, { tier: ent.tier, serial: 0, days: ent.days, email });
  recordRegistration({
    at: new Date().toISOString(),
    name,
    email: email.toLowerCase(),
    child: String(body.child || '').trim().slice(0, 40) || null,
    ip,
    ua: String(req.headers['user-agent'] || '').slice(0, 200)
  });

  const licence = TIERS[ent.tier];
  console.log(`[register] ${email.toLowerCase()} access=${ent.reason} tier=${licence.id} password=${stored ? 'checked' : passwordSet ? 'set' : 'none'} ip=${ip}`);
  return sendJson(req, res, 200, {
    ok: true,
    token,
    hasPassword: !!(stored || passwordSet),
    trialDays: ent.days,
    licence: { id: licence.id, name: licence.name, maxPages: licence.maxPages, commercial: licence.commercial, trial: !!licence.trial },
    ads: adsConfig()
  });
}

/* ---------- saved progress ----------
 *
 * Stars, levels and badges used to live in localStorage and nowhere else, so
 * a cleared browser or a second iPad meant starting again. They are now kept
 * against the account the token was issued to.
 *
 * One file per account, named by a hash of the address rather than the
 * address itself — the progress directory should not read as a mailing list
 * to anyone who gets a look at the disk.
 *
 * Merging matters more than saving. A child who plays on a phone and then a
 * tablet must not lose the afternoon's work because the tablet's copy was
 * older, so the two are merged per game, keeping the better of each, rather
 * than one overwriting the other.
 */
const PROGRESS_DIR = path.join(DATA_DIR, 'progress');
const MAX_PROGRESS_BYTES = 64 * 1024;

function progressFile(email) {
  const key = crypto.createHash('sha256').update(`papercub-progress:${email}`).digest('hex').slice(0, 32);
  return path.join(PROGRESS_DIR, `${key}.json`);
}

function readProgress(email) {
  try {
    return JSON.parse(fs.readFileSync(progressFile(email), 'utf8'));
  } catch {
    return null;
  }
}

function writeProgress(email, state) {
  try {
    fs.mkdirSync(PROGRESS_DIR, { recursive: true });
    fs.writeFileSync(progressFile(email), JSON.stringify(state));
    return true;
  } catch (err) {
    console.error('[progress] could not save:', err.message);
    return false;
  }
}

/* ---------- passwords ---------- */
function accountKey(email) {
  return crypto.createHash('sha256').update(`papercub-progress:${String(email || '').toLowerCase()}`).digest('hex').slice(0, 32);
}
function passwordOf(email) {
  const rec = passwords[accountKey(email)];
  return rec && typeof rec.hash === 'string' ? rec.hash : null;
}
function hasPassword(email) { return !!passwordOf(email); }
function setPassword(email, password) {
  passwords[accountKey(email)] = { hash: hashPassword(password), updatedAt: Math.floor(Date.now() / 1000) };
  return persist(PASSWORDS_FILE, passwords);
}
function clearPassword(email) {
  const key = accountKey(email);
  if (!passwords[key]) return false;
  delete passwords[key];
  persist(PASSWORDS_FILE, passwords);
  return true;
}

/* Only the fields the app actually keeps, with sane bounds. Whatever a browser
   posts here comes back to a browser later, so it is rebuilt field by field
   rather than stored as sent. */
/* The quest's own ladder, kept with the rest of the account so a child who
   has climbed to level 40 finds level 40 on any device. */
function cleanQuest(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const hero = String(raw.hero || '').slice(0, 16);
  if (!/^[a-z]{0,16}$/.test(hero)) return null;
  return {
    hero: hero || null,
    level: Math.min(250, Math.max(1, Math.floor(Number(raw.level) || 1))),
    best: Math.min(250, Math.max(1, Math.floor(Number(raw.best) || 1))),
    wins: Math.min(999999, Math.max(0, Math.floor(Number(raw.wins) || 0)))
  };
}

function cleanProgress(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const out = {
    name: String(raw.name || '').slice(0, 14),
    age: Math.min(12, Math.max(3, Number(raw.age) || 5)),
    avatar: String(raw.avatar || '🦊').slice(0, 8),
    avatarHat: raw.avatarHat ? String(raw.avatarHat).slice(0, 8) : null,
    avatarBg: raw.avatarBg ? String(raw.avatarBg).slice(0, 24) : null,
    setup: !!raw.setup,
    /* allUnlocked is deliberately not read from raw here: it is an
       admin-only field, set by POST /api/admin/account (action
       unlockAll/lockAll) directly on the stored record, never derived
       from whatever a client happens to post. mergeProgress carries it
       forward from the existing stored copy only, so a device that synced
       before an admin's change can't echo a stale value back over it. */
    stars: Math.min(999999, Math.max(0, Math.floor(Number(raw.stars) || 0))),
    streak: Math.min(3650, Math.max(0, Math.floor(Number(raw.streak) || 0))),
    perfects: Math.min(999999, Math.max(0, Math.floor(Number(raw.perfects) || 0))),
    roundsPlayed: Math.min(999999, Math.max(0, Math.floor(Number(raw.roundsPlayed) || 0))),
    /* adsDisabled is the same kind of admin-only field as allUnlocked above:
       never read from raw here, only ever carried forward from the stored
       copy by mergeProgress, and set by POST /api/admin/account (action
       disableAds/enableAds). */
    lastPlayed: String(raw.lastPlayed || '').slice(0, 10),
    motion: raw.motion !== false,
    sound: raw.sound !== false,
    music: raw.music !== false,
    readAloud: raw.readAloud !== false,
    quest: cleanQuest(raw.quest),
    progress: {},
    updatedAt: Math.floor(Date.now() / 1000)
  };
  const src = raw.progress && typeof raw.progress === 'object' ? raw.progress : {};
  let n = 0;
  for (const id of Object.keys(src)) {
    if (n++ >= 200) break;
    if (!/^[a-z0-9_-]{1,24}$/i.test(id)) continue;
    const p = src[id];
    if (!p || typeof p !== 'object') continue;
    out.progress[id] = {
      level: Math.min(99, Math.max(1, Math.floor(Number(p.level) || 1))),
      stars: Math.min(99999, Math.max(0, Math.floor(Number(p.stars) || 0)))
    };
  }
  return out;
}

/* The better of the two, game by game. Nothing a child has earned is dropped
   because the other device had not heard about it yet. */
function mergeProgress(mine, theirs) {
  if (!mine) return theirs;
  if (!theirs) return mine;
  const newer = (Number(theirs.updatedAt) || 0) >= (Number(mine.updatedAt) || 0) ? theirs : mine;
  const merged = {
    ...newer,
    stars: Math.max(Number(mine.stars) || 0, Number(theirs.stars) || 0),
    perfects: Math.max(Number(mine.perfects) || 0, Number(theirs.perfects) || 0),
    streak: Math.max(Number(mine.streak) || 0, Number(theirs.streak) || 0),
    roundsPlayed: Math.max(Number(mine.roundsPlayed) || 0, Number(theirs.roundsPlayed) || 0),
    setup: !!(mine.setup || theirs.setup),
    /* Always the existing stored copy's value, never theirs (the incoming
       client post) — cleanProgress never derives either field from client
       input, so theirs.allUnlocked/adsDisabled/banned are always undefined
       here anyway. This is what stops a device that synced before an
       admin's change from echoing a stale value back over it once the
       admin flips it. */
    allUnlocked: !!mine.allUnlocked,
    adsDisabled: !!mine.adsDisabled,
    banned: !!mine.banned,
    progress: {}
  };
  const a = mine.quest, b = theirs.quest;
  if (a || b) {
    merged.quest = (!a) ? b : (!b) ? a
      : { hero: (b.hero || a.hero), level: Math.max(a.level, b.level),
          best: Math.max(a.best, b.best), wins: Math.max(a.wins, b.wins) };
  }
  const ids = new Set([...Object.keys(mine.progress || {}), ...Object.keys(theirs.progress || {})]);
  for (const id of ids) {
    const a = (mine.progress || {})[id] || { level: 1, stars: 0 };
    const b = (theirs.progress || {})[id] || { level: 1, stars: 0 };
    merged.progress[id] = {
      level: Math.max(Number(a.level) || 1, Number(b.level) || 1),
      stars: Math.max(Number(a.stars) || 0, Number(b.stars) || 0)
    };
  }
  return merged;
}

async function handleProgress(req, res) {
  let body;
  try { body = await readBody(req, MAX_PROGRESS_BYTES); }
  catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  const result = readToken(KEY_SECRET, body.token);
  if (!result.ok) return sendJson(req, res, 401, { ok: false, error: result.reason });
  if (!result.email) {
    // A key activated without registering has no account to save against.
    return sendJson(req, res, 200, { ok: true, saved: false, reason: 'no_account' });
  }

  const stored = readProgress(result.email);

  if (req.method === 'GET' || !body.state) {
    return sendJson(req, res, 200, { ok: true, state: stored, email: result.email, hasPassword: hasPassword(result.email) });
  }

  const incoming = cleanProgress(body.state);
  if (!incoming) return sendJson(req, res, 400, { ok: false, error: 'bad_state' });

  const merged = mergeProgress(stored, incoming);
  const saved = writeProgress(result.email, merged);
  // The page shows "signed in as", so it needs the address back on every
  // reply, not only on the read-only branch.
  return sendJson(req, res, 200, { ok: true, saved, state: merged, email: result.email, hasPassword: hasPassword(result.email) });
}

/* ---------- Sign in with Google ----------
 *
 * The browser gets an ID token from Google Identity Services and posts it
 * here. We verify it ourselves rather than trusting it: fetch Google's public
 * keys, check the RS256 signature, then check the issuer, the audience, the
 * expiry and that Google has actually verified the address. Only then does the
 * email count as proven, and the account is created exactly as a typed
 * registration would create it.
 *
 * No library: node:crypto reads a JWK directly.
 */
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const JWKS_TTL_MS = 60 * 60 * 1000;
// Google rotates these keys, so they are refetched rather than pinned. The
// previous set is kept as a fallback for the moment a fetch fails mid-rotation.
let jwksCache = { keys: [], fetchedAt: 0 };

async function googleKeys() {
  const fresh = Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS;
  if (jwksCache.keys.length && fresh) return jwksCache.keys;
  try {
    const res = await fetch(GOOGLE_JWKS_URL, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error(`status ${res.status}`);
    const body = await res.json();
    if (Array.isArray(body.keys) && body.keys.length) {
      jwksCache = { keys: body.keys, fetchedAt: Date.now() };
    }
  } catch (err) {
    console.error('[google] could not fetch signing keys:', err.message);
    if (!jwksCache.keys.length) throw new Error('keys_unavailable');
  }
  return jwksCache.keys;
}

async function handleGoogle(req, res) {
  if (!GOOGLE_CLIENT_ID) {
    return sendJson(req, res, 503, {
      ok: false, error: 'google_not_configured',
      message: 'Google sign-in is not set up on this site yet.'
    });
  }

  const ip = clientIp(req);
  if (signupLimited(ip)) {
    return sendJson(req, res, 429, {
      ok: false, error: 'too_many_signups',
      message: 'That is a lot of sign-ins from one place. Get in touch and we will sort you out.'
    });
  }

  let body;
  try { body = await readBody(req); } catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  let claims;
  try {
    claims = verifyGoogleToken(body.credential, { keys: await googleKeys(), clientId: GOOGLE_CLIENT_ID });
  } catch (err) {
    console.error('[google] rejected a sign-in:', err.message);
    return sendJson(req, res, 401, {
      ok: false, error: 'google_rejected',
      message: 'Google could not confirm that sign-in. Please try again.'
    });
  }

  const email = String(claims.email).trim().slice(0, 254).toLowerCase();
  const name = String(claims.name || claims.given_name || '').trim().slice(0, 60) || email.split('@')[0];

  signups.set(ip, [...(signups.get(ip) || []), Date.now()]);

  const ent = entitlementFor(email);
  const token = issueToken(KEY_SECRET, { tier: ent.tier, serial: 0, days: ent.days, email });
  recordRegistration({
    at: new Date().toISOString(),
    name,
    email,
    child: String(body.child || '').trim().slice(0, 40) || null,
    via: 'google',
    ip,
    ua: String(req.headers['user-agent'] || '').slice(0, 200)
  });

  const licence = TIERS[ent.tier];
  console.log(`[google] ${email} access=${ent.reason} tier=${licence.id} ip=${ip}`);
  return sendJson(req, res, 200, {
    ok: true,
    token,
    name,
    email,
    hasPassword: hasPassword(email),
    trialDays: ent.days,
    licence: { id: licence.id, name: licence.name, maxPages: licence.maxPages, commercial: licence.commercial, trial: !!licence.trial },
    ads: adsConfig()
  });
}

async function handleSettings(req, res) {
  if (!requireAdmin(req, res)) return;

  if (req.method === 'GET') {
    return sendJson(req, res, 200, {
      ok: true,
      settings,
      grants,
      tiers: SELLABLE_TIERS.map((n) => ({ id: TIERS[n].id, name: TIERS[n].name })),
      trialDays: TRIAL_DAYS,
      registrations: countRegistrations()
    });
  }

  let body;
  try { body = await readBody(req); } catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  if (typeof body.openAccess === 'boolean') settings.openAccess = body.openAccess;
  if (typeof body.defaultTier === 'string') {
    try { tierByName(body.defaultTier); settings.defaultTier = body.defaultTier.toLowerCase(); }
    catch (e) { return sendJson(req, res, 400, { ok: false, error: 'bad_tier', message: e.message }); }
  }
  if (typeof body.adsEnabled === 'boolean') settings.adsEnabled = body.adsEnabled;
  if (body.adsEveryRounds !== undefined) {
    const n = Math.floor(Number(body.adsEveryRounds));
    if (!Number.isFinite(n) || n < 1 || n > 100) {
      return sendJson(req, res, 400, { ok: false, error: 'bad_ads_every', message: 'Pick a number of rounds between 1 and 100.' });
    }
    settings.adsEveryRounds = n;
  }
  const saved = persist(SETTINGS_FILE, settings);
  console.log(`[admin] openAccess=${settings.openAccess} defaultTier=${settings.defaultTier} adsEnabled=${settings.adsEnabled} adsEveryRounds=${settings.adsEveryRounds}`);
  return sendJson(req, res, 200, { ok: true, settings, saved });
}

async function handleGrant(req, res) {
  if (!requireAdmin(req, res)) return;

  let body;
  try { body = await readBody(req); } catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  const email = String(body.email || '').trim().toLowerCase();
  if (!looksLikeEmail(email)) return sendJson(req, res, 400, { ok: false, error: 'email_invalid' });

  if (body.tier === null || body.tier === '' || body.tier === undefined) {
    delete grants[email];
  } else {
    try { tierByName(body.tier); } catch (e) { return sendJson(req, res, 400, { ok: false, error: 'bad_tier', message: e.message }); }
    grants[email] = String(body.tier).toLowerCase();
  }
  const saved = persist(GRANTS_FILE, grants);
  console.log(`[admin] grant ${email} -> ${grants[email] || 'revoked'}`);
  return sendJson(req, res, 200, { ok: true, grants, saved });
}

/* ---------- a child's own writing or drawing, turned into a game ----------
   Kayden or Ellyia (or anyone playing) types a sentence or draws a picture.
   It sits as 'pending' until a parent looks at it in the admin page and
   approves it - only then does it ever appear to another player, credited
   to whoever made it. A sentence becomes a one-round Sentence Builder,
   unscrambling the child's own words; a drawing becomes a small art card
   that shows the picture full size. Neither is auto-graded or auto-turned
   into a quiz - there is no model in here to write a comprehension question
   from free text or describe a drawing, so a parent decides by hand what,
   if anything, each submission becomes. */
const MAX_PENDING_PER_EMAIL = 5;
/* \n is allowed now that a submission can run to essay length and a child
   might reasonably break it into paragraphs; everything rendering this
   still goes through textContent (see el() in index.html), never innerHTML,
   so there is no more injection risk in allowing it than in any other
   character here. */
const SENTENCE_CHARS = /^[A-Za-z0-9À-ÖØ-öø-ÿ '"():;.,!?\n-]+$/;
const IMAGE_DATA_URL = /^data:image\/(png|jpeg);base64,([A-Za-z0-9+/=]+)$/;
const MAX_IMAGE_BYTES = 260 * 1024; // a simple canvas drawing, not a photo
const MAX_WRITING_BODY_BYTES = 380 * 1024; // room for the base64 inflation

function cleanSentence(raw) {
  const s = String(raw || '').replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
  /* No upper word count any more — a submission can be a whole essay, not
     just a one-line sentence. The character ceiling is just there to keep
     one child's story from being an unbounded amount of storage; a few
     thousand characters is well beyond what a primary-school child types
     in one sitting. Short submissions (a handful of words) still become
     the drag-the-words-into-order game they always did — see playWriting()
     in index.html — while longer ones are read back instead, since a
     reorder puzzle stops being playable well before "long essay" length. */
  if (s.length < 6 || s.length > 4000) return null;
  const words = s.split(/\s+/).filter(Boolean);
  if (words.length < 2) return null;
  if (!SENTENCE_CHARS.test(s)) return null;
  return s;
}

function cleanDrawing(raw) {
  const s = String(raw || '');
  const m = IMAGE_DATA_URL.exec(s);
  if (!m) return null;
  // Base64 inflates by ~4/3; this is an estimate, not a decode, since a
  // multi-hundred-KB string does not need decoding just to size-check it.
  const approxBytes = Math.floor((m[2].length * 3) / 4);
  if (approxBytes > MAX_IMAGE_BYTES) return null;
  return s;
}

async function handleWriting(req, res) {
  if (req.method === 'GET') {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const result = readToken(KEY_SECRET, url.searchParams.get('token'));
    if (!result.ok || !result.email) return sendJson(req, res, 401, { ok: false, error: result.reason || 'no_account' });
    const mine = writings.filter((w) => w.email === result.email)
      .map((w) => ({ id: w.id, type: w.type || 'sentence', sentence: w.sentence,
        imageDataUrl: w.imageDataUrl, status: w.status, createdAt: w.createdAt }));
    return sendJson(req, res, 200, { ok: true, writings: mine });
  }

  let body;
  try { body = await readBody(req, MAX_WRITING_BODY_BYTES); }
  catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  const result = readToken(KEY_SECRET, body.token);
  if (!result.ok) return sendJson(req, res, 401, { ok: false, error: result.reason });
  if (!result.email) return sendJson(req, res, 200, { ok: false, error: 'no_account' });

  const type = body.imageDataUrl ? 'drawing' : 'sentence';
  const entry = {
    id: crypto.randomUUID(),
    email: result.email,
    childName: String(body.childName || '').trim().slice(0, 40),
    type,
    status: 'pending',
    createdAt: Date.now(),
  };

  if (type === 'drawing') {
    const imageDataUrl = cleanDrawing(body.imageDataUrl);
    if (!imageDataUrl) {
      return sendJson(req, res, 400, { ok: false, error: 'bad_drawing',
        message: 'That drawing could not be saved. Try again.' });
    }
    entry.imageDataUrl = imageDataUrl;
  } else {
    const sentence = cleanSentence(body.sentence);
    if (!sentence) {
      return sendJson(req, res, 400, { ok: false, error: 'bad_sentence',
        message: 'That needs to be at least a couple of words (up to about 4000 characters), using ordinary letters, numbers and punctuation.' });
    }
    entry.sentence = sentence;
  }

  const pending = writings.filter((w) => w.email === result.email && w.status === 'pending').length;
  if (pending >= MAX_PENDING_PER_EMAIL) {
    return sendJson(req, res, 429, { ok: false, error: 'too_many_pending',
      message: 'Wait for one of your sentences or drawings to be reviewed before sending another.' });
  }

  writings.push(entry);
  const saved = persist(WRITINGS_FILE, writings);
  console.log(`[writing] ${result.email} submitted a ${type}, pending review`);
  return sendJson(req, res, 200, { ok: true, saved, writing: entry });
}

/* Public and read-only: the small set of already-approved submissions,
   which is exactly what a parent chose to let other players see. */
async function handleWritingsApproved(req, res) {
  const approved = writings.filter((w) => w.status === 'approved')
    .map((w) => ({ id: w.id, type: w.type || 'sentence', childName: w.childName || 'A player',
      sentence: w.sentence, imageDataUrl: w.imageDataUrl }));
  return sendJson(req, res, 200, { ok: true, writings: approved });
}

async function handleAdminWritings(req, res) {
  if (!requireAdmin(req, res)) return;

  if (req.method === 'GET') {
    return sendJson(req, res, 200, { ok: true, writings });
  }

  let body;
  try { body = await readBody(req); } catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  const id = String(body.id || '');
  const entry = writings.find((w) => w.id === id);
  if (!entry) return sendJson(req, res, 404, { ok: false, error: 'not_found' });

  if (body.status === 'delete') {
    writings = writings.filter((w) => w.id !== id);
  } else if (['pending', 'approved', 'rejected'].includes(body.status)) {
    entry.status = body.status;
  } else {
    return sendJson(req, res, 400, { ok: false, error: 'bad_status' });
  }
  const saved = persist(WRITINGS_FILE, writings);
  console.log(`[admin] writing ${id} -> ${body.status}`);
  return sendJson(req, res, 200, { ok: true, saved, writings });
}

function readRegistrations() {
  let lines = [];
  try { lines = fs.readFileSync(REGISTRATIONS, 'utf8').split('\n').filter(Boolean); } catch { return []; }
  return lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}
function countRegistrations() {
  const seen = new Set();
  readRegistrations().forEach((r) => seen.add(r.email));
  return { total: readRegistrations().length, unique: seen.size };
}

/* A rough read of the user-agent, enough for an admin to recognise a device.
   Deliberately not a UA-parsing library: this only has to answer "which iPad
   was that" well enough to be useful. */
function describeDevice(ua) {
  const s = String(ua || '');
  if (!s) return '';
  let os = '';
  if (/iPad/.test(s)) os = 'iPad';
  else if (/iPhone/.test(s)) os = 'iPhone';
  else if (/Android/.test(s)) os = /Mobile/.test(s) ? 'Android phone' : 'Android tablet';
  else if (/Windows NT/.test(s)) os = 'Windows';
  else if (/Mac OS X/.test(s)) os = 'Mac';
  else if (/CrOS/.test(s)) os = 'Chromebook';
  else if (/Linux/.test(s)) os = 'Linux';

  let br = '';
  if (/Edg\//.test(s)) br = 'Edge';
  else if (/OPR\//.test(s)) br = 'Opera';
  else if (/SamsungBrowser/.test(s)) br = 'Samsung';
  else if (/Firefox\//.test(s)) br = 'Firefox';
  else if (/Chrome\//.test(s)) br = 'Chrome';
  else if (/Safari\//.test(s)) br = 'Safari';

  return [os, br].filter(Boolean).join(' · ');
}

/* One row per account rather than one per sign-up, because the same family
   signing in from a phone and a tablet is one account, not two people. */
function accountRows() {
  const byEmail = new Map();

  readRegistrations().forEach((r) => {
    const email = String(r.email || '').toLowerCase();
    if (!email) return;
    let a = byEmail.get(email);
    if (!a) {
      a = { email, name: '', child: '', first: r.at, last: r.at, signIns: 0, ips: new Set(), ua: '', via: 'email' };
      byEmail.set(email, a);
    }
    a.signIns++;
    if (r.name) a.name = r.name;
    if (r.child) a.child = r.child;
    if (r.at && (!a.first || r.at < a.first)) a.first = r.at;
    if (r.at && (!a.last || r.at > a.last)) a.last = r.at;
    if (r.ip) a.ips.add(r.ip);
    if (r.ua) a.ua = r.ua;
    if (r.via) a.via = r.via;
    a.lastIp = r.ip || a.lastIp || '';
  });

  return [...byEmail.values()].map((a) => {
    const prog = readProgress(a.email);
    const games = prog && prog.progress ? Object.keys(prog.progress).length : 0;
    return {
      email: a.email,
      name: a.name,
      child: a.child,
      first: a.first,
      last: a.last,
      signIns: a.signIns,
      ip: a.lastIp || '',
      ipCount: a.ips.size,
      device: describeDevice(a.ua),
      via: a.via,
      access: grants[a.email] || (settings.openAccess ? settings.defaultTier + ' (open)' : 'trial'),
      stars: prog ? (Number(prog.stars) || 0) : 0,
      games,
      childAge: prog ? (Number(prog.age) || null) : null,
      playedAt: prog && prog.updatedAt ? new Date(prog.updatedAt * 1000).toISOString() : null,
      allUnlocked: prog ? !!prog.allUnlocked : false,
      adsDisabled: prog ? !!prog.adsDisabled : false,
      banned: prog ? !!prog.banned : false
    };
  }).sort((x, y) => String(y.last || '').localeCompare(String(x.last || '')));
}

/* Removing an account means removing all of it: the sign-up lines, the saved
   progress and any personal grant. Anything left behind would quietly come
   back the next time that address signed in. */
function deleteAccount(email) {
  const target = String(email || '').toLowerCase();
  if (!target) return { ok: false, error: 'no_email' };

  let removedRows = 0;
  try {
    const kept = readRegistrations().filter((r) => {
      const match = String(r.email || '').toLowerCase() === target;
      if (match) removedRows++;
      return !match;
    });
    const body = kept.map((r) => JSON.stringify(r)).join('\n');
    fs.writeFileSync(REGISTRATIONS, body ? body + '\n' : '');
  } catch (err) {
    console.error('[admin] could not rewrite registrations:', err.message);
    return { ok: false, error: 'write_failed' };
  }

  let removedProgress = false;
  try {
    fs.unlinkSync(progressFile(target));
    removedProgress = true;
  } catch { /* nothing saved for this account */ }

  let removedGrant = false;
  if (grants[target]) { delete grants[target]; removedGrant = true; persist(GRANTS_FILE, grants); }
  const removedPassword = clearPassword(target);

  console.log(`[admin] deleted ${target} (${removedRows} sign-ups, progress=${removedProgress}, grant=${removedGrant}, password=${removedPassword})`);
  return { ok: true, removedRows, removedProgress, removedGrant, removedPassword };
}

async function handleAccount(req, res) {
  if (!requireAdmin(req, res)) return;

  let body;
  try { body = await readBody(req); }
  catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  const email = String(body.email || '').trim().toLowerCase();
  if (!email) return sendJson(req, res, 400, { ok: false, error: 'no_email' });

  if (body.action === 'delete') {
    const out = deleteAccount(email);
    return sendJson(req, res, out.ok ? 200 : 500, out);
  }
  if (body.action === 'reset') {
    // Wipe what the child has earned but keep the account and its sign-ups.
    let done = false;
    try { fs.unlinkSync(progressFile(email)); done = true; } catch {}
    console.log(`[admin] reset progress for ${email} (had progress: ${done})`);
    return sendJson(req, res, 200, { ok: true, reset: done });
  }
  if (body.action === 'unlockAll' || body.action === 'lockAll') {
    // A shell record if the child has never actually played anything yet —
    // unlocking should work before their first star, not only after.
    const current = readProgress(email) || cleanProgress({});
    current.allUnlocked = body.action === 'unlockAll';
    current.updatedAt = Math.floor(Date.now() / 1000);
    const saved = writeProgress(email, current);
    console.log(`[admin] ${body.action} for ${email}`);
    return sendJson(req, res, 200, { ok: true, saved, allUnlocked: current.allUnlocked });
  }
  if (body.action === 'disableAds' || body.action === 'enableAds') {
    const current = readProgress(email) || cleanProgress({});
    current.adsDisabled = body.action === 'disableAds';
    current.updatedAt = Math.floor(Date.now() / 1000);
    const saved = writeProgress(email, current);
    console.log(`[admin] ${body.action} for ${email}`);
    return sendJson(req, res, 200, { ok: true, saved, adsDisabled: current.adsDisabled });
  }
  if (body.action === 'clearPassword') {
    // The way back in for a parent who has forgotten: the account goes back
    // to signing in by email alone until they set a new password.
    const cleared = clearPassword(email);
    console.log(`[admin] clearPassword for ${email} (had one: ${cleared})`);
    return sendJson(req, res, 200, { ok: true, cleared });
  }
  if (body.action === 'ban' || body.action === 'unban') {
    // Reversible, unlike the old delete: a banned account keeps its stars
    // and sign-up record, it just can't sign in or stay signed in — see the
    // banned check in handleRegister and handleVerify.
    const current = readProgress(email) || cleanProgress({});
    current.banned = body.action === 'ban';
    current.updatedAt = Math.floor(Date.now() / 1000);
    const saved = writeProgress(email, current);
    console.log(`[admin] ${body.action} for ${email}`);
    return sendJson(req, res, 200, { ok: true, saved, banned: current.banned });
  }
  return sendJson(req, res, 400, { ok: false, error: 'unknown_action' });
}

async function handleRegistrations(req, res) {
  if (!requireAdmin(req, res)) return;
  const rows = readRegistrations();

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const accounts = accountRows();

  if (url.searchParams.get('format') === 'json') {
    return sendJson(req, res, 200, {
      ok: true, rows: accounts.slice(0, 500), total: rows.length, accounts: accounts.length
    });
  }

  const cols = ['email', 'name', 'child', 'child_age', 'first_seen', 'last_seen', 'sign_ins',
    'last_ip', 'distinct_ips', 'device', 'signed_up_via', 'access', 'stars', 'games_played', 'last_played'];
  const csv = cols.join(',') + '\n' + accounts.map((a) =>
    [a.email, a.name, a.child, a.childAge || '', a.first, a.last, a.signIns,
     a.ip, a.ipCount, a.device, a.via, a.access, a.stars, a.games, a.playedAt || '']
      .map((v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`).join(',')
  ).join('\n');
  res.writeHead(200, {
    'content-type': 'text/csv; charset=utf-8',
    'content-disposition': 'attachment; filename="registrations.csv"',
    'cache-control': 'no-store'
  });
  res.end(csv + '\n');
}

async function handleActivate(req, res) {
  const ip = clientIp(req);
  if (rateLimited(ip)) {
    return sendJson(req, res, 429, { ok: false, error: 'too_many_attempts', message: 'Too many tries. Wait 10 minutes and try again.' });
  }

  let body;
  try {
    body = await readBody(req);
  } catch {
    return sendJson(req, res, 400, { ok: false, error: 'bad_request' });
  }

  const result = verify(KEY_SECRET, body.key, REVOKED);
  if (!result.ok) {
    recordAttempt(ip);
    const message =
      result.reason === 'revoked'
        ? 'This key has been cancelled. Reply to your order if you think that is wrong.'
        : "That key doesn't look right. Check your receipt and try again.";
    return sendJson(req, res, 400, { ok: false, error: result.reason, message });
  }

  const token = issueToken(KEY_SECRET, { tier: result.tier, serial: result.serial, days: TOKEN_DAYS });
  console.log(`[activate] tier=${result.licence.id} serial=${result.serial} ip=${ip}`);
  return sendJson(req, res, 200, {
    ok: true,
    token,
    licence: { id: result.licence.id, name: result.licence.name, maxPages: result.licence.maxPages, commercial: result.licence.commercial, trial: !!result.licence.trial }
  });
}

async function handleVerify(req, res) {
  let body;
  try {
    body = await readBody(req);
  } catch {
    return sendJson(req, res, 400, { ok: false, error: 'bad_request' });
  }
  const result = readToken(KEY_SECRET, body.token);
  if (!result.ok) return sendJson(req, res, 401, { ok: false, error: result.reason });
  if (result.email && readProgress(result.email.toLowerCase())?.banned) {
    return sendJson(req, res, 403, { ok: false, error: 'banned', message: 'This account has been suspended.' });
  }

  // Someone holding a trial from before open access was switched on — or who
  // has just paid, or been given a personal grant — gets upgraded here rather
  // than having to sign up again.
  const grantedNow = result.email ? grants[String(result.email).toLowerCase()] : null;
  if (result.licence.trial && (settings.openAccess || grantedNow)) {
    let tier;
    try { tier = tierByName(grantedNow || settings.defaultTier); } catch { tier = 3; }
    const up = TIERS[tier];
    const token = issueToken(KEY_SECRET, { tier, serial: result.serial || 0, days: TOKEN_DAYS, email: result.email });
    return sendJson(req, res, 200, {
      ok: true,
      token,
      upgraded: true,
      hasPassword: !!result.email && hasPassword(result.email),
      licence: { id: up.id, name: up.name, maxPages: up.maxPages, commercial: up.commercial, trial: false },
      ads: adsConfig()
    });
  }

  return sendJson(req, res, 200, {
    ok: true,
    hasPassword: !!result.email && hasPassword(result.email),
    licence: { id: result.licence.id, name: result.licence.name, maxPages: result.licence.maxPages, commercial: result.licence.commercial, trial: !!result.licence.trial },
    expiresAt: result.expiresAt,
    ads: adsConfig()
  });
}

/* ---------- set or change a password ----------
   Signed-in only (the token names the account). An account that already has
   a password must give the current one; one that never had a password is
   simply setting its first. There is no email-based reset here: a parent who
   forgets asks, and the admin page clears it so they can set a new one. */
async function handlePassword(req, res) {
  let body;
  try { body = await readBody(req); }
  catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  const result = readToken(KEY_SECRET, body.token);
  if (!result.ok) return sendJson(req, res, 401, { ok: false, error: result.reason });
  if (!result.email) return sendJson(req, res, 200, { ok: false, error: 'no_account', message: 'Sign in with your email first.' });
  const email = String(result.email).toLowerCase();
  if (readProgress(email)?.banned) {
    return sendJson(req, res, 403, { ok: false, error: 'banned', message: 'This account has been suspended.' });
  }

  const ip = clientIp(req);
  const stored = passwordOf(email);
  if (stored) {
    if (rateLimited(ip)) {
      return sendJson(req, res, 429, { ok: false, error: 'too_many_attempts',
        message: 'Too many tries. Please wait ten minutes and try again.' });
    }
    if (!checkPassword(typeof body.current === 'string' ? body.current : '', stored)) {
      recordAttempt(ip);
      return sendJson(req, res, 401, { ok: false, error: 'wrong_password',
        message: 'Your current password does not match.' });
    }
  }

  const next = typeof body.next === 'string' ? body.next : '';
  const problem = passwordProblem(next);
  if (problem) return sendJson(req, res, 400, { ok: false, error: 'password_invalid', message: problem });
  if (!setPassword(email, next)) {
    return sendJson(req, res, 500, { ok: false, error: 'password_not_saved',
      message: 'We could not save that password. Please try again in a moment.' });
  }
  console.log(`[password] ${stored ? 'changed' : 'set'} for ${email} ip=${ip}`);
  return sendJson(req, res, 200, { ok: true, hasPassword: true });
}

/* ---------- payments (Stripe Checkout) ----------
   A parent pays once and is unlocked without anyone touching the admin page:
   the webhook writes the very same grants[email] = 'full' the "Give full"
   button writes, so everything downstream (entitlementFor, verify upgrade,
   the admin table) already understands it. Stripe is spoken to over plain
   fetch — no SDK, so the app stays dependency-free. Nothing here runs unless
   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET and STRIPE_PRICE_ID are set. */
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || '';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
const PAID_TIER = 'full';
function paymentsEnabled() { return !!(STRIPE_SECRET_KEY && STRIPE_WEBHOOK_SECRET && STRIPE_PRICE_ID); }

function readRawBody(req, limit = 256 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function siteOrigin(req) {
  if (PUBLIC_URL) return PUBLIC_URL;
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  return `${proto}://${req.headers.host || 'localhost'}`;
}

async function handlePayConfig(req, res) {
  return sendJson(req, res, 200, { ok: true, enabled: paymentsEnabled() });
}

async function handlePayCheckout(req, res) {
  if (!paymentsEnabled()) {
    return sendJson(req, res, 503, { ok: false, error: 'payments_not_configured',
      message: 'Payments are not set up yet — ask whoever runs the app to unlock you.' });
  }
  let body;
  try { body = await readBody(req); }
  catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  // Only a signed-in parent can start a checkout, and it is tied to their
  // own address so the webhook knows exactly which account to unlock.
  const tok = readToken(KEY_SECRET, body.token);
  const email = tok.ok && tok.email ? String(tok.email).toLowerCase() : String(body.email || '').trim().toLowerCase();
  if (!looksLikeEmail(email)) return sendJson(req, res, 401, { ok: false, error: 'sign_in_first' });
  if (grants[email]) return sendJson(req, res, 200, { ok: true, already: true });

  const origin = siteOrigin(req);
  const form = new URLSearchParams();
  form.set('mode', 'payment');
  form.set('line_items[0][price]', STRIPE_PRICE_ID);
  form.set('line_items[0][quantity]', '1');
  form.set('customer_email', email);
  form.set('client_reference_id', email);
  form.set('metadata[email]', email);
  form.set('success_url', `${origin}/?paid=1`);
  form.set('cancel_url', `${origin}/?paid=0`);

  try {
    const r = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { authorization: `Bearer ${STRIPE_SECRET_KEY}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString()
    });
    const j = await r.json();
    if (!r.ok || !j.url) {
      console.error('[pay] checkout session failed:', j && j.error ? j.error.message : r.status);
      return sendJson(req, res, 502, { ok: false, error: 'checkout_failed' });
    }
    console.log(`[pay] checkout started for ${email}`);
    return sendJson(req, res, 200, { ok: true, url: j.url });
  } catch (err) {
    console.error('[pay] stripe unreachable:', err.message);
    return sendJson(req, res, 502, { ok: false, error: 'checkout_failed' });
  }
}

/* Stripe signs every webhook: Stripe-Signature: t=<unix>,v1=<hmac>. The
   HMAC-SHA256 is over "<t>.<raw body>" with the endpoint secret, so the body
   must be verified as the exact bytes received, before any JSON parsing. */
function stripeSignatureOk(rawBody, header) {
  const parts = {};
  String(header || '').split(',').forEach((kv) => {
    const i = kv.indexOf('=');
    if (i > 0) parts[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  });
  const t = Number(parts.t), v1 = parts.v1;
  if (!t || !v1) return false;
  if (Math.abs(Date.now() / 1000 - t) > 300) return false;   // replay guard
  const expected = crypto.createHmac('sha256', STRIPE_WEBHOOK_SECRET)
    .update(`${t}.`).update(rawBody).digest('hex');
  const a = Buffer.from(expected), b = Buffer.from(v1);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function handlePayWebhook(req, res) {
  if (!paymentsEnabled()) return sendJson(req, res, 503, { ok: false, error: 'payments_not_configured' });
  let raw;
  try { raw = await readRawBody(req); }
  catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }
  if (!stripeSignatureOk(raw, req.headers['stripe-signature'])) {
    console.warn('[pay] webhook with a bad signature rejected');
    return sendJson(req, res, 400, { ok: false, error: 'bad_signature' });
  }
  let event;
  try { event = JSON.parse(raw.toString('utf8')); }
  catch { return sendJson(req, res, 400, { ok: false, error: 'bad_json' }); }

  if (event.type === 'checkout.session.completed') {
    const s = event.data && event.data.object ? event.data.object : {};
    const paid = s.payment_status === 'paid' || s.status === 'complete';
    const email = String((s.metadata && s.metadata.email) || s.client_reference_id ||
      (s.customer_details && s.customer_details.email) || s.customer_email || '').toLowerCase();
    if (paid && looksLikeEmail(email)) {
      grants[email] = PAID_TIER;
      persist(GRANTS_FILE, grants);
      console.log(`[pay] ${email} paid — full access granted`);
    } else {
      console.warn(`[pay] completed session without a usable email or not paid (status=${s.payment_status})`);
    }
  }
  // Every other event type is acknowledged so Stripe stops retrying it.
  return sendJson(req, res, 200, { ok: true, received: true });
}

/* Who may open /admin. An admin signs in with their own account email and
   password (the same password they use in the app), or with Google when it
   is configured; the long ADMIN_TOKEN still works as a way back in if either
   is ever misconfigured, which would otherwise lock the owner out of his own
   site. The owner's addresses are always on the list, whatever ADMIN_EMAILS
   says, so a deployment with the variable set to one of them cannot quietly
   drop the other. */
const OWNER_EMAILS = ['zzoom18@gmail.com', 'zzoom18@yahoo.com'];
const ADMIN_EMAILS = [...new Set([
  ...OWNER_EMAILS,
  ...(process.env.ADMIN_EMAILS || '').split(',').map((e) => e.trim().toLowerCase()).filter(Boolean)
])];
const ADMIN_SESSION_HOURS = 12;

function sameString(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  // timingSafeEqual throws on a length mismatch, and the length itself is not
  // worth hiding here, so it is checked first.
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function adminSign(payload) {
  return crypto.createHmac('sha256', KEY_SECRET)
    .update(`admin1:${payload}`).digest('base64url').slice(0, 43);
}

function adminSession(email) {
  const body = Buffer.from(JSON.stringify({
    e: email, x: Math.floor(Date.now() / 1000) + ADMIN_SESSION_HOURS * 3600
  })).toString('base64url');
  return `${body}.${adminSign(body)}`;
}

function readAdminSession(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 2) return null;
  if (!sameString(parts[1], adminSign(parts[0]))) return null;
  let claims;
  try { claims = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')); }
  catch { return null; }
  if (!claims || Number(claims.x) <= Math.floor(Date.now() / 1000)) return null;
  // Re-checked on every request, so removing an address from ADMIN_EMAILS ends
  // that person's session immediately rather than in twelve hours.
  if (ADMIN_EMAILS.indexOf(String(claims.e || '').toLowerCase()) < 0) return null;
  return claims;
}

function requireAdmin(req, res) {
  const auth = req.headers.authorization || '';
  const given = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (given && readAdminSession(given)) return true;
  if (ADMIN_TOKEN && given && sameString(given, ADMIN_TOKEN)) return true;

  sendJson(req, res, 401, { ok: false, error: 'unauthorized' });
  return false;
}

/* Sign in to the admin page: with the account's own email and password, or
   with Google. A Google ID token is verified exactly as a parent's is; a
   password is checked exactly as it is on the sign-in sheet. Either way the
   only extra step is checking the address is on the list. */
async function handleAdminLogin(req, res) {
  let body;
  try { body = await readBody(req); } catch { return sendJson(req, res, 400, { ok: false, error: 'bad_request' }); }

  let email;
  if (body.credential) {
    if (!GOOGLE_CLIENT_ID) {
      return sendJson(req, res, 503, {
        ok: false, error: 'google_not_configured',
        message: 'Google sign-in is not set up yet. Sign in with your email and password instead.'
      });
    }
    let claims;
    try {
      claims = verifyGoogleToken(body.credential, { keys: await googleKeys(), clientId: GOOGLE_CLIENT_ID });
    } catch (err) {
      console.error('[admin] rejected a Google sign-in:', err.message);
      return sendJson(req, res, 401, { ok: false, error: 'google_rejected', message: 'Google could not confirm that sign-in.' });
    }
    email = String(claims.email).toLowerCase();
    if (ADMIN_EMAILS.indexOf(email) < 0) {
      console.error(`[admin] ${email} is not on the admin list`);
      return sendJson(req, res, 403, { ok: false, error: 'not_an_admin', message: 'That account is not an administrator of this site.' });
    }
  } else {
    email = String(body.email || '').trim().toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    const ip = clientIp(req);
    if (rateLimited(ip)) {
      return sendJson(req, res, 429, { ok: false, error: 'too_many_attempts',
        message: 'Too many tries. Please wait ten minutes and try again.' });
    }
    if (!email || !password) {
      return sendJson(req, res, 400, { ok: false, error: 'missing', message: 'Enter your email and password.' });
    }
    /* One answer for "not an admin" and "wrong password", so the form does
       not confirm which addresses are on the list. */
    const stored = ADMIN_EMAILS.indexOf(email) >= 0 ? passwordOf(email) : null;
    if (ADMIN_EMAILS.indexOf(email) >= 0 && !stored) {
      return sendJson(req, res, 403, { ok: false, error: 'no_password',
        message: 'This account has no password yet. Sign in to the game with it, open your profile and set one, then come back.' });
    }
    if (!stored || !checkPassword(password, stored)) {
      recordAttempt(ip);
      console.error(`[admin] rejected a password sign-in for ${email} ip=${ip}`);
      return sendJson(req, res, 401, { ok: false, error: 'rejected', message: 'That email and password were not accepted.' });
    }
  }

  console.log(`[admin] signed in as ${email}`);
  return sendJson(req, res, 200, { ok: true, token: adminSession(email), email });
}

async function handleMint(req, res) {
  if (!requireAdmin(req, res)) return;

  let body;
  try {
    body = await readBody(req);
  } catch {
    return sendJson(req, res, 400, { ok: false, error: 'bad_request' });
  }

  const count = Math.min(Math.max(Number(body.count) || 1, 1), 500);
  const from = Math.max(Number(body.from) || 0, 0);
  /* Only the one real tier is ever minted. A legacy tier name still verifies
     on an old key, but nothing new is issued against it. */
  let tier;
  try {
    tier = tierByName(body.tier || 'full');
    if (SELLABLE_TIERS.indexOf(tier) < 0) tier = SELLABLE_TIERS[0];
  } catch {
    tier = SELLABLE_TIERS[0];
  }

  const keys = [];
  for (let i = 0; i < count; i++) keys.push({ serial: from + i, key: mint(KEY_SECRET, tier, from + i) });
  return sendJson(req, res, 200, { ok: true, tier: TIERS[tier].id, keys });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (url.pathname === '/admin') { url.pathname = '/admin.html'; req.url = '/admin.html'; }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(req)).end();
    return;
  }

  try {
    if (url.pathname === '/api/health') {
      return sendJson(req, res, 200, { ok: true, service: 'papercub', version: APP_VERSION, time: new Date().toISOString() });
    }
    /* Public, and deliberately so: a Google client ID is not a secret, and the
       page needs it before it can draw the sign-in button. */
    if (url.pathname === '/api/config') {
      return sendJson(req, res, 200, { ok: true, googleClientId: GOOGLE_CLIENT_ID || null });
    }
    if (url.pathname === '/api/register' && req.method === 'POST') return await handleRegister(req, res);
    if (url.pathname === '/api/google' && req.method === 'POST') return await handleGoogle(req, res);
    if (url.pathname === '/api/admin/login' && req.method === 'POST') return await handleAdminLogin(req, res);
    if (url.pathname === '/api/activate' && req.method === 'POST') return await handleActivate(req, res);
    if (url.pathname === '/api/verify' && req.method === 'POST') return await handleVerify(req, res);
    if (url.pathname === '/api/password' && req.method === 'POST') return await handlePassword(req, res);
    if (url.pathname === '/api/pay/config' && req.method === 'GET') return await handlePayConfig(req, res);
    if (url.pathname === '/api/pay/checkout' && req.method === 'POST') return await handlePayCheckout(req, res);
    if (url.pathname === '/api/pay/webhook' && req.method === 'POST') return await handlePayWebhook(req, res);
    if (url.pathname === '/api/progress' && req.method === 'POST') return await handleProgress(req, res);
    if (url.pathname === '/api/admin/mint' && req.method === 'POST') return await handleMint(req, res);
    if (url.pathname === '/api/admin/registrations' && req.method === 'GET') return await handleRegistrations(req, res);
    if (url.pathname === '/api/admin/settings') return await handleSettings(req, res);
    if (url.pathname === '/api/admin/grant' && req.method === 'POST') return await handleGrant(req, res);
    if (url.pathname === '/api/admin/account' && req.method === 'POST') return await handleAccount(req, res);
    if (url.pathname === '/api/writing' && (req.method === 'GET' || req.method === 'POST')) return await handleWriting(req, res);
    if (url.pathname === '/api/writings/approved' && req.method === 'GET') return await handleWritingsApproved(req, res);
    if (url.pathname === '/api/admin/writings' && (req.method === 'GET' || req.method === 'POST')) return await handleAdminWritings(req, res);
    if (url.pathname.startsWith('/api/')) return sendJson(req, res, 404, { ok: false, error: 'not_found' });

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return sendJson(req, res, 405, { ok: false, error: 'method_not_allowed' });
    }
    return serveStatic(req, res, url.pathname);
  } catch (err) {
    console.error('[error]', err);
    if (!res.headersSent) sendJson(req, res, 500, { ok: false, error: 'server_error' });
  }
});

server.listen(PORT, () => {
  console.log(`Fun Game listening on :${PORT}`);
  console.log(`  admin mint endpoint: ${ADMIN_TOKEN ? 'enabled' : 'disabled (set ADMIN_TOKEN to enable)'}`);
  console.log(`  cross-origin activation: ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : 'same-origin only'}`);
  console.log(`  sample access: ${TRIAL_DAYS} days, registrations saved to ${REGISTRATIONS}`);
  console.log(`  access: ${settings.openAccess ? 'OPEN — everyone gets ' + settings.defaultTier : 'trial then licence key'}`);
  console.log(`  Google sign-in: ${GOOGLE_CLIENT_ID ? 'enabled' : 'off (set GOOGLE_CLIENT_ID)'}`);
  console.log(`  payments: ${paymentsEnabled() ? 'Stripe Checkout enabled' : 'off (set STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID)'}`);
  console.log(`  admin page: /admin (sign in as ${ADMIN_EMAILS.join(', ')})`);

  /* Redeploying almost always means replacing ROOT with a fresh copy of the
     app (a rebuilt container, a tarball extracted over the old files). Any
     explicit DATA_DIR override that still points inside ROOT loses every
     registration and every child's saved stars the next time that happens —
     silently, which is the worst way to lose them. This is not tied to any
     one host: it is true wherever a deploy replaces the app folder. */
  if (DATA_DIR.startsWith(ROOT)) {
    console.error('');
    console.error('  ****************************************************************');
    console.error('  *  DATA_DIR is inside the app directory, which redeploys wipe: *');
    console.error(`  *  ${DATA_DIR}`);
    console.error('  *  Registrations and saved progress WILL be lost on the next   *');
    console.error('  *  deploy. Point DATA_DIR outside the app folder instead.      *');
    console.error('  ****************************************************************');
    console.error('');
  }
});
