import crypto from 'node:crypto';

/**
 * Kayden Bang World licence keys are self-describing and stateless: everything needed to check a
 * key is inside the key itself, signed with KEY_SECRET. No database, so a
 * redeploy that wipes the filesystem cannot lose a customer's licence.
 *
 * Layout — 60 bits, rendered as 12 Crockford base32 characters:
 *
 *   [ 4 bits tier ][ 24 bits serial ][ 32 bits truncated HMAC-SHA256 ]
 *
 * Printed as KBW-XXXX-XXXX-XXXX. Forging one without the secret means guessing
 * a 32-bit tag, which the activation rate limiter makes hopeless.
 */

// Crockford base32: no I, L, O or U, so keys survive being read aloud or
// copied off a receipt by hand.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const DECODE = new Map([...ALPHABET].map((c, i) => [c, i]));
// The characters people actually type instead of the ones we use.
const CONFUSABLES = { I: '1', L: '1', O: '0', U: 'V' };

const TIER_BITS = 4n;
const SERIAL_BITS = 24n;
const MAC_BITS = 32n;
const MAC_MASK = (1n << MAC_BITS) - 1n;
const SERIAL_MASK = (1n << SERIAL_BITS) - 1n;
const TIER_MASK = (1n << TIER_BITS) - 1n;
const KEY_CHARS = 12;

export const TRIAL_TIER = 15;

/* There is one thing to have: the whole app. Four graded tiers were more
 * bookkeeping than the site needed, so 3 is now simply "Full access".
 *
 * 0, 1 and 2 are kept because the tier number is baked into every key ever
 * issued and the signature covers it — dropping them would break keys that
 * are already out there. They are hidden from the admin page and from
 * minting, and they now grant exactly what tier 3 grants, so an older key
 * keeps working and unlocks everything.
 */
export const TIERS = {
  0: { id: 'personal', name: 'Full access', maxPages: 0, commercial: true, legacy: true },
  1: { id: 'family', name: 'Full access', maxPages: 0, commercial: true, legacy: true },
  2: { id: 'teacher', name: 'Full access', maxPages: 0, commercial: true, legacy: true },
  3: { id: 'full', name: 'Full access', maxPages: 0, commercial: true }, // 0 = unlimited
  // Neither of these is sold or minted as a key — both are handed out by
  // /api/register and carried only by a token. A new account gets the trial
  // (every game, for TRIAL_DAYS); when that runs out it holds `limited`: still
  // signed in, stars kept, but no game opens until it pays or is granted.
  14: { id: 'limited', name: 'Trial ended', maxPages: 1, commercial: false, limited: true },
  15: { id: 'trial', name: 'Trial', maxPages: 3, commercial: false, trial: true }
};
export const LIMITED_TIER = 14;

/* What the admin page offers and what mint() will produce: the one real tier. */
export const SELLABLE_TIERS = [3];

/* "studio" was the old name for tier 3 and is still written in settings.json
   and grants.json on live installs, so it stays understood. */
const TIER_ALIASES = { studio: 'full' };

export function tierByName(name) {
  const wanted = String(name).toLowerCase();
  const id = TIER_ALIASES[wanted] || wanted;
  const entry = Object.entries(TIERS).find(([, t]) => t.id === id);
  if (!entry) throw new Error(`Unknown tier "${name}". Use one of: full, trial, limited`);
  return Number(entry[0]);
}

function mac(secret, tier, serial) {
  const h = crypto.createHmac('sha256', secret);
  h.update(`papercub1:${tier}:${serial}`);
  return BigInt('0x' + h.digest('hex').slice(0, 8)) & MAC_MASK;
}

/**
 * Without this, serial 1 renders as KBW-0000-… — which tells the customer
 * holding it that they are buyer number one, and makes consecutive keys look
 * like consecutive keys. A 4-round Feistel network over the 60 bits shuffles
 * them into something that reads as random while staying exactly reversible.
 */
const HALF_BITS = 30n;
const HALF_MASK = (1n << HALF_BITS) - 1n;
const ROUNDS = 4;

function roundFn(secret, round, half) {
  const h = crypto.createHmac('sha256', secret);
  h.update(`papercub1-feistel:${round}:${half}`);
  return BigInt('0x' + h.digest('hex').slice(0, 10)) & HALF_MASK;
}

function scramble(secret, value) {
  let L = (value >> HALF_BITS) & HALF_MASK;
  let R = value & HALF_MASK;
  for (let r = 0; r < ROUNDS; r++) {
    const next = L ^ roundFn(secret, r, R);
    L = R;
    R = next;
  }
  return (L << HALF_BITS) | R;
}

function unscramble(secret, value) {
  let L = (value >> HALF_BITS) & HALF_MASK;
  let R = value & HALF_MASK;
  for (let r = ROUNDS - 1; r >= 0; r--) {
    const prev = R ^ roundFn(secret, r, L);
    R = L;
    L = prev;
  }
  return (L << HALF_BITS) | R;
}

function encode(value) {
  let out = '';
  for (let i = KEY_CHARS - 1; i >= 0; i--) {
    out += ALPHABET[Number((value >> (5n * BigInt(i))) & 31n)];
  }
  return out;
}

const PREFIX = 'KBW';

function format(body) {
  return `${PREFIX}-${body.slice(0, 4)}-${body.slice(4, 8)}-${body.slice(8, 12)}`;
}

/** Build one key. `serial` must be unique per tier — that is what the CLI tracks. */
export function mint(secret, tier, serial) {
  if (!secret) throw new Error('KEY_SECRET is required to mint keys');
  if (tier < 0 || tier > 15) throw new Error('tier must be 0-15');
  if (serial < 0 || serial > Number(SERIAL_MASK)) throw new Error(`serial must be 0-${SERIAL_MASK}`);
  const payload = (BigInt(tier) << SERIAL_BITS) | BigInt(serial);
  const value = (payload << MAC_BITS) | mac(secret, tier, serial);
  return format(encode(scramble(secret, value)));
}

/** Strip formatting and repair the characters people typically mistype. */
export function normalize(input) {
  let s = String(input || '').toUpperCase().replace(/[\s\-_]/g, '');
  // Strip the prefix only when what remains is exactly a key body. U is not in
  // the alphabet, so CUB can never be the start of a body and this is safe.
  if (s.length === KEY_CHARS + PREFIX.length && s.startsWith(PREFIX)) s = s.slice(PREFIX.length);
  return [...s].map((c) => CONFUSABLES[c] ?? c).join('');
}

/**
 * Check a key. Returns { ok, tier, serial, reason } — never throws on bad
 * input, because every value here arrives straight from a text box.
 */
export function verify(secret, input, revoked = new Set()) {
  const body = normalize(input);
  if (body.length !== KEY_CHARS) return { ok: false, reason: 'format' };

  let raw = 0n;
  for (const ch of body) {
    const d = DECODE.get(ch);
    if (d === undefined) return { ok: false, reason: 'format' };
    raw = (raw << 5n) | BigInt(d);
  }

  const value = unscramble(secret, raw);
  const given = value & MAC_MASK;
  const payload = value >> MAC_BITS;
  const serial = Number(payload & SERIAL_MASK);
  const tier = Number((payload >> SERIAL_BITS) & TIER_MASK);

  const expected = mac(secret, tier, serial);
  // Compare as fixed-width buffers so the check is constant time.
  const a = Buffer.from(given.toString(16).padStart(8, '0'), 'hex');
  const b = Buffer.from(expected.toString(16).padStart(8, '0'), 'hex');
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'invalid' };

  if (!TIERS[tier] || TIERS[tier].trial) return { ok: false, reason: 'invalid' };
  if (revoked.has(format(body)) || revoked.has(body)) return { ok: false, reason: 'revoked' };

  return { ok: true, tier, serial, licence: TIERS[tier] };
}

/* ---------- activation tokens ---------- */

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

/**
 * A short-lived token the browser keeps, so the app does not have to hold the
 * licence key itself or call home on every page load.
 */
/* The token carries the account it belongs to as well as the licence, so the
   server can tell whose saved progress to hand back without a second login.
   It is signed, so the address in it cannot be swapped for someone else's. */
export function issueToken(secret, { tier, serial, days = 90, email = '', exp }) {
  // `exp` (unix seconds) pins the expiry exactly; otherwise it is `days` from now.
  const body = { t: tier, s: serial, exp: Number.isFinite(exp) ? Math.floor(exp) : Math.floor(Date.now() / 1000) + days * 86400 };
  if (email) body.e = String(email).toLowerCase();
  const payload = b64url(JSON.stringify(body));
  const sig = b64url(crypto.createHmac('sha256', secret).update(payload).digest()).slice(0, 43);
  return `${payload}.${sig}`;
}

export function readToken(secret, token) {
  const [payload, sig] = String(token || '').split('.');
  if (!payload || !sig) return { ok: false, reason: 'format' };

  const expected = b64url(crypto.createHmac('sha256', secret).update(payload).digest()).slice(0, 43);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'invalid' };

  let body;
  try {
    body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return { ok: false, reason: 'invalid' };
  }

  if (!body || typeof body.exp !== 'number' || body.exp * 1000 < Date.now()) {
    // The signature checked out, so the address it names is still trustworthy:
    // the server uses it to hand an expired trial its follow-on token.
    return { ok: false, reason: 'expired', email: (body && body.e) || null, tier: body ? body.t : null };
  }
  const licence = TIERS[body.t];
  if (!licence) return { ok: false, reason: 'invalid' };

  return { ok: true, tier: body.t, serial: body.s, licence, expiresAt: body.exp, email: body.e || null };
}
