import test from 'node:test';
import assert from 'node:assert/strict';
import { mint, verify, normalize, issueToken, readToken, tierByName, TIERS, TRIAL_TIER } from '../lib/keys.js';

const SECRET = 'test-secret-that-is-long-enough-to-use-here';
const OTHER = 'a-completely-different-secret-value-here!!';

test('a minted key verifies and carries its tier and serial', () => {
  const key = mint(SECRET, 2, 4242);
  const result = verify(SECRET, key);
  assert.equal(result.ok, true);
  assert.equal(result.tier, 2);
  assert.equal(result.serial, 4242);
  assert.equal(result.licence.id, 'teacher');
});

test('keys are printed in the KBW-XXXX-XXXX-XXXX shape', () => {
  assert.match(mint(SECRET, 0, 1), /^KBW-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
});

test('every serial produces a distinct key', () => {
  const seen = new Set();
  for (let i = 0; i < 2000; i++) seen.add(mint(SECRET, 0, i));
  assert.equal(seen.size, 2000);
});

test('a key minted with one secret is rejected by another', () => {
  const key = mint(SECRET, 1, 7);
  assert.equal(verify(OTHER, key).ok, false);
  assert.equal(verify(OTHER, key).reason, 'invalid');
});

test('tampering with any character invalidates the key', () => {
  const key = mint(SECRET, 0, 99);
  const body = normalize(key);
  let rejected = 0;
  for (let i = 0; i < body.length; i++) {
    const swapped = body.slice(0, i) + (body[i] === '7' ? '8' : '7') + body.slice(i + 1);
    if (!verify(SECRET, swapped).ok) rejected++;
  }
  assert.equal(rejected, body.length);
});

test('made-up keys of the right shape are rejected', () => {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  let accepted = 0;
  for (let i = 0; i < 5000; i++) {
    let body = '';
    for (let j = 0; j < 12; j++) body += alphabet[Math.floor(Math.random() * 32)];
    if (verify(SECRET, body).ok) accepted++;
  }
  // 12 random characters clearing a 32-bit tag should essentially never happen.
  assert.equal(accepted, 0);
});

test('typing I, L, O or U still works', () => {
  const key = mint(SECRET, 0, 12345);
  const mistyped = key.replace(/1/g, 'I').replace(/0/g, 'O').replace(/V/g, 'U');
  assert.equal(verify(SECRET, mistyped).ok, true);
});

test('spaces, lowercase and a missing prefix are all forgiven', () => {
  const key = mint(SECRET, 0, 55);
  const body = normalize(key);
  assert.equal(verify(SECRET, key.toLowerCase()).ok, true);
  assert.equal(verify(SECRET, ` ${key} `).ok, true);
  assert.equal(verify(SECRET, body).ok, true);
  assert.equal(verify(SECRET, body.replace(/(.{4})/g, '$1 ')).ok, true);
});

test('malformed input is rejected without throwing', () => {
  for (const bad of ['', null, undefined, 'nope', 'KBW-----', 'KBW-!!!!-????-****', 12345, {}]) {
    assert.equal(verify(SECRET, bad).ok, false);
  }
});

test('revoked keys stop working', () => {
  const key = mint(SECRET, 0, 321);
  assert.equal(verify(SECRET, key).ok, true);
  const result = verify(SECRET, key, new Set([key]));
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'revoked');
});

test('an unused tier number is not a valid licence', () => {
  const key = mint(SECRET, 9, 1);
  assert.equal(verify(SECRET, key).ok, false);
});

test('activation tokens round-trip', () => {
  const token = issueToken(SECRET, { tier: 2, serial: 88, days: 30 });
  const result = readToken(SECRET, token);
  assert.equal(result.ok, true);
  assert.equal(result.tier, 2);
  assert.equal(result.serial, 88);
  assert.equal(result.licence.id, 'teacher');
});

test('tokens are rejected when forged, tampered with, or expired', () => {
  const token = issueToken(SECRET, { tier: 0, serial: 1, days: 30 });
  assert.equal(readToken(OTHER, token).ok, false);

  const [payload, sig] = token.split('.');
  assert.equal(readToken(SECRET, `${payload}x.${sig}`).ok, false);
  const flipped = sig.slice(0, -1) + (sig.at(-1) === 'A' ? 'B' : 'A');
  assert.equal(readToken(SECRET, `${payload}.${flipped}`).ok, false);
  assert.equal(readToken(SECRET, 'garbage').ok, false);

  const expired = issueToken(SECRET, { tier: 0, serial: 1, days: -1 });
  assert.equal(readToken(SECRET, expired).reason, 'expired');
});

test('a token cannot be upgraded to a better tier by editing it', () => {
  const token = issueToken(SECRET, { tier: 0, serial: 1, days: 30 });
  const [payload] = token.split('.');
  const body = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  body.t = 3; // studio
  const forged = Buffer.from(JSON.stringify(body)).toString('base64url') + '.' + token.split('.')[1];
  assert.equal(readToken(SECRET, forged).ok, false);
});

test('tier names map to numbers', () => {
  assert.equal(tierByName('personal'), 0);
  assert.equal(tierByName('STUDIO'), 3);
  assert.throws(() => tierByName('gold'), /Unknown tier/);
  assert.equal(Object.keys(TIERS).length, 6); // 4 sold + trial + limited
});

test('minting rejects out-of-range input', () => {
  assert.throws(() => mint('', 0, 1), /KEY_SECRET/);
  assert.throws(() => mint(SECRET, 99, 1), /tier/);
  assert.throws(() => mint(SECRET, 0, 16777216), /serial/);
});

test('keys do not look sequential', () => {
  // Buyer #1 should not receive a key that announces it.
  const keys = [];
  for (let i = 1; i <= 6; i++) keys.push(mint(SECRET, 0, i));
  const prefixes = new Set(keys.map((k) => k.slice(4, 8)));
  assert.equal(prefixes.size, keys.length, 'consecutive serials shared a leading block');
  assert.ok(!keys.some((k) => k.startsWith('KBW-0000')), 'a key leaked its serial number');
  // and they still decode back to the right serial
  keys.forEach((k, i) => assert.equal(verify(SECRET, k).serial, i + 1));
});

test('a trial cannot be obtained as a purchased key', () => {
  // Someone who worked out the key format must not be able to mint themselves
  // a trial — trials only ever arrive as a token from /api/register.
  const key = mint(SECRET, TRIAL_TIER, 1);
  const result = verify(SECRET, key);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'invalid');
});

test('trial tokens work, carry the trial licence, and expire', () => {
  const token = issueToken(SECRET, { tier: TRIAL_TIER, serial: 0, days: 7 });
  const result = readToken(SECRET, token);
  assert.equal(result.ok, true);
  assert.equal(result.licence.id, 'trial');
  assert.equal(result.licence.trial, true);
  assert.equal(result.licence.maxPages, 3);

  const stale = issueToken(SECRET, { tier: TRIAL_TIER, serial: 0, days: -1 });
  assert.equal(readToken(SECRET, stale).reason, 'expired');
});

test('a trial token cannot be edited into a paid licence', () => {
  const token = issueToken(SECRET, { tier: TRIAL_TIER, serial: 0, days: 7 });
  const body = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
  body.t = 3;
  const forged = Buffer.from(JSON.stringify(body)).toString('base64url') + '.' + token.split('.')[1];
  assert.equal(readToken(SECRET, forged).ok, false);
});

test('an expired token still names its account, and exp can be pinned', () => {
  const past = Math.floor(Date.now() / 1000) - 10;
  const tok = issueToken(SECRET, { tier: TRIAL_TIER, serial: 0, email: 'Mum@Example.com', exp: past });
  const r = readToken(SECRET, tok);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'expired');
  assert.equal(r.email, 'mum@example.com');
  assert.equal(r.tier, TRIAL_TIER);
  // A forged expired token names nobody.
  const forged = tok.slice(0, -4) + 'AAAA';
  assert.equal(readToken(SECRET, forged).email, undefined);
});
