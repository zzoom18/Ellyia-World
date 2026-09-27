import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, checkPassword, passwordProblem, generatePassword, MIN_PASSWORD, MAX_PASSWORD } from '../lib/password.js';

test('a hashed password checks against itself and nothing else', () => {
  const stored = hashPassword('correct horse');
  assert.equal(checkPassword('correct horse', stored), true);
  assert.equal(checkPassword('correct horsE', stored), false);
  assert.equal(checkPassword('', stored), false);
  assert.equal(checkPassword('correct horse ', stored), false);
});

test('the stored form never contains the password and differs per hash', () => {
  const a = hashPassword('sunshine1');
  const b = hashPassword('sunshine1');
  assert.doesNotMatch(a, /sunshine/);
  assert.match(a, /^scrypt\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
  assert.notEqual(a, b, 'a fresh salt every time');
  assert.equal(checkPassword('sunshine1', b), true);
});

test('too short, too long and non-string passwords are refused with a reason', () => {
  assert.equal(passwordProblem('abcdef'), null);
  assert.match(passwordProblem('abcde'), new RegExp(String(MIN_PASSWORD)));
  assert.match(passwordProblem('x'.repeat(MAX_PASSWORD + 1)), new RegExp(String(MAX_PASSWORD)));
  assert.ok(passwordProblem(undefined));
  assert.ok(passwordProblem(12345678));
  assert.throws(() => hashPassword('short'));
});

test('a damaged or foreign record is a plain "no", not a crash', () => {
  assert.equal(checkPassword('anything', ''), false);
  assert.equal(checkPassword('anything', null), false);
  assert.equal(checkPassword('anything', 'bcrypt$abc$def'), false);
  assert.equal(checkPassword('anything', 'scrypt$zz$zz'), false);
  assert.equal(checkPassword('anything', 'scrypt$00ff$00ff'), false);
  assert.equal(checkPassword(null, hashPassword('validone')), false);
});

test('a generated password is readable, long enough and never the same twice', () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const p = generatePassword();
    assert.match(p, /^[A-HJ-NP-Za-hj-km-z2-9]{4}-[A-HJ-NP-Za-hj-km-z2-9]{4}$/);
    assert.equal(passwordProblem(p), null);
    assert.equal(checkPassword(p, hashPassword(p)), true);
    seen.add(p);
  }
  assert.equal(seen.size, 200);
});
