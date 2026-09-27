import crypto from 'node:crypto';

/**
 * Account passwords. Hashed with scrypt from node:crypto — no dependency, and
 * a deliberately slow hash so a leaked passwords file is not a list of
 * passwords. Nothing here ever stores or logs the plain text.
 *
 * Stored form: `scrypt$<salt hex>$<hash hex>`. Keeping the algorithm name in
 * front means a later change of parameters can tell old records from new
 * ones without a migration.
 */

export const MIN_PASSWORD = 6;
export const MAX_PASSWORD = 128;

const SCRYPT_OPTIONS = { N: 16384, r: 8, p: 1 };
const KEY_LEN = 32;

/** Why a password will not do, as a sentence for the person who typed it, or
 *  null when it is fine. */
export function passwordProblem(password) {
  if (typeof password !== 'string') return 'Please type a password.';
  if (password.length < MIN_PASSWORD) return `Please use at least ${MIN_PASSWORD} characters.`;
  if (password.length > MAX_PASSWORD) return `That password is too long — ${MAX_PASSWORD} characters at most.`;
  return null;
}

/* A password we choose for someone and send by email: eight characters from
   an alphabet with no 0/O or 1/l/I to mistype, split in two so it reads off a
   phone screen. About 47 bits, and the sign-in limiter makes guessing moot. */
const PLAIN_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
export function generatePassword() {
  const bytes = crypto.randomBytes(8);
  let out = '';
  for (let i = 0; i < 8; i++) {
    out += PLAIN_ALPHABET[bytes[i] % PLAIN_ALPHABET.length];
    if (i === 3) out += '-';
  }
  return out;
}

export function hashPassword(password) {
  const problem = passwordProblem(password);
  if (problem) throw new Error(problem);
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, KEY_LEN, SCRYPT_OPTIONS);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

/** True only when `password` is the one `stored` was made from. Any malformed
 *  record, wrong type or wrong length is simply "no", never a throw. */
export function checkPassword(password, stored) {
  if (typeof password !== 'string' || typeof stored !== 'string') return false;
  const [algo, saltHex, hashHex] = stored.split('$');
  if (algo !== 'scrypt' || !saltHex || !hashHex) return false;
  let salt, expected;
  try {
    salt = Buffer.from(saltHex, 'hex');
    expected = Buffer.from(hashHex, 'hex');
  } catch {
    return false;
  }
  if (!salt.length || expected.length !== KEY_LEN) return false;
  if (password.length > MAX_PASSWORD) return false;
  const actual = crypto.scryptSync(password, salt, KEY_LEN, SCRYPT_OPTIONS);
  return crypto.timingSafeEqual(actual, expected);
}
