// Sharebuff v4 client crypto — the single implementation used by the retrieve
// page (app.js) AND by the node test harness (tests/parity.mjs, tests/e2e.mjs),
// so what is tested against the Go reference vectors is exactly what runs in
// the browser. Conforms to docs/SPEC.md.
import { scryptAsync } from './scrypt.js';

const SCRYPT = { N: 2 ** 16, r: 8, p: 1, dkLen: 64 };
const CROCK = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const LOCATOR_LEN = 5;
const AAD_PREFIX = 'sharebuff/v4.';
const SALT_PREFIX = 'sharebuff/v4/';
const utf8 = (s) => new TextEncoder().encode(s);

export const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');

// Uppercase, strip spaces/dashes, map O→0 and I/L→1 (Crockford tolerance).
export function normalizeCode(s) {
  return s.toUpperCase().replace(/[ -]/g, '')
    .replaceAll('O', '0').replaceAll('I', '1').replaceAll('L', '1');
}

function crockEncode(bytes) {
  let out = '', buf = 0, bits = 0;
  for (const b of bytes) {
    buf = ((buf << 8) | b) & 0xffff; bits += 8;
    while (bits >= 5) { out += CROCK[(buf >> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += CROCK[(buf << (5 - bits)) & 31];
  return out;
}

// Parse a typed code "LOCATOR-KEY…" (any case, dashes optional) into the
// public 5-char locator and the 5/16/32-byte secret key. Rejects
// non-canonical spellings so every key has exactly one form.
export function decodeCode(code) {
  const n = normalizeCode(code);
  if (n.length < LOCATOR_LEN) throw new Error('code too short');
  const locator = n.slice(0, LOCATOR_LEN);
  const rest = n.slice(LOCATOR_LEN);
  for (const ch of locator) if (CROCK.indexOf(ch) < 0) throw new Error('invalid code character');
  if (rest.length !== 8 && rest.length !== 26 && rest.length !== 52) {
    throw new Error('the key part must be 8, 26 or 52 characters');
  }
  const bytes = [];
  let buf = 0, bits = 0;
  for (const ch of rest) {
    const v = CROCK.indexOf(ch);
    if (v < 0) throw new Error('invalid code character');
    buf = ((buf << 5) | v) & 0xffff; bits += 5;
    if (bits >= 8) { bytes.push((buf >> (bits - 8)) & 255); bits -= 8; }
  }
  const key = new Uint8Array(bytes);
  if (![5, 16, 32].includes(key.length) || crockEncode(key) !== rest) throw new Error('non-canonical code');
  return { locator, key };
}

export function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// KDF: encryption key + claim proof from K, PIN, salted by the locator.
export async function derive(key, pin, locator) {
  const pinBytes = utf8(normalizeCode(pin));
  const password = new Uint8Array(key.length + pinBytes.length);
  password.set(key, 0);
  password.set(pinBytes, key.length);
  const root = await scryptAsync(password, utf8(SALT_PREFIX + locator), SCRYPT);
  return { enc: root.slice(0, 32), auth: root.slice(32, 64) };
}

export async function decrypt(encKey, locator, blob) {
  const key = await crypto.subtle.importKey('raw', encKey, 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.slice(0, 12), additionalData: utf8(AAD_PREFIX + locator) },
    key,
    blob.slice(12),
  );
  return new Uint8Array(plain);
}

// Envelope: u32be(header length) || header JSON || payload.
export function parseEnvelope(bytes) {
  if (bytes.length < 4) throw new Error('envelope truncated');
  const hlen = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
  if (hlen > 4096 || 4 + hlen > bytes.length) throw new Error('envelope header out of bounds');
  const header = JSON.parse(new TextDecoder().decode(bytes.slice(4, 4 + hlen)));
  if (header.t !== 'text' && header.t !== 'file') throw new Error('unknown envelope type');
  return { header, payload: bytes.slice(4 + hlen) };
}
