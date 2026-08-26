// Sharebuff v3 client crypto — the single implementation used by the retrieve
// page (app.js) AND by the node test harness (tests/parity.mjs, tests/e2e.mjs),
// so what is tested against the Go reference vectors is exactly what runs in
// the browser. Conforms to docs/SPEC.md.
import { scryptAsync } from './scrypt.js';

const SCRYPT = { N: 2 ** 16, r: 8, p: 1 };
const CROCK = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const AAD_PREFIX = 'sharebuff/v3.';
const PRE_SALT = 'sharebuff/v3/pre';
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
    buf = (buf << 8) | b; bits += 8;
    while (bits >= 5) { out += CROCK[(buf >> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += CROCK[(buf << (5 - bits)) & 31];
  return out;
}

// Parse a typed key code (26 or 52 chars, any case, dashes optional) into a
// 16- or 32-byte key. Rejects non-canonical spellings.
export function decodeCode(code) {
  const n = normalizeCode(code);
  if (n.length !== 26 && n.length !== 52) throw new Error('code must be 26 or 52 characters');
  const bytes = [];
  let buf = 0, bits = 0;
  for (const ch of n) {
    const v = CROCK.indexOf(ch);
    if (v < 0) throw new Error('invalid code character');
    buf = (buf << 5) | v; bits += 5;
    if (bits >= 8) { bytes.push((buf >> (bits - 8)) & 255); bits -= 8; }
  }
  const key = new Uint8Array(bytes);
  if (crockEncode(key) !== n) throw new Error('non-canonical code');
  return key;
}

export function b58encode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  return '1'.repeat(zeros) + out;
}

export function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// KDF stage A: id + per-secret salt from K alone.
export async function prepare(key) {
  const pre = await scryptAsync(key, utf8(PRE_SALT), { ...SCRYPT, dkLen: 32 });
  return { id: b58encode(pre.slice(0, 16)), salt: pre.slice(16, 32) };
}

// KDF stage B: encryption key + claim proof from K, PIN and the stage-A salt.
export async function derive(key, pin, salt) {
  const pinBytes = utf8(normalizeCode(pin));
  const password = new Uint8Array(key.length + pinBytes.length);
  password.set(key, 0);
  password.set(pinBytes, key.length);
  const root = await scryptAsync(password, salt, { ...SCRYPT, dkLen: 64 });
  return { enc: root.slice(0, 32), auth: root.slice(32, 64) };
}

export async function decrypt(encKey, id, blob) {
  const key = await crypto.subtle.importKey('raw', encKey, 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.slice(0, 12), additionalData: utf8(AAD_PREFIX + id) },
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
