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

// ---------------------------------------------------------------------------
// Sender side (the Share tab). Same primitives, reversed; the server still
// only ever receives {locator, ciphertext, verifier}.

export function crockEncodeKey(key) { return crockEncode(key); }

function group5(raw) {
  const groups = [];
  while (raw.length > 5) { groups.push(raw.slice(0, 5)); raw = raw.slice(5); }
  groups.push(raw);
  return groups.join('-');
}

export function encodeCode(locator, key) {
  return group5(locator + crockEncode(key));
}

// n uniformly random alphabet characters. 32 divides 256, so a masked byte
// is already unbiased.
export function randomToken(n) {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  let out = '';
  for (const b of bytes) out += CROCK[b & 31];
  return out;
}

export const newLocator = () => randomToken(LOCATOR_LEN);
export const newKey = (bytes) => crypto.getRandomValues(new Uint8Array(bytes));

// words uniformly chosen from list (rejection sampling on 13-bit draws so
// there is no modulo bias), joined by dashes — the CLI's PIN format.
export function newWordPin(list, words) {
  if (list.length > 8192) throw new Error('wordlist too large for 13-bit sampling');
  const out = [];
  const buf = new Uint16Array(1);
  while (out.length < words) {
    crypto.getRandomValues(buf);
    const idx = buf[0] & 0x1fff;
    if (idx < list.length) out.push(list[idx]);
  }
  return out.join('-');
}

export function encodeEnvelope(header, payload) {
  const hj = utf8(JSON.stringify(header));
  if (hj.length > 4096) throw new Error('envelope header too large');
  const out = new Uint8Array(4 + hj.length + payload.length);
  new DataView(out.buffer).setUint32(0, hj.length);
  out.set(hj, 4);
  out.set(payload, 4 + hj.length);
  return out;
}

export async function encrypt(encKey, locator, plain) {
  const key = await crypto.subtle.importKey('raw', encKey, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(AAD_PREFIX + locator) },
    key,
    plain,
  ));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return out;
}

export async function verifierHex(authKey) {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', authKey)));
}

export function b64encode(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}

// Full sender flow against `base` (same-origin '' in the page). Retries the
// public locator on a 409 collision. Returns {code, pin, expiresAt}.
export async function createSecret(base, { header, payload, keyBytes, pin, ttlSeconds = 604800 }) {
  const key = newKey(keyBytes);
  const envelope = encodeEnvelope(header, payload);
  for (let attempt = 0; attempt < 6; attempt++) {
    const locator = newLocator();
    const keys = await derive(key, pin, locator);
    const blob = await encrypt(keys.enc, locator, envelope);
    const resp = await fetch(`${base}/api/secrets`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: locator, ct: b64encode(blob), verifier: await verifierHex(keys.auth), ttl_seconds: ttlSeconds }),
    });
    if (resp.status === 201) {
      const body = await resp.json().catch(() => ({}));
      return { code: encodeCode(locator, key), pin, expiresAt: body.expires_at };
    }
    if (resp.status === 409) continue;
    const body = await resp.json().catch(() => ({}));
    const e = new Error(`server said ${resp.status}${body.error ? `: ${body.error}` : ''}`);
    e.status = resp.status;
    e.reasons = body.reasons || [];
    throw e;
  }
  throw new Error('could not find a free locator; try again');
}
