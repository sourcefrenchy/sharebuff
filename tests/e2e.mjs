// End-to-end retrieve: takes a real sharebuff URL + PIN and performs exactly
// what web/app.js does (KDF → claim → decrypt → parse envelope). Text payloads
// go to stdout as text; file payloads go to stdout as raw bytes with the
// header JSON on stderr (redirect stdout to a file for binary comparison).
// Usage: node tests/e2e.mjs '<url>#v2....' '<PIN>' [--expect-status 410]
import { scryptAsync } from '../web/scrypt.js';

const [url, pin, ...rest] = process.argv.slice(2);
const expectStatus = rest[0] === '--expect-status' ? Number(rest[1]) : 200;
if (!url || !pin) { console.error('usage: node tests/e2e.mjs <url> <pin>'); process.exit(2); }

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s) {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  let n = 0n;
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error('invalid base58');
    n = n * 58n + BigInt(v);
  }
  const out = [];
  while (n > 0n) { out.unshift(Number(n & 0xffn)); n >>= 8n; }
  return new Uint8Array([...new Array(zeros).fill(0), ...out]);
}
const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const normalizePin = (p) => p.toUpperCase().replace(/[ -]/g, '')
  .replaceAll('O', '0').replaceAll('I', '1').replaceAll('L', '1');

const u = new URL(url);
const m = /^#v2\.([1-9A-HJ-NP-Za-km-z]+)\.([1-9A-HJ-NP-Za-km-z]+)\.([1-9A-HJ-NP-Za-km-z]+)$/.exec(u.hash);
if (!m) { console.error('bad fragment'); process.exit(2); }
const [, id, kB58, saltB58] = m;
const key = b58decode(kB58);
const salt = b58decode(saltB58);

const pinBytes = new TextEncoder().encode(normalizePin(pin));
const password = new Uint8Array([...key, ...pinBytes]);
const root = await scryptAsync(password, salt, { N: 2 ** 16, r: 8, p: 1, dkLen: 64 });

const resp = await fetch(`${u.origin}/api/secrets/${id}/claim`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ auth: toHex(root.slice(32, 64)) }),
});
const body = await resp.json().catch(() => ({}));
if (resp.status !== expectStatus) {
  console.error(`FAIL: expected ${expectStatus}, got ${resp.status}`, body);
  process.exit(1);
}
if (resp.status !== 200) {
  console.log(`OK: got expected ${resp.status}`, JSON.stringify(body));
  process.exit(0);
}
const blob = Buffer.from(body.ct, 'base64');
const aesKey = await crypto.subtle.importKey('raw', root.slice(0, 32), 'AES-GCM', false, ['decrypt']);
const plain = new Uint8Array(await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: blob.subarray(0, 12), additionalData: new TextEncoder().encode('sharebuff/v2.' + id) },
  aesKey,
  blob.subarray(12),
));

// Envelope parse, mirroring web/app.js.
const hlen = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
if (hlen > 4096 || 4 + hlen > plain.length) { console.error('bad envelope'); process.exit(1); }
const header = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + hlen)));
const payload = plain.slice(4 + hlen);
if (header.t === 'file') {
  console.error(`envelope: ${JSON.stringify(header)}`);
  process.stdout.write(Buffer.from(payload));
} else {
  process.stdout.write(new TextDecoder().decode(payload));
}
