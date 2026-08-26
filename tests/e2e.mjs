// End-to-end retrieve: takes a real sharebuff URL + PIN and performs exactly
// what the page does, via the same web/crypto.js module (KDF stages → claim →
// decrypt → parse envelope). Text payloads go to stdout as text; file
// payloads go to stdout as raw bytes with the header JSON on stderr.
// Usage: node tests/e2e.mjs '<url>#<code>' '<PIN>' [--expect-status 410]
import { decodeCode, prepare, derive, decrypt, parseEnvelope, toHex } from '../web/crypto.js';

const [url, pin, ...rest] = process.argv.slice(2);
const expectStatus = rest[0] === '--expect-status' ? Number(rest[1]) : 200;
if (!url || !pin) { console.error('usage: node tests/e2e.mjs <url> <pin>'); process.exit(2); }

const u = new URL(url);
let key;
try { key = decodeCode(decodeURIComponent(u.hash.slice(1))); } catch (e) { console.error(`bad code: ${e.message}`); process.exit(2); }

const { id, salt } = await prepare(key);
const keys = await derive(key, pin, salt);

const resp = await fetch(`${u.origin}/api/secrets/${id}/claim`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ auth: toHex(keys.auth) }),
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
const plain = await decrypt(keys.enc, id, new Uint8Array(Buffer.from(body.ct, 'base64')));
const { header, payload } = parseEnvelope(plain);
if (header.t === 'file') {
  console.error(`envelope: ${JSON.stringify(header)}`);
  process.stdout.write(Buffer.from(payload));
} else {
  process.stdout.write(new TextDecoder().decode(payload));
}
