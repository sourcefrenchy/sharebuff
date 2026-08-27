// Produces internal/wire/testdata/js_vectors.json: secrets encrypted by the
// BROWSER implementation (web/crypto.js) that the Go reference must be able
// to open (internal/wire TestOpenJSVectors). Run: make jsvectors
import { writeFile } from 'node:fs/promises';
import { decodeCode, derive, encrypt, encodeEnvelope, encodeCode } from '../web/crypto.js';

const cases = [
  { keyHex: '0102030405', locator: 'AB3DE', pin: 'basil-tundra-koala', header: { t: 'text' }, payload: 'browser → go ✓' },
  { keyHex: 'aa'.repeat(16), locator: 'ZZZZZ', pin: 'ZZZZZZ', header: { t: 'file', n: 'résumé 🔐.pdf', m: 'application/pdf' }, payload: '\x25PDF-\x00\x01\xfe\xff' },
  { keyHex: '42'.repeat(32), locator: 'K7Q4T', pin: 'Four Words Now Here', header: { t: 'text' }, payload: 'multi\nline\néàü' },
];
const out = [];
for (const c of cases) {
  const key = Uint8Array.from(c.keyHex.match(/../g).map((h) => parseInt(h, 16)));
  const code = encodeCode(c.locator, key);
  const { locator } = decodeCode(code);
  const keys = await derive(key, c.pin, locator);
  const payload = Uint8Array.from(c.payload, (ch) => ch.charCodeAt(0) & 0xff);
  const isText = c.header.t === 'text';
  const payloadBytes = isText ? new TextEncoder().encode(c.payload) : payload;
  const env = encodeEnvelope(c.header, payloadBytes);
  const blob = await encrypt(keys.enc, locator, env);
  out.push({ code, pin: c.pin, header_json: JSON.stringify(c.header), payload_b64: Buffer.from(payloadBytes).toString('base64'), ct_b64: Buffer.from(blob).toString('base64') });
}
await writeFile(new URL('../internal/wire/testdata/js_vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${out.length} browser-encrypted vectors`);
