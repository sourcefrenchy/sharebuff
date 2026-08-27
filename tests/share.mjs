// "Browser sender" for tests: creates a secret through the same web/crypto.js
// path the Share tab uses (no CLI involved) and prints URL:/PIN: lines in the
// CLI's format so tests/e2e.sh helpers work unchanged.
// Usage: printf 'text' | node tests/share.mjs <base> [--file path] [--tier 5|16|32] [--words 3]
import { readFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { createSecret, newWordPin } from '../web/crypto.js';
import { WORDLISTS } from '../web/wordlist.js';

const args = process.argv.slice(2);
const base = args[0];
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
if (!base) { console.error('usage: node tests/share.mjs <base> [--file path] [--tier 5|16|32] [--words 3]'); process.exit(2); }

let header, payload;
const file = opt('--file', null);
if (file) {
  payload = new Uint8Array(await readFile(file));
  header = { t: 'file', n: basename(file), m: 'application/octet-stream' };
} else {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  payload = new Uint8Array(Buffer.concat(chunks));
  header = { t: 'text' };
}
const pin = newWordPin(WORDLISTS, Number(opt('--words', 3)));
const { code } = await createSecret(base, { header, payload, keyBytes: Number(opt('--tier', 5)), pin });
console.log(`URL: ${base}/#${code}`);
console.log(`PIN: ${pin}`);
