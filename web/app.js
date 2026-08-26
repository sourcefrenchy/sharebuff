// Sharebuff retrieve client. Conforms to docs/SPEC.md v1.
// All cryptography runs locally: scrypt (vendored @noble/hashes) + WebCrypto
// AES-256-GCM. The URL fragment (id, key, salt) never reaches the server;
// only the derived claim proof is transmitted, and only when a PIN is
// deliberately submitted.
import { scryptAsync } from './scrypt.js';

const SCRYPT = { N: 2 ** 16, r: 8, p: 1, dkLen: 64 };
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

function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');

function normalizePin(pin) {
  return pin.toUpperCase().replace(/[ -]/g, '')
    .replaceAll('O', '0').replaceAll('I', '1').replaceAll('L', '1');
}

function parseFragment(hash) {
  const m = /^#v2\.([1-9A-HJ-NP-Za-km-z]+)\.([1-9A-HJ-NP-Za-km-z]+)\.([1-9A-HJ-NP-Za-km-z]+)$/.exec(hash);
  if (!m) return null;
  try {
    const key = b58decode(m[2]);
    const salt = b58decode(m[3]);
    if (key.length !== 32 || salt.length !== 16) return null;
    return { id: m[1], key, salt };
  } catch {
    return null;
  }
}

const $ = (id) => document.getElementById(id);
const show = (id) => {
  for (const s of ['state-nosecret', 'state-pin', 'state-done']) $(s).hidden = s !== id;
};
function setStatus(msg, cls = '') {
  const el = $('status');
  el.textContent = msg;
  el.className = 'status ' + cls;
}

async function deriveKeys(frag, pin) {
  const pinBytes = new TextEncoder().encode(normalizePin(pin));
  const password = new Uint8Array(frag.key.length + pinBytes.length);
  password.set(frag.key, 0);
  password.set(pinBytes, frag.key.length);
  const root = await scryptAsync(password, frag.salt, SCRYPT);
  return { enc: root.slice(0, 32), auth: root.slice(32, 64) };
}

async function decrypt(encKey, id, blob) {
  const key = await crypto.subtle.importKey('raw', encKey, 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.slice(0, 12), additionalData: new TextEncoder().encode('sharebuff/v2.' + id) },
    key,
    blob.slice(12),
  );
  return new Uint8Array(plain);
}

// Envelope: u32be(header length) || header JSON || payload. See docs/SPEC.md.
function parseEnvelope(bytes) {
  if (bytes.length < 4) throw new Error('envelope truncated');
  const hlen = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
  if (hlen > 4096 || 4 + hlen > bytes.length) throw new Error('envelope header out of bounds');
  const header = JSON.parse(new TextDecoder().decode(bytes.slice(4, 4 + hlen)));
  if (header.t !== 'text' && header.t !== 'file') throw new Error('unknown envelope type');
  return { header, payload: bytes.slice(4 + hlen) };
}

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false; // e.g. gesture expired after the async KDF — offer a button
  }
}

function finishText(text, copied) {
  show('state-done');
  const msg = $('done-msg');
  if (copied) {
    msg.textContent = 'Decrypted and copied to your clipboard.';
  } else {
    msg.textContent = 'Decrypted. Press the button to copy it.';
    const btn = $('copy-btn');
    btn.hidden = false;
    btn.addEventListener('click', async () => {
      if (await copyToClipboard(text)) msg.textContent = 'Copied to your clipboard.';
    });
  }
  $('reveal-btn').hidden = false;
  $('reveal-btn').addEventListener('click', () => {
    const out = $('secret-out');
    out.value = text;
    out.hidden = false;
    $('reveal-btn').hidden = true;
  }, { once: true });
}

function finishFile(header, payload) {
  show('state-done');
  // The name is untrusted data from the sender: keep only a safe basename.
  const name = (header.n || 'sharebuff.bin').replace(/[/\\]/g, '_').slice(0, 255);
  $('done-msg').textContent = `Decrypted ${name} (${formatSize(payload.length)}).`;
  $('reveal-btn').hidden = true;
  const btn = $('download-btn');
  btn.hidden = false;
  btn.textContent = `Download ${name}`;
  const blob = new Blob([payload], { type: header.m || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  btn.addEventListener('click', () => {
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
  });
  btn.click(); // start the download immediately; button stays for retries
}

const frag = parseFragment(location.hash);
if (!frag) {
  show('state-nosecret');
} else {
  show('state-pin');
  $('pin-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const btn = $('claim-btn');
    const pin = $('pin').value;
    btn.disabled = true;
    try {
      setStatus('Deriving key locally (memory-hard, ~1 s)…');
      const keys = await deriveKeys(frag, pin);
      setStatus('Requesting the secret…');
      const resp = await fetch(`/api/secrets/${frag.id}/claim`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ auth: toHex(keys.auth) }),
      });
      const body = await resp.json().catch(() => ({}));
      if (resp.status === 200) {
        const { header, payload } = parseEnvelope(await decrypt(keys.enc, frag.id, b64decode(body.ct)));
        if (header.t === 'file') {
          finishFile(header, payload);
        } else {
          const text = new TextDecoder().decode(payload);
          finishText(text, await copyToClipboard(text));
        }
      } else if (resp.status === 403) {
        setStatus(`Wrong PIN — the secret is untouched. ${body.attempts_left} attempt${body.attempts_left === 1 ? '' : 's'} left.`, 'err');
      } else if (resp.status === 429) {
        setStatus(`Too many attempts too quickly — wait ${body.retry_after_seconds}s and try again. (Rushed attempts are ignored, not counted.)`, 'err');
      } else if (resp.status === 410) {
        setStatus(body.reason === 'claimed'
          ? 'This secret was already retrieved and has been destroyed.'
          : 'This secret was destroyed after too many wrong PINs.', 'err');
      } else if (resp.status === 404) {
        setStatus('No such secret — it may have expired or never existed.', 'err');
      } else {
        setStatus(`Unexpected server response (${resp.status}). Try again.`, 'err');
      }
    } catch (e) {
      setStatus(e.name === 'OperationError'
        ? 'Decryption failed — the link may be corrupted.'
        : `Error: ${e.message}`, 'err');
    } finally {
      btn.disabled = false;
    }
  });
  $('pin').focus();
}
