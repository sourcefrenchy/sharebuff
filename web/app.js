// Sharebuff retrieve page. All cryptography lives in crypto.js (shared with
// the node test harness); this file is only UI flow. The code (locator + key)
// comes from the URL fragment or is typed into the page; only the locator and
// the derived claim proof are ever transmitted, and only when a PIN is
// deliberately submitted.
import { decodeCode, derive, decrypt, parseEnvelope, b64decode, toHex } from './crypto.js';

const $ = (id) => document.getElementById(id);
const show = (id) => {
  for (const s of ['state-pin', 'state-done']) $(s).hidden = s !== id;
};
function setStatus(msg, cls = '') {
  const el = $('status');
  el.textContent = msg;
  el.className = 'status ' + cls;
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

// Fragment handling: a valid code hides the code field; an absent one shows
// it (the bare site is a legitimate entry point for typed codes); a malformed
// one shows it with a warning.
const fragment = location.hash.length > 1 ? decodeURIComponent(location.hash.slice(1)) : '';
let fromLink = null;
if (fragment) {
  try { decodeCode(fragment); fromLink = fragment; } catch { fromLink = null; }
}
show('state-pin');
if (fromLink) {
  $('code-row').hidden = true;
  $('pin').focus();
} else {
  $('code-row').hidden = false;
  if (fragment) {
    $('code').value = fragment;
    setStatus('The code in this link looks malformed — check it against what the sender gave you.', 'err');
  }
  $('code').focus();
}

$('pin-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = $('claim-btn');
  const pin = $('pin').value;
  btn.disabled = true;
  try {
    let parsed;
    try {
      parsed = decodeCode(fromLink ?? $('code').value);
    } catch (e) {
      setStatus(`That code doesn't look right: ${e.message}.`, 'err');
      return;
    }
    const { locator, key } = parsed;
    setStatus('Deriving keys locally (memory-hard, ~1 s)…');
    const keys = await derive(key, pin, locator);
    setStatus('Requesting the secret…');
    const resp = await fetch(`/api/secrets/${locator}/claim`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ auth: toHex(keys.auth) }),
    });
    const body = await resp.json().catch(() => ({}));
    if (resp.status === 200) {
      const { header, payload } = parseEnvelope(await decrypt(keys.enc, locator, b64decode(body.ct)));
      if (header.t === 'file') {
        finishFile(header, payload);
      } else {
        const text = new TextDecoder().decode(payload);
        finishText(text, await copyToClipboard(text));
      }
    } else if (resp.status === 403) {
      setStatus(`Wrong PIN or code — the secret is untouched. ${body.attempts_left} attempt${body.attempts_left === 1 ? '' : 's'} left.`, 'err');
    } else if (resp.status === 429) {
      setStatus(`Too many attempts too quickly — wait ${body.retry_after_seconds}s and try again. (Rushed attempts are ignored, not counted.)`, 'err');
    } else if (resp.status === 410) {
      setStatus(body.reason === 'claimed'
        ? 'This secret was already retrieved and has been destroyed.'
        : 'This secret was destroyed after too many wrong PINs.', 'err');
    } else if (resp.status === 404) {
      setStatus('No such secret — it may have expired, or the code is mistyped.', 'err');
    } else {
      setStatus(`Unexpected server response (${resp.status}). Try again.`, 'err');
    }
  } catch (e) {
    setStatus(e.name === 'OperationError'
      ? 'Decryption failed — the code or PIN is wrong for this secret.'
      : `Error: ${e.message}`, 'err');
  } finally {
    btn.disabled = false;
  }
});
