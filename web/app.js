// Sharebuff page. All cryptography lives in crypto.js (shared verbatim with
// the node test harness); this file is UI flow only. The code (locator + key)
// and the PIN never leave the browser: only the locator, the ciphertext and
// a derived proof are ever transmitted.
import {
  decodeCode, derive, decrypt, parseEnvelope, b64decode, toHex,
  createSecret, newWordPin,
} from './crypto.js';
import { WORDS } from './wordlist.js';

const $ = (id) => document.getElementById(id);
const PANELS = ['state-share', 'state-created', 'state-pin', 'state-done'];
const show = (id) => { for (const p of PANELS) $(p).hidden = p !== id; };
function status(el, msg, cls = '') {
  el.textContent = msg;
  el.className = 'status ' + cls;
}
const setStatus = (msg, cls = '') => status($('status'), msg, cls);
const setShareStatus = (msg, cls = '') => status($('share-status'), msg, cls);

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

async function copyToClipboard(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}

// ---------------------------------------------------------------- tabs
function selectTab(which) {
  const share = which === 'share';
  $('tab-share').setAttribute('aria-selected', String(share));
  $('tab-retrieve').setAttribute('aria-selected', String(!share));
  show(share ? 'state-share' : 'state-pin');
  (share ? $('share-text') : ($('code-row').hidden ? $('pin') : $('code'))).focus();
}
$('tab-share').addEventListener('click', () => selectTab('share'));
$('tab-retrieve').addEventListener('click', () => selectTab('retrieve'));

// ---------------------------------------------------------------- corporate guard
// Best-effort signals that this is a managed / corporate environment, in
// which case the Share tab is hidden (Retrieve keeps working). Not a DLP
// control — see docs/SECURITY.md — but it prevents accidental policy breaches.
async function corporateSignals() {
  const reasons = [];
  try {
    if (navigator.managed && typeof navigator.managed.getManagedConfiguration === 'function') {
      await navigator.managed.getManagedConfiguration(['sharebuff']);
      reasons.push('managed browser (enterprise policy)');
    }
  } catch { /* rejects when not managed */ }
  try {
    const resp = await fetch('/api/env', { cache: 'no-store' });
    if (resp.ok) {
      const env = await resp.json();
      if (env && env.share === false) reasons.push(...(env.reasons || ['server policy']));
    }
  } catch { /* fail open: nothing to decide on */ }
  return reasons;
}

function disableShare(reasons) {
  $('tab-share').hidden = true;
  const note = document.createElement('p');
  note.className = 'warnbox';
  note.setAttribute('role', 'note');
  note.textContent = `Sharing from this page is turned off on corporate or managed devices to avoid posting company data by accident (${reasons.join('; ')}). You can still retrieve secrets here; use a personal device or the CLI to share.`;
  $('state-share').replaceChildren(note);
  if ($('tab-share').getAttribute('aria-selected') === 'true') selectTab('retrieve');
}

// ---------------------------------------------------------------- share
let chosenFile = null;
const MAX_PAYLOAD = 20 * 1024 * 1024;

$('read-clip-btn').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (!text) { setShareStatus('Your clipboard is empty.', 'err'); return; }
    $('share-text').value = text;
    setShareStatus(`Read ${formatSize(new TextEncoder().encode(text).length)} from the clipboard.`);
  } catch {
    setShareStatus('Your browser did not allow reading the clipboard — paste into the box with ⌘V / Ctrl+V instead.', 'err');
  }
});

$('share-file').addEventListener('change', () => {
  chosenFile = $('share-file').files[0] || null;
  $('file-row').hidden = !chosenFile;
  if (chosenFile) {
    $('file-name').textContent = chosenFile.name;
    $('file-size').textContent = formatSize(chosenFile.size);
  }
});
$('file-clear').addEventListener('click', () => {
  chosenFile = null;
  $('share-file').value = '';
  $('file-row').hidden = true;
});

const radio = (name) => document.querySelector(`input[name="${name}"]:checked`).value;

$('create-btn').addEventListener('click', async () => {
  const btn = $('create-btn');
  btn.disabled = true;
  try {
    let header, payload;
    if (chosenFile) {
      if (chosenFile.size > MAX_PAYLOAD) { setShareStatus('That file is over the 20 MiB limit.', 'err'); return; }
      payload = new Uint8Array(await chosenFile.arrayBuffer());
      header = { t: 'file', n: chosenFile.name.slice(0, 255), m: chosenFile.type || 'application/octet-stream' };
    } else {
      const text = $('share-text').value;
      if (!text) { setShareStatus('Paste some text or choose a file first.', 'err'); return; }
      payload = new TextEncoder().encode(text);
      if (payload.length > MAX_PAYLOAD) { setShareStatus('That text is over the 20 MiB limit.', 'err'); return; }
      header = { t: 'text' };
    }
    setShareStatus('Encrypting locally (memory-hard key derivation, ~1 s)…');
    const pin = newWordPin(WORDS, Number(radio('pinwords')));
    const { code, expiresAt } = await createSecret('', {
      header, payload, keyBytes: Number(radio('tier')), pin, ttlSeconds: Number(radio('ttl')),
    });
    // Do not leave plaintext lying around in the page.
    $('share-text').value = '';
    chosenFile = null; $('share-file').value = ''; $('file-row').hidden = true;
    payload.fill(0);

    $('out-url').value = `${location.origin}/#${code}`;
    $('out-pin').value = pin;
    $('out-code').textContent = code;
    $('out-expiry').textContent = expiresAt ? `Expires ${new Date(expiresAt * 1000).toLocaleString()}.` : '';
    setShareStatus('');
    show('state-created');
  } catch (e) {
    setShareStatus(`Could not create the link: ${e.message}`, 'err');
  } finally {
    btn.disabled = false;
  }
});

for (const [btnId, inputId] of [['copy-url', 'out-url'], ['copy-pin', 'out-pin']]) {
  $(btnId).addEventListener('click', async () => {
    const ok = await copyToClipboard($(inputId).value);
    $(btnId).textContent = ok ? 'Copied' : 'Select & copy manually';
    if (!ok) $(inputId).select();
    setTimeout(() => { $(btnId).textContent = 'Copy'; }, 1500);
  });
}
$('share-again').addEventListener('click', () => {
  $('out-url').value = ''; $('out-pin').value = ''; $('out-code').textContent = '';
  selectTab('share');
});

// ---------------------------------------------------------------- retrieve
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
  const name = (header.n || 'sharebuff.bin').replace(/[/\\]/g, '_').slice(0, 255);
  $('done-msg').textContent = `Decrypted ${name} (${formatSize(payload.length)}).`;
  $('reveal-btn').hidden = true;
  const btn = $('download-btn');
  btn.hidden = false;
  btn.textContent = `Download ${name}`;
  const url = URL.createObjectURL(new Blob([payload], { type: header.m || 'application/octet-stream' }));
  btn.addEventListener('click', () => {
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
  });
  btn.click();
}

// Fragment handling: a valid code opens Retrieve with the code hidden; none
// opens Share; a malformed one opens Retrieve with the code field shown.
const fragment = location.hash.length > 1 ? decodeURIComponent(location.hash.slice(1)) : '';
let fromLink = null;
if (fragment) {
  try { decodeCode(fragment); fromLink = fragment; } catch { fromLink = null; }
}
if (fromLink) {
  $('code-row').hidden = true;
  selectTab('retrieve');
} else {
  $('code-row').hidden = false;
  if (fragment) {
    $('code').value = fragment;
    selectTab('retrieve');
    setStatus('The code in this link is malformed — nothing was sent. Check it against what the sender gave you.', 'err');
  } else {
    selectTab('share');
  }
}
corporateSignals().then((reasons) => { if (reasons.length) disableShare(reasons); });

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
      setStatus(`That isn't a valid code (${e.message}). Nothing was sent — check it against what the sender gave you.`, 'err');
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
      setStatus(`Wrong PIN (or wrong code) — the secret is untouched. ${body.attempts_left} attempt${body.attempts_left === 1 ? '' : 's'} left.`, 'err');
    } else if (resp.status === 429) {
      setStatus(`Too many attempts too quickly — wait ${body.retry_after_seconds}s and try again. (Rushed attempts are ignored, not counted.)`, 'err');
    } else if (resp.status === 410) {
      setStatus(body.reason === 'claimed'
        ? 'Already retrieved: this secret was unlocked earlier and destroyed. If that wasn\'t you, someone else had both the code and the PIN — tell the sender.'
        : 'Destroyed after too many wrong PINs. Someone (perhaps you) used up the 10 attempts; ask the sender to share it again.', 'err');
    } else if (resp.status === 404) {
      setStatus('No secret with this code — it may have expired, been mistyped, or never existed.', 'err');
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
