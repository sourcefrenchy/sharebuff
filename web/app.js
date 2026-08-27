// Sharebuff page. All cryptography lives in crypto.js (shared verbatim with
// the node test harness); this file is UI flow only. The code (locator + key)
// and the PIN never leave the browser: only the locator, the ciphertext and
// a derived proof are ever transmitted.
import {
  decodeCode, derive, decrypt, parseEnvelope, b64decode, toHex,
  createSecret, newWordPin, newCharPin, autoKeyBytes, AUTO_ESCALATE_BYTES,
} from './crypto.js';
import { WORDS } from './wordlist.js';

const $ = (id) => document.getElementById(id);
const PANELS = ['state-share', 'state-created', 'state-pin', 'state-done'];
const show = (id) => { for (const p of PANELS) { const el = $(p); if (el) el.hidden = p !== id; } };
const MAX_PAYLOAD = 20 * 1024 * 1024;
const touch = matchMedia('(pointer: coarse)').matches;
const focus = (el) => { if (el && !touch) el.focus(); };

// Two live regions per panel: polite progress, assertive errors. Setting one
// clears the other so the reader never sees stale text.
function say(statusId, errorId, msg, isError = false) {
  $(statusId).textContent = isError ? '' : msg;
  $(errorId).textContent = isError ? msg : '';
}
const setStatus = (msg, cls) => say('status', 'error', msg, cls === 'err');
const setShareStatus = (msg, cls) => say('share-status', 'share-error', msg, cls === 'err');

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
const short = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

async function copyToClipboard(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}

// ---------------------------------------------------------------- tabs
const TABS = ['tab-share', 'tab-retrieve'];
function selectTab(which) {
  const share = which === 'share' && !!$('tab-share');
  for (const id of TABS) {
    const b = $(id);
    if (!b) continue;
    const on = (id === 'tab-share') === share;
    b.setAttribute('aria-selected', String(on));
    b.tabIndex = on ? 0 : -1;
  }
  show(share ? 'state-share' : 'state-pin');
  focus(share ? $('share-text') : ($('code-row').hidden ? $('pin') : $('code')));
}
$('tab-share').addEventListener('click', () => selectTab('share'));
$('tab-retrieve').addEventListener('click', () => selectTab('retrieve'));
$('tabs').addEventListener('keydown', (ev) => {
  const order = TABS.filter((id) => $(id));
  const i = order.indexOf(document.activeElement?.id);
  if (i < 0) return;
  let next = null;
  if (ev.key === 'ArrowRight' || ev.key === 'ArrowDown') next = order[(i + 1) % order.length];
  if (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp') next = order[(i - 1 + order.length) % order.length];
  if (ev.key === 'Home') next = order[0];
  if (ev.key === 'End') next = order[order.length - 1];
  if (next) { ev.preventDefault(); $(next).focus(); $(next).click(); }
});

// ---------------------------------------------------------------- corporate guard
// Best-effort signals that this is a managed / corporate environment. The
// server enforces the same rule on create (403); the page removes the Share
// UI so an unusable feature isn't shown.
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
  } catch { /* fail open: nothing to decide on; the server still enforces */ }
  return reasons;
}

// Remove the Share UI entirely (tab bar included) and explain why at the top
// of Retrieve, where the user actually lands.
function removeShare(reasons, { afterAttempt = false } = {}) {
  for (const id of ['tab-share', 'state-share', 'state-created', 'tabs']) $(id)?.remove();
  const box = $('retrieve-alert');
  box.textContent = (afterAttempt ? 'The server declined to create the link — nothing was uploaded and your text never left this browser. ' : '')
    + `Sharing isn't available on this device or network (${reasons.join('; ')}). Retrieving works as usual; to share, use a personal device or the CLI.`;
  box.hidden = false;
  selectTab('retrieve');
}

const withTimeout = (p, ms) => Promise.race([p, new Promise((r) => setTimeout(() => r([]), ms))]);

// ---------------------------------------------------------------- share
let chosenFile = null;
const radio = (name) => document.querySelector(`input[name="${name}"]:checked`).value;

function updateSummary() {
  const tier = radio('tier');
  const tierText = { auto: 'auto key size', 5: 'tiny 13-char code', 16: 'short 31-char code', 32: 'full 57-char code' }[tier];
  const pinText = { w3: '3-word PIN', w4: '4-word PIN', w6: '6-word PIN', c16: '16-char PIN' }[radio('pin')];
  const ttlText = { 3600: '1 hour', 86400: '1 day', 604800: '7 days' }[radio('ttl')];
  $('opts-summary').textContent = `Options — ${tierText}, ${pinText}, ${ttlText}`;
}
for (const input of document.querySelectorAll('#opts input[type="radio"]')) input.addEventListener('change', updateSummary);

$('read-clip-btn').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (!text) { setShareStatus('Your clipboard is empty.', 'err'); return; }
    $('share-text').value = text;
    setShareStatus(`Read ${formatSize(new TextEncoder().encode(text).length)} from the clipboard.`);
  } catch {
    setShareStatus('The browser blocked clipboard reading — paste into the box with ⌘V / Ctrl+V.', 'err');
  }
});

$('share-file').addEventListener('change', () => {
  chosenFile = $('share-file').files[0] || null;
  $('file-row').hidden = !chosenFile;
  if (chosenFile) {
    $('file-name').textContent = short(chosenFile.name, 60);
    $('file-size').textContent = formatSize(chosenFile.size);
  }
});
$('file-clear').addEventListener('click', () => {
  chosenFile = null;
  $('share-file').value = '';
  $('file-row').hidden = true;
  focus($('share-file'));
});

function makePin() {
  const choice = radio('pin');
  if (choice === 'c16') return newCharPin(16);
  return newWordPin(WORDS, Number(choice.slice(1)));
}

$('create-btn').addEventListener('click', async () => {
  const btn = $('create-btn');
  btn.disabled = true;
  let payload = null;
  try {
    let header;
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
    const tierChoice = radio('tier');
    const keyBytes = tierChoice === 'auto' ? autoKeyBytes(!!chosenFile, payload.length) : Number(tierChoice);
    setShareStatus('Encrypting locally (memory-hard key derivation, ~1 s)…');
    const pin = makePin();
    const { code, expiresAt } = await createSecret('', {
      header, payload, keyBytes, pin, ttlSeconds: Number(radio('ttl')),
    });

    const what = header.t === 'file' ? `Your file ${short(header.n, 40)} (${formatSize(payload.length)})` : `Your text (${formatSize(payload.length)})`;
    $('created-msg').textContent = `${what} is encrypted and posted. It has been cleared from this page.`;
    $('out-url').textContent = `${location.origin}/#${code}`;
    $('out-pin').textContent = pin;
    const tierNote = { 5: '13-char code, 40-bit key', 16: '31-char code, 128-bit key', 32: '57-char code, 256-bit key' }[keyBytes];
    const autoNote = tierChoice === 'auto' && keyBytes === 16 ? ` (chosen automatically: ${header.t === 'file' ? 'files' : `text over ${AUTO_ESCALATE_BYTES / 1024} KiB`} get the 128-bit key)` : '';
    $('out-detail').textContent = `${tierNote}${autoNote}. Typing instead of pasting? Open this site and enter the code ${code} in the Retrieve tab.`
      + (expiresAt ? ` Expires ${new Date(expiresAt * 1000).toLocaleString()}.` : '');

    // Nothing readable stays behind: clear inputs and wipe the buffer.
    $('share-text').value = '';
    chosenFile = null; $('share-file').value = ''; $('file-row').hidden = true;
    payload.fill(0);
    setShareStatus('');
    $('tabs').hidden = true; // a stray tab click would lose the only copy of link + PIN
    show('state-created');
    focus($('copy-url'));
  } catch (e) {
    if (payload) payload.fill(0);
    if (e.status === 403 && e.reasons && e.reasons.length) {
      removeShare(e.reasons, { afterAttempt: true });
    } else {
      setShareStatus(`Could not create the link: ${short(e.message || String(e), 90)}`, 'err');
    }
  } finally {
    if ($('create-btn')) $('create-btn').disabled = false;
  }
});

const copyTimers = {};
for (const [btnId, srcId] of [['copy-url', 'out-url'], ['copy-pin', 'out-pin']]) {
  $(btnId).addEventListener('click', async () => {
    const ok = await copyToClipboard($(srcId).textContent);
    $(btnId).textContent = ok ? 'Copied' : 'Copy failed';
    if (!ok) { const r = document.createRange(); r.selectNodeContents($(srcId)); getSelection().removeAllRanges(); getSelection().addRange(r); }
    clearTimeout(copyTimers[btnId]);
    copyTimers[btnId] = setTimeout(() => { $(btnId).textContent = 'Copy'; }, 1500);
  });
}
$('share-again').addEventListener('click', () => {
  for (const id of ['out-url', 'out-pin', 'out-detail', 'created-msg']) $(id).textContent = '';
  $('opts').open = false;
  setShareStatus('');
  $('tabs').hidden = false;
  selectTab('share');
});

// ---------------------------------------------------------------- retrieve
let fromLink = null;
let ready = false;

$('pin-toggle').addEventListener('click', () => {
  const showing = $('pin').type === 'text';
  $('pin').type = showing ? 'password' : 'text';
  $('pin-toggle').textContent = showing ? 'Show' : 'Hide';
  $('pin-toggle').setAttribute('aria-pressed', String(!showing));
  $('pin-toggle').setAttribute('aria-label', showing ? 'Show PIN' : 'Hide PIN');
});

// Turn crypto.js's terse decode errors into instructions.
function codeProblem(raw, err) {
  if (!raw.trim()) return 'Enter the code from the sender.';
  const m = String(err.message || '');
  if (m.includes('too short') || m.includes('8, 26 or 52')) return 'That code isn\'t complete — it should be 13, 31 or 57 characters (dashes optional).';
  if (m.includes('invalid code character')) return 'That code has a character that can\'t be right — check it against the sender\'s.';
  if (m.includes('non-canonical')) return 'That code has a typo in its last character — check it against the sender\'s.';
  return 'That code doesn\'t look right — check it against the sender\'s.';
}

// Accept a pasted full link as well as a bare code.
const codeFromInput = (raw) => (raw.includes('#') ? raw.slice(raw.indexOf('#') + 1) : raw).trim();

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
    focus(btn);
  }
  $('reveal-btn').hidden = false;
  $('reveal-btn').addEventListener('click', () => {
    const out = $('secret-out');
    out.value = text;
    out.hidden = false;
    $('reveal-btn').hidden = true;
    out.focus();
  }, { once: true });
}

function finishFile(header, payload) {
  show('state-done');
  const name = (header.n || 'sharebuff.bin').replace(/[/\\]/g, '_').slice(0, 255);
  $('done-msg').textContent = `Decrypted ${short(name, 40)} (${formatSize(payload.length)}). The download has started.`;
  $('reveal-btn').hidden = true;
  const btn = $('download-btn');
  btn.hidden = false;
  btn.textContent = `Download ${short(name, 28)} again`;
  btn.title = name;
  const url = URL.createObjectURL(new Blob([payload], { type: header.m || 'application/octet-stream' }));
  addEventListener('pagehide', () => URL.revokeObjectURL(url), { once: true });
  const download = () => {
    const a = document.createElement('a');
    a.href = url; a.download = name; a.click();
  };
  btn.addEventListener('click', download);
  download();
  focus(btn);
}

// Registered before any await so Enter can never fall through to a native
// (URL-serializing) form submit; the button stays disabled until init is done.
$('pin-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if (!ready) return;
  const btn = $('claim-btn');
  const pin = $('pin').value;
  btn.disabled = true;
  try {
    const raw = fromLink ?? codeFromInput($('code').value);
    let parsed;
    try {
      parsed = decodeCode(raw);
    } catch (e) {
      setStatus(codeProblem(raw, e), 'err');
      focus($('code'));
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
      const plain = await decrypt(keys.enc, locator, b64decode(body.ct));
      const { header, payload } = parseEnvelope(plain);
      // Hygiene: the code leaves the address bar/history, the PIN leaves the field.
      history.replaceState(null, '', location.pathname);
      $('pin').value = '';
      setStatus('');
      if (header.t === 'file') {
        finishFile(header, payload);
      } else {
        const text = new TextDecoder().decode(payload);
        finishText(text, await copyToClipboard(text));
      }
      plain.fill(0);
    } else if (resp.status === 403) {
      setStatus(`Wrong PIN — nothing happened to the secret. ${body.attempts_left} attempt${body.attempts_left === 1 ? '' : 's'} left.`, 'err');
      focus($('pin'));
    } else if (resp.status === 429) {
      setStatus(`Too fast — wait ${body.retry_after_seconds}s and try again (rushed attempts aren't counted).`, 'err');
    } else if (resp.status === 410) {
      setStatus(body.reason === 'claimed'
        ? 'Already retrieved and destroyed. If that wasn\'t you, tell the sender: someone had both the code and the PIN.'
        : 'Destroyed after 10 wrong PINs. Ask the sender to share it again.', 'err');
      $('code-row').hidden = false;
    } else if (resp.status === 404) {
      setStatus('No secret with this code — expired, mistyped, or never existed.', 'err');
      $('code-row').hidden = false;
      if (fromLink) { $('code').value = fromLink; fromLink = null; }
      focus($('code'));
    } else {
      setStatus(`Unexpected server response (${resp.status}). Try again.`, 'err');
    }
  } catch (e) {
    setStatus(e.name === 'OperationError'
      ? 'Decryption failed — the code or PIN is wrong for this secret.'
      : `Error: ${short(e.message || String(e), 90)}`, 'err');
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------- init
// Fragment: a valid code opens Retrieve with the code hidden; none opens
// Share; a malformed one opens Retrieve with the code field shown. The
// corporate check runs first so the Share UI never flashes on a device where
// it is then removed.
const fragment = location.hash.length > 1 ? decodeURIComponent(location.hash.slice(1)) : '';
if (fragment) {
  try { decodeCode(fragment); fromLink = fragment; } catch { fromLink = null; }
}
updateSummary();
const corpReasons = await withTimeout(corporateSignals(), 1500);
if (corpReasons.length) removeShare(corpReasons);
if (fromLink) {
  $('code-row').hidden = true;
  selectTab('retrieve');
} else {
  $('code-row').hidden = false;
  if (fragment) {
    $('code').value = fragment;
    selectTab('retrieve');
    setStatus('The code in this link is malformed — nothing was sent. Type the correct code below.', 'err');
  } else if ($('tab-share')) {
    selectTab('share');
  } else {
    selectTab('retrieve');
  }
}
ready = true;
$('claim-btn').disabled = false;
