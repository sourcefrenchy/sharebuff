# Sharebuff wire & crypto specification (v3)

This document is the single source of truth for the protocol. The Go CLI
(`cmd/sharebuff`), the browser client (`web/app.js`), the Cloudflare Worker
(`worker/`) and the self-hosted Go server (`cmd/sharebuff-server`) MUST all
conform to it. Cross-language conformance is enforced by
`internal/wire/testdata/vectors.json` + `tests/parity.mjs`.

## Model

A **secret** is a one-shot encrypted payload: clipboard text or a single file.
The server is zero-knowledge: it stores only ciphertext and a verifier hash,
and can never decrypt — not even the filename or MIME type, which live inside
the encrypted envelope. The secret is destroyed on the **first valid claim**,
after 10 counted invalid claims (burn), or at TTL expiry — whichever comes
first.

v3 replaces v2 (id/salt derived from the key; typeable key codes; optional 128-bit short keys). Older links are not supported.

## Parameters

| name    | value                                             |
|---------|---------------------------------------------------|
| K       | 32 random bytes (default) or 16 with `--short`; the only secret in the URL |
| code    | K in Crockford base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), dash-grouped by 5: 52 or 26 chars |
| id      | 16 bytes derived from K (KDF stage A), base58 — opaque to the server |
| salt    | 16 bytes derived from K (KDF stage A)               |
| PIN     | 6 chars (default) from the same Crockford alphabet |
| scrypt  | N=2^16, r=8, p=1, dkLen=64 (~64 MiB, memory-hard)  |
| cipher  | AES-256-GCM, 12-byte random nonce                  |
| max payload | 20 MiB (20971520 bytes)                        |
| max envelope header | 4096 bytes                             |
| TTL     | default 604800 s (7 d), min 60 s, max 604800 s     |
| attempts| max 10 *counted* invalid claims, then burn         |
| cooldown| after the n-th counted wrong attempt: min(2^n, 300) s; claims inside the window get 429 and are NOT counted |

Base58 uses the Bitcoin alphabet
`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` (leading zero
bytes encode as `1`).

## Code & PIN normalization

Both the key code and the PIN are typed by humans, so both are normalized
before use: uppercase; strip spaces and hyphens; map `O→0`, `I→1`, `L→1`.
Generated codes/PINs never contain the ambiguous characters. A key code must
decode canonically (zero padding bits) so each key has exactly one spelling.

## Key derivation

```
stage A (from K alone — no PIN):
  pre   = scrypt(K_bytes, ASCII("sharebuff/v3/pre"), N=2^16, r=8, p=1, dkLen=32)
  id    = base58(pre[0:16])     server-side record key
  salt  = pre[16:32]

stage B (K + PIN):
  password = K_bytes || ASCII(normalize(PIN))
  root     = scrypt(password, salt, N=2^16, r=8, p=1, dkLen=64)
  K_enc    = root[0:32]     AES-256-GCM key (never leaves the client)
  K_auth   = root[32:64]    claim proof (sent to server only on claim)
  verifier = SHA-256(K_auth), lowercase hex (stored by server at create)
```

Stage A runs scrypt too, so the id the server stores is only an *expensive*
oracle for guessing K (no cheap hash-of-key exists anywhere). Keeping the PIN
out of stage A means a wrong PIN still maps to the right id, so the server
can count attempts and enforce the cooldown/burn.

The server verifies a claim by computing `SHA-256(auth)` and constant-time
comparing with the stored verifier. A database dump (ciphertext + verifier)
grants neither decryption (no `K`) nor a valid claim (needs the SHA-256
preimage `K_auth`).

## Envelope

What gets encrypted is an **envelope**: a small JSON header followed by the
raw payload bytes. The header (filename, MIME type, kind) is therefore hidden
from the server exactly like the payload itself.

```
header   = JSON: {"t":"text"} or {"t":"file","n":"<filename>","m":"<mime>"}
envelope = u32_bigendian(len(header)) || header || payload
```

- `t` (required): `"text"` (payload is UTF-8 text destined for the clipboard)
  or `"file"` (payload is arbitrary bytes offered as a download).
- `n`, `m` (file mode): suggested filename and MIME type. Clients MUST treat
  `n` as untrusted display data (strip path separators).
- header length ≤ 4096; payload length ≤ 20 MiB.

## Encryption

```
nonce = 12 random bytes
AAD   = ASCII("sharebuff/v3." + id_base58)
blob  = nonce || AES-256-GCM-Seal(K_enc, nonce, envelope, AAD)
ct    = standard base64 of blob (with padding)
```

## Retrieve URL

```
https://<host>/#XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X        (--short, 128-bit)
https://<host>/#XXXXX-…-XX                            (default, 256-bit)
```

The fragment is just the key code; it is case-insensitive and dashes are
optional, so it can be dictated or typed on another machine.

Everything after `#` is a URL fragment: it is never transmitted to any server
(not by browsers, link-preview bots, or URL scanners). Opening the link is
therefore stateless and cannot consume, burn, or identify the secret. The PIN
is communicated out-of-band and is never part of the URL.

## HTTP API

JSON bodies, `Cache-Control: no-store` on every API response. Servers treat
`id` as an opaque `^[1-9A-HJ-NP-Za-km-z]{16,32}$` string; `verifier` and
`auth` match `^[0-9a-f]{64}$`.

### `POST /api/secrets`

Request: `{"id": "...", "ct": "<base64>", "verifier": "<hex>", "ttl_seconds": 604800}`
(`ttl_seconds` omitted or 0 → the 7-day default)

- `201` → `{"expires_at": <unix seconds>}`
- `400` malformed field / bad base64 / ttl out of range
- `409` id already exists
- `413` ciphertext blob larger than max envelope (4 + 4096 + 20 MiB) + 28 bytes

Storage note (Cloudflare): SQLite-backed Durable Object values cap at 2 MB, so
the DO transparently splits the base64 ciphertext across `ct:<n>` keys
(~1.5 MB each) and rejoins them on claim. This is invisible to clients. The
create/claim payloads ride DO `fetch()` bodies (not RPC) to avoid RPC size
limits.

### `POST /api/secrets/{id}/claim`

Request: `{"auth": "<hex>"}`

- `200` → `{"ct": "<base64>"}` — the record is atomically replaced by a
  tombstone *before* the response is sent; exactly one claim can ever succeed
  (Durable Objects serialize per-id; the Go server holds a lock).
- `403` → `{"attempts_left": n}` — wrong proof; the secret is untouched. This
  starts a cooldown of min(2^attempts, 300) seconds.
- `429` → `{"retry_after_seconds": n}` (+ `Retry-After` header) — a claim
  arrived during a cooldown window. It is rejected **before** the proof is
  even examined and does **not** count toward the burn limit: hammering the
  endpoint can neither brute-force the PIN nor burn the secret by volume.
- `410` → `{"reason": "claimed"|"burned"}` — destroyed earlier (tombstone kept
  until original expiry).
- `404` unknown or expired id.

Burn-vs-abuse rationale: only deliberate, correctly paced wrong proofs are
counted (10 lifetime → burn, fail-closed). Rapid-fire attempts — the signature
of a bot or a spam-burn attack — are absorbed as uncounted 429s.

### `GET /`

The static retrieve page. Response headers (both servers):

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store
```

## Client claim flow (web/app.js)

1. Decode the key code from the fragment; reject malformed.
2. User types PIN (explicit user action — headless scanners stop here).
3. KDF stages A and B client-side (~2 s; doubles as proof-of-work).
4. `POST /api/secrets/{id}/claim` with `auth = hex(root[32:64])`.
5. On 200: decrypt with WebCrypto AES-GCM and parse the envelope. `text` →
   write to the clipboard (fallback: explicit "copy" button) + optional
   reveal. `file` → offer a local Blob download named per the header. The
   server already destroyed the ciphertext either way.

## Explicit non-goals / accepted trade-offs

- An adversary holding the **complete URL including fragment** can burn the
  secret with 5 garbage claims. Fail-closed by design: a leaked link means the
  secret should die.
- No accounts, no create-rate-limiting in v1 (64 KiB cap + platform free-tier
  quotas bound abuse).
- Quantum stance: the scheme is purely symmetric (no RSA/ECDH → nothing for
  Shor's algorithm). AES-256 from 256-bit true entropy keeps ≥128-bit strength
  under Grover — the accepted post-quantum bar for symmetric crypto.
