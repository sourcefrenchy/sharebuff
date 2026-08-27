# Sharebuff wire & crypto specification (v4)

This document is the single source of truth for the protocol. The Go CLI
(`cmd/sharebuff`), the browser client (`web/crypto.js` + `web/app.js`), the
Cloudflare Worker (`worker/`) and the self-hosted Go server
(`cmd/sharebuff-server`) MUST all conform to it. Cross-language conformance is
enforced by `internal/wire/testdata/vectors.json` + `tests/parity.mjs`.
The rationale lives in [SECURITY.md](SECURITY.md).

## Model

A **secret** is a one-shot encrypted payload: clipboard text or a single file.
The server is zero-knowledge: it stores only ciphertext and a verifier hash,
and can never decrypt — not even the filename or MIME type, which live inside
the encrypted envelope. The secret is destroyed on the **first valid claim**,
after 10 counted invalid claims (burn), or at TTL expiry — whichever comes
first.

v4 replaces v3 (random public locator instead of a key-derived id, tiered key
sizes, single KDF stage). Older links are not supported.

## Parameters

| name    | value |
|---------|-------|
| alphabet | Crockford base32 `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I/L/O/U) for locators, keys and PINs |
| locator | 5 random alphabet chars (25 bits); the server-side record id; also the KDF salt |
| K       | random key: 5 bytes (`--tiny`), 16 bytes (`--short`) or 32 bytes (`--full`); default is automatic — tiny for text ≤ 4096 bytes, short for files and larger text |
| code    | `locator ‖ base32(K)`, dash-grouped by 5 → 13 / 31 / 57 chars normalized |
| PIN     | 4 dictionary words joined by `-` (default; 6,134-word list → 50.3 bits; `--pin-words N`) or `--pin-len N` alphabet chars |
| scrypt  | N=2^16, r=8, p=1, dkLen=64 (~64 MiB, memory-hard) |
| cipher  | AES-256-GCM, 12-byte random nonce |
| max payload | 20 MiB (20971520 bytes) |
| max envelope header | 4096 bytes |
| TTL     | default 604800 s (7 d), min 60 s, max 604800 s |
| attempts| max 10 *counted* invalid claims, then burn |
| cooldown| after the n-th counted wrong attempt: min(2^n, 300) s; claims inside the window get 429 and are NOT counted |

## Codes and normalization

Codes and PINs are typed by humans, so both are normalized before use:
uppercase; strip spaces and hyphens; map `O→0`, `I→1`, `L→1`. Generated
codes never contain the ambiguous characters; word PINs may (e.g. `oil`),
which is harmless because sender and recipient normalize identically and the
attacker's search space is the dictionary either way. The recipient never
needs the dictionary.

```
code = group5(locator ‖ crockford_base32_nopad(K))     e.g. K7Q4T-N8PX2-MW3
```

Decoding takes the first 5 normalized characters as the locator and the rest
(8, 26 or 52 chars) as the key. The key part MUST re-encode to the same
string (zero padding bits) — each key has exactly one canonical spelling.

## Key derivation

```
password = K_bytes ‖ ASCII(normalize(PIN))
root     = scrypt(password, ASCII("sharebuff/v4/" + locator), N=2^16, r=8, p=1, dkLen=64)
K_enc    = root[0:32]     AES-256-GCM key (never leaves the client)
K_auth   = root[32:64]    claim proof (sent to server only on claim)
verifier = SHA-256(K_auth), lowercase hex (stored by server at create)
```

The locator is the salt: unique per secret, public, and independent of K, so
nothing the server stores is a function of K alone and an offline attacker
must search K and PIN jointly (see SECURITY.md). The server verifies a claim
by computing `SHA-256(auth)` and constant-time comparing with the verifier.

Locator collisions: the server answers `409` at create; the sender picks a new
locator and re-derives.

## Envelope

What gets encrypted is an **envelope**: a small JSON header followed by the
raw payload bytes, so filename/MIME are hidden exactly like the payload.

```
header   = JSON: {"t":"text"} or {"t":"file","n":"<filename>","m":"<mime>"}
envelope = u32_bigendian(len(header)) ‖ header ‖ payload
```

- `t` (required): `"text"` (UTF-8 text destined for the clipboard) or
  `"file"` (arbitrary bytes offered as a download).
- `n`, `m` (file mode): suggested filename and MIME type. Clients MUST treat
  `n` as untrusted display data (strip path separators).
- header length ≤ 4096; payload length ≤ 20 MiB.

## Encryption

```
nonce = 12 random bytes
AAD   = ASCII("sharebuff/v4." + locator)
blob  = nonce ‖ AES-256-GCM-Seal(K_enc, nonce, envelope, AAD)
ct    = standard base64 of blob (with padding)
```

## Retrieve URL

```
https://<host>/#K7Q4T-N8PX2-MW3                       (--tiny, default)
https://<host>/#K7Q4T-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X (--short)
https://<host>/#K7Q4T-…                               (--full, 57 chars)
```

The fragment is the code. Browsers never transmit fragments, so opening a
link is stateless and cannot consume, burn, or identify the secret. The bare
site is also a valid entry point: the page offers a Code field when the
fragment is absent (or malformed), for codes read aloud or typed by hand.
The PIN is communicated out-of-band and is never part of the URL.

## HTTP API

JSON bodies, `Cache-Control: no-store` on every API response. `id` MUST match
`^[0-9A-HJKMNP-TV-Z]{5}$` (a normalized locator); `verifier` and `auth` match
`^[0-9a-f]{64}$`.

### `POST /api/secrets`

Request: `{"id": "<locator>", "ct": "<base64>", "verifier": "<hex>", "ttl_seconds": 604800}`
(`ttl_seconds` omitted or 0 → the 7-day default)

- `201` → `{"expires_at": <unix seconds>}`
- `403` → `{"error": "sharing is disabled on this network", "reasons": [...]}` —
  corporate-network signal (see SECURITY.md); nothing is stored. Not sent when
  the server runs in advise-only mode.
- `429` → `{"error": "too many requests", "retry_after_seconds": n}` (+
  `Retry-After`) — per-IP limits (10 creates per minute; 60 creates and 256 MiB
  per hour), enforced exactly by a per-IP Durable Object behind Cloudflare's
  coarse rate-limit binding.
- `400` malformed field / bad base64 / ttl out of range
- `409` locator already in use (sender retries with a new one)
- `413` ciphertext blob larger than max envelope (4 + 4096 + 20 MiB) + 28 bytes

Storage note (Cloudflare): SQLite-backed Durable Object values cap at 2 MB, so
the DO transparently splits the base64 ciphertext across `ct:<n>` keys
(~1.5 MB each) and rejoins them on claim. Create/claim payloads ride DO
`fetch()` bodies (not RPC) to avoid RPC size limits.

### `POST /api/secrets/{id}/claim`

Request: `{"auth": "<hex>"}`

- `200` → `{"ct": "<base64>"}` — the record is atomically replaced by a
  tombstone *before* the response is sent; exactly one claim can ever succeed
  (Durable Objects serialize per-id; the Go server holds a lock).
- `403` → `{"attempts_left": n}` — wrong proof; the secret is untouched. This
  starts a cooldown of min(2^attempts, 300) seconds.
- `429` → `{"retry_after_seconds": n}` (+ `Retry-After` header) — a claim
  arrived during a cooldown window. Rejected **before** the proof is examined
  and **not** counted.
- `410` → `{"reason": "claimed"|"burned"}` — destroyed earlier (tombstone kept
  until original expiry).
- `404` unknown or expired locator.
- `429` with `{"error": "too many requests", ...}` (no `attempts_left`) — the
  per-IP claim limit (30 per minute), applied before the record is looked up.

### `GET /api/env`

`{"share": bool, "reasons": [string]}` — whether the page may offer
browser-side sharing. `share` is false when the server sees a corporate
environment signal (organization policy header `X-Sharebuff-Policy:
retrieve-only`, secure-web-gateway egress ASN, proxy-injected headers) or the
operator disabled it (`-share=false`). See SECURITY.md. No secret material is
involved; the page fails open if the endpoint is unreachable.

### `GET /api/stats`

Public, anonymized usage tallies (cacheable 60 s):
`{"days": 30, "totals": {event: n}, "by_day": {"YYYY-MM-DD": {event: n}},
"by_geo": {"CC|City|asntag": {event: n}}, "feed": [{t, event, cc, city, asn,
reason?}]}` where `event` ∈ create, claim_ok, claim_wrong, claim_burned,
claim_gone, claim_missing, refused, rate_limited, volume_limited and `asntag` =
first 6 hex chars of HMAC-SHA256(STATS_SALT, ASN organization). See SECURITY.md
for what is deliberately not collected.

### `GET /`

The static retrieve page. Response headers (both servers):

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Cache-Control: no-store
```

## Client create flow (web/app.js, Share tab)

1. Payload from the paste box, `navigator.clipboard.readText()` (user
   gesture + browser permission) or a file picker; cap 20 MiB.
2. `key = getRandomValues(5|16|32)`, `PIN = 3–4 words` from the embedded
   wordlist (`web/wordlist.js` = the CLI's list), `locator = randomToken(5)`.
3. `derive` → `encrypt` (AES-256-GCM, AAD bound to the locator) → `POST
   /api/secrets`; on `409` pick a new locator and re-derive.
4. Show `origin/#code` and the PIN; clear the plaintext from the page.

Cross-implementation conformance: `tests/parity.mjs` decrypts Go-encrypted
vectors in JS; `internal/wire/testdata/js_vectors.json` (from
`tests/gen-js-vectors.mjs`) holds browser-encrypted secrets that Go must open.

## Client claim flow (web/app.js, Retrieve tab)

1. Take the code from the fragment, or from the Code field; decode → locator + K.
2. User types the PIN (explicit user action — headless scanners stop here).
3. `root = scrypt(...)` client-side (~1 s; doubles as proof-of-work).
4. `POST /api/secrets/{locator}/claim` with `auth = hex(root[32:64])`.
5. On 200: decrypt with WebCrypto AES-GCM and parse the envelope. `text` →
   clipboard (fallback: explicit "copy" button) + optional reveal; `file` →
   local Blob download named per the header. The server already destroyed the
   ciphertext either way.
