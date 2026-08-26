# Sharebuff wire & crypto specification (v1)

This document is the single source of truth for the protocol. The Go CLI
(`cmd/sharebuff`), the browser client (`web/app.js`), the Cloudflare Worker
(`worker/`) and the self-hosted Go server (`cmd/sharebuff-server`) MUST all
conform to it. Cross-language conformance is enforced by
`internal/wire/testdata/vectors.json` + `tests/parity.mjs`.

## Model

A **secret** is a one-shot encrypted clipboard payload. The server is
zero-knowledge: it stores only ciphertext and a verifier hash, and can never
decrypt. The secret is destroyed on the **first valid claim**, after 5 invalid
claims (burn), or at TTL expiry — whichever comes first.

## Parameters

| name    | value                                             |
|---------|---------------------------------------------------|
| id      | 16 random bytes, base58-encoded (opaque to server) |
| K       | 32 random bytes (256-bit), base58-encoded          |
| PIN     | 6 chars (default) from Crockford base32 alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` |
| salt    | 16 random bytes, base58-encoded                    |
| scrypt  | N=2^16, r=8, p=1, dkLen=64 (~64 MiB, memory-hard)  |
| cipher  | AES-256-GCM, 12-byte random nonce                  |
| max plaintext | 65536 bytes                                  |
| TTL     | default 604800 s (7 d), min 60 s, max 604800 s     |
| attempts| max 5 invalid claims, then burn                    |

Base58 uses the Bitcoin alphabet
`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` (leading zero
bytes encode as `1`).

## PIN normalization

Before use, a PIN is normalized: uppercase; strip spaces and hyphens; map
`O→0`, `I→1`, `L→1`. Generated PINs never contain the ambiguous characters.

## Key derivation

```
password = K_bytes (32 raw bytes) || ASCII(normalize(PIN))
root     = scrypt(password, salt_bytes, N=2^16, r=8, p=1, dkLen=64)
K_enc    = root[0:32]     AES-256-GCM key (never leaves the client)
K_auth   = root[32:64]    claim proof (sent to server only on claim)
verifier = SHA-256(K_auth), lowercase hex (stored by server at create)
```

The server verifies a claim by computing `SHA-256(auth)` and constant-time
comparing with the stored verifier. A database dump (ciphertext + verifier)
grants neither decryption (no `K`) nor a valid claim (needs the SHA-256
preimage `K_auth`).

## Encryption

```
nonce = 12 random bytes
AAD   = ASCII("sharebuff/v1." + id_base58)
blob  = nonce || AES-256-GCM-Seal(K_enc, nonce, plaintext, AAD)
ct    = standard base64 of blob (with padding)
```

Plaintext is the raw clipboard bytes (UTF-8 text expected by the web client).

## Retrieve URL

```
https://<host>/#v1.<id_base58>.<K_base58>.<salt_base58>
```

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
- `413` ciphertext blob larger than 65536 + 28 bytes

### `POST /api/secrets/{id}/claim`

Request: `{"auth": "<hex>"}`

- `200` → `{"ct": "<base64>"}` — the record is atomically replaced by a
  tombstone *before* the response is sent; exactly one claim can ever succeed
  (Durable Objects serialize per-id; the Go server holds a lock).
- `403` → `{"attempts_left": n}` — wrong proof; the secret is untouched.
- `410` → `{"reason": "claimed"|"burned"}` — destroyed earlier (tombstone kept
  until original expiry).
- `404` unknown or expired id.

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

1. Parse fragment `v1.<id>.<K>.<salt>`; reject malformed.
2. User types PIN (explicit user action — headless scanners stop here).
3. `root = scrypt(...)` client-side (~1 s; doubles as proof-of-work).
4. `POST /api/secrets/{id}/claim` with `auth = hex(root[32:64])`.
5. On 200: decrypt with WebCrypto AES-GCM, write plaintext to the clipboard
   (fallback: explicit "copy" button), then offer optional reveal. The server
   already destroyed the ciphertext.

## Explicit non-goals / accepted trade-offs

- An adversary holding the **complete URL including fragment** can burn the
  secret with 5 garbage claims. Fail-closed by design: a leaked link means the
  secret should die.
- No accounts, no create-rate-limiting in v1 (64 KiB cap + platform free-tier
  quotas bound abuse).
- Quantum stance: the scheme is purely symmetric (no RSA/ECDH → nothing for
  Shor's algorithm). AES-256 from 256-bit true entropy keeps ≥128-bit strength
  under Grover — the accepted post-quantum bar for symmetric crypto.
