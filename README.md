# Sharebuff

One-shot, end-to-end-encrypted clipboard drop. Post a secret from your
clipboard with a tiny CLI; the recipient opens a link, types a one-time PIN,
and the data is decrypted **in their browser**, copied to their clipboard, and
**destroyed on the server at that instant**. The server is zero-knowledge: it
only ever stores ciphertext plus a verifier hash and can never decrypt.

```
$ pbpaste | sharebuff        # or: sharebuff  (reads the macOS clipboard)
URL: https://sharebuff.sharebuff-worker.workers.dev/#v1.<id>.<key>.<salt>
PIN: 7KQ4TN
```

The CLI defaults to the deployed Worker
(`https://sharebuff.sharebuff-worker.workers.dev`); point it elsewhere with
`SHAREBUFF_URL` or `--server`.

Share the URL and the PIN over **two different channels**. The secret dies on
the first valid retrieve, after 10 wrong PINs (burn), or after 7 days —
whichever comes first.

## Security model (short version — full spec in [docs/SPEC.md](docs/SPEC.md))

- **End-to-end encrypted**: AES-256-GCM keyed via memory-hard scrypt
  (N=2^16, r=8, p=1) from a 256-bit random key `K` + the PIN. Encryption and
  decryption only ever happen on the sender's and recipient's machines.
- **Zero-knowledge server**: stores `{ciphertext, SHA-256(K_auth)}`. A full
  database dump yields neither plaintext (no `K`) nor a valid claim (needs the
  hash preimage).
- **Burn on first *valid* retrieve, atomically**: a claim must present
  `K_auth`, derivable only from `K` (URL fragment) **and** the PIN. One
  Durable Object per secret serializes claims — exactly one can ever succeed;
  the record is tombstoned before the ciphertext is returned.
- **Wrong PINs never burn** the secret (up to 10 counted attempts, then it
  burns — online brute force is capped, and each guess costs a ~1 s, 64 MiB
  scrypt). After each miss an **exponential cooldown** (2 s → 4 s → … → 5 min)
  rejects further claims with `429` *before the proof is examined*, and those
  are **not counted**: hammering the endpoint can neither brute-force the PIN
  nor burn the secret by volume.
- **Bot/scanner-proof by construction**: everything secret-specific lives in
  the URL *fragment*, which browsers, link-preview bots and URL scanners never
  send to any server. Opening the link is stateless; only a deliberately
  submitted PIN changes anything.
- **Quantum stance**: purely symmetric crypto — nothing for Shor's algorithm;
  AES-256 from 256-bit entropy keeps ≥128-bit strength under Grover.
- Strict CSP (`default-src 'none'`), no third-party requests, no analytics;
  the only vendored JS is [@noble/hashes](https://github.com/paulmillr/noble-hashes)
  scrypt, pinned and checked in (`web/scrypt.js`).

## Layout

| path | what |
|------|------|
| `cmd/sharebuff` | CLI: encrypt + post, prints URL & PIN to stdout |
| `cmd/sharebuff-server` | self-hosted fallback server (same API, embedded page) |
| `worker/` | Cloudflare Worker + Durable Objects (primary, free-tier host) |
| `web/` | the static retrieve page, served identically by both servers |
| `internal/wire` | shared Go crypto/encoding + reference test vectors |
| `tests/` | JS↔Go parity test and E2E harness |
| `docs/SPEC.md` | the protocol spec (source of truth) |

## Build & test

```
make build      # host binaries: ./sharebuff, ./sharebuff-server
make test       # go vet + go test -race + JS/Go crypto parity
make e2e        # full local lifecycle against the fallback server
make release    # dist/: macOS (arm64+Intel), Linux (static, RHEL-ok), Windows
```

Regenerate the crypto reference vectors after any (spec-versioned!) change:
`go test ./internal/wire -run TestVectors -update && node tests/parity.mjs`.

To upgrade the vendored scrypt: `pnpm add @noble/hashes esbuild`, bundle
`export { scryptAsync } from '@noble/hashes/scrypt.js'` with
`esbuild --bundle --format=esm`, and re-run `node tests/parity.mjs`.

## Deploy

**Cloudflare (primary, free):**

```
cd worker
pnpm install
pnpm exec wrangler login    # once
pnpm exec wrangler deploy
export SHAREBUFF_URL=https://sharebuff.<your-subdomain>.workers.dev
```

**Self-hosted (fallback):** run `dist/sharebuff-server-<platform>` (e.g.
`-addr 127.0.0.1:8091`) behind any TLS-terminating proxy, and point the CLI at
it with `SHAREBUFF_URL`/`--server`.

## CLI usage

```
sharebuff [--server URL] [--ttl 168h] [--pin-len 6] [--clip]
```

Reads piped stdin, or the macOS clipboard when run interactively. Input is
capped at 64 KiB. `URL:` and `PIN:` go to stdout (script-friendly); guidance
goes to stderr.
