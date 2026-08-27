<p align="center">
  <img src="web/logo.svg" width="140" alt="Sharebuff — one-shot encrypted drop">
</p>

<h1 align="center">Sharebuff</h1>

One-shot, end-to-end-encrypted secret drop for clipboard text **and files**
(up to 20 MiB). Post with a tiny CLI; the recipient opens a link, types a
one-time PIN, and the data is decrypted **in their browser** — text lands on
their clipboard, files download locally — and is **destroyed on the server at
that instant**. The server is zero-knowledge: it only ever stores ciphertext
plus a verifier hash and can never decrypt (not even the filename, which
travels inside the encrypted envelope).

```
$ sharebuff                          # shows usage (posts nothing)
$ sharebuff --clip                   # sends your clipboard (macOS/Linux/Windows)
$ some-command | sharebuff           # sends piped text
$ sharebuff --file report.pdf        # sends a file (≤ 20 MiB)
$ sharebuff --full --clip            # 57-char code, 256-bit key (formal post-quantum bar)
URL: https://s.sharebuff-worker.workers.dev/#K7Q4T-N8PX2-MW3
PIN: basil-tundra-koala
```

The link carries only a **code** — Crockford base32, case-insensitive, dashes
optional — so it can be read aloud or typed by hand: the recipient can open the
bare site and enter the code in a box instead of the address bar. Three sizes:
`--tiny` (13 chars, 40-bit key hardened by the PIN — **the default**),
`--short` (31 chars, 128-bit) and `--full` (57 chars, 256-bit, the formal
post-quantum bar). Want the full key by default? `export SHAREBUFF_TIER=full`
(flags still override). [docs/SECURITY.md](docs/SECURITY.md) has the numbers.

Clipboard capture uses `pbpaste` (macOS), `wl-paste`/`xclip`/`xsel` (Linux),
or `Get-Clipboard` (Windows PowerShell).

**No CLI at hand?** Open the site itself: the **Share** tab pastes text (or reads
the clipboard, or takes a file), encrypts it in the browser with the very same
code the Retrieve tab uses, and hands you the link and the 3-word PIN with copy
buttons. The server still only ever receives ciphertext. On **corporate or
managed devices** the Share tab hides itself (managed-browser API, secure-web-
gateway/proxy signals, or an IT-injected `X-Sharebuff-Policy: retrieve-only`
header) so company data isn't posted by accident — details and limits in
[docs/SECURITY.md](docs/SECURITY.md).

The CLI defaults to the deployed Worker
(`https://s.sharebuff-worker.workers.dev`); point it elsewhere with
`SHAREBUFF_URL` or `--server`.

The PIN is three dictionary words (37.7 bits; `--pin-words 4` for 50) — easy to
read out loud, and the recipient can type them in any case with spaces or
dashes. Share the URL and the PIN over **two different channels**. The secret dies on
the first valid retrieve, after 10 wrong PINs (burn), or after 7 days —
whichever comes first.

## Security model (short version — full spec in [docs/SPEC.md](docs/SPEC.md))

- **End-to-end encrypted**: AES-256-GCM keyed via memory-hard scrypt
  (N=2^16, r=8, p=1) from a random key `K` **and** the PIN, salted by a random
  public locator. Nothing stored server-side is a function of `K` alone, so an
  attacker with the database must search key and PIN *jointly*: even `--tiny`
  (40-bit key) costs 2⁷⁰ memory-hard scrypt evaluations offline. Encryption
  and decryption only ever happen on the sender's and recipient's machines.
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
  `--full` keeps ≥128-bit strength under Grover. Full analysis of
  online, offline and quantum attacks per tier: [docs/SECURITY.md](docs/SECURITY.md).
- Strict CSP (`default-src 'none'`), no third-party requests, no analytics;
  the only vendored JS is [@noble/hashes](https://github.com/paulmillr/noble-hashes)
  scrypt, pinned and checked in (`web/scrypt.js`).

## Layout

| path | what |
|------|------|
| `cmd/sharebuff` | CLI: encrypt + post, prints URL & PIN to stdout |
| `cmd/sharebuff-server` | self-hosted fallback server (same API, embedded page) |
| `worker/` | Cloudflare Worker + Durable Objects (primary, free-tier host) |
| `web/` | the static page (Share + Retrieve tabs), served identically by both servers |
| `internal/wire` | shared Go crypto/encoding + reference test vectors |
| `tests/` | JS↔Go parity (both directions), browser-sender harness, E2E |
| `docs/SPEC.md` | the protocol spec (source of truth) |
| `docs/SECURITY.md` | threat model: brute force, offline, quantum — per tier |
| `docs/THREAT-MODEL.md` | one-page scenario table with work factors and timings |

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
export SHAREBUFF_URL=https://s.<your-subdomain>.workers.dev   # worker is named "s" for a short host
```

**Self-hosted (fallback):** run `dist/sharebuff-server-<platform>` (e.g.
`-addr 127.0.0.1:8091`) behind any TLS-terminating proxy, and point the CLI at
it with `SHAREBUFF_URL`/`--server`.

## CLI usage

```
sharebuff [--server URL] [--ttl 168h] [--pin-words 3 | --pin-len N] [--tiny|--short|--full] [--clip] [--file PATH]
```

Input precedence: `--file`, then `--clip` (system clipboard), then piped
stdin; run bare, it prints usage and posts nothing. Code size comes from the
flag, else `SHAREBUFF_TIER` (`tiny`/`short`/`full`), else tiny. Payloads are
capped at 20 MiB. `URL:` and `PIN:` go to stdout (script-friendly); guidance goes to
stderr.
