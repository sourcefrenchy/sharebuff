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
PIN: basil-tundra-koala-oxide
```

The link carries only a **code** — Crockford base32, case-insensitive, dashes
optional — so it can be read aloud or typed by hand: the recipient can open the
bare site and enter the code in a box instead of the address bar. Three sizes:
`--tiny` (13 chars, 40-bit key hardened by the PIN), `--short` (31 chars,
128-bit) and `--full` (57 chars, 256-bit, the formal post-quantum bar). By
default the size is **automatic**: short clipboard text gets the 13-char code;
files and text over 4 KiB get the 128-bit key, so a leaked PIN plus a stolen
copy is never enough to unlock them. Flags or `SHAREBUFF_TIER=tiny|short|full`
override. [docs/SECURITY.md](docs/SECURITY.md) has the numbers.

Clipboard capture uses `pbpaste` (macOS), `wl-paste`/`xclip`/`xsel` (Linux),
or `Get-Clipboard` (Windows PowerShell).

**No CLI at hand?** Open the site itself: the **Share** tab pastes text (or reads
the clipboard, or takes a file), encrypts it in the browser with the very same
code the Retrieve tab uses, and hands you the link and the 3-word PIN with copy
buttons. The server still only ever receives ciphertext. From **corporate
networks** the server refuses to create secrets at all (secure-web-gateway ASN,
proxy-stamped headers, a modern browser arriving over HTTP/1.1, or an IT-
injected `X-Sharebuff-Policy: retrieve-only` header) and the page removes the
Share tab — so company data isn't posted by accident, and patching the page
JavaScript changes nothing. Details and limits in [docs/SECURITY.md](docs/SECURITY.md).

The CLI defaults to the deployed Worker
(`https://s.sharebuff-worker.workers.dev`); point it elsewhere with
`SHAREBUFF_URL` or `--server`.

The PIN is **four dictionary words (50 bits)** — easy to read out loud, and the
recipient can type them in any case with spaces or dashes. `--pin-words 3` or
`6`, or `--pin-len N` for random characters. Share the URL and the PIN over **two different channels**. The secret dies on
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
- **Rate-limited at the edge**: 10 creates and 30 claims per IP per minute
  (Workers Rate Limiting binding; the Go server has the same limits), checked
  before any Durable Object is touched. Refusals, burns and rate-limit hits are
  logged as structured events (Workers Logs) and optionally POSTed to an
  `ALERT_WEBHOOK` — never payloads or IPs.
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
| `docs/THREAT-REVIEW.md` | independent static analysis & threat review (2026-08-27) that drove the v4.1 hardening |

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

Optional alerting: `pnpm exec wrangler secret put ALERT_WEBHOOK` with an ntfy,
Slack or Discord webhook URL; every `create_refused`, `secret_burned` and
`rate_limited` event is POSTed as JSON (`{"event","ts","reasons","asn_org",
"country"}` — no payloads, proofs or IPs). The same events always land in
Workers Logs (observability is on).

**Self-hosted (fallback):** run `dist/sharebuff-server-<platform>` (e.g.
`-addr 127.0.0.1:8091 -trust-proxy-headers -alert-webhook https://…`) behind
any TLS-terminating proxy, and point the CLI at it with `SHAREBUFF_URL`/
`--server`. Flags: `-create-rpm`/`-claim-rpm` (per-IP limits), `-enforce`
(corporate-network refusal), `-share=false` (retrieve-only).

## Verify the page you were served

The browser client is first-party JavaScript, so its integrity is what a
compromised origin would attack. `make integrity` prints the SHA-256 of every
file the page runs; compare against what you receive:

```
curl -s https://s.sharebuff-worker.workers.dev/app.js | shasum -a 256
```

Hashes for each tagged release are listed in the release notes.

## CLI usage

```
sharebuff [--server URL] [--ttl 168h] [--pin-words 4 | --pin-len N] [--tiny|--short|--full] [--clip] [--file PATH] [--no-preview]
```

Input precedence: `--file`, then `--clip` (system clipboard), then piped
stdin; run bare, it prints usage and posts nothing. Code size comes from the
flag, else `SHAREBUFF_TIER` (`tiny`/`short`/`full`), else automatic (tiny for
small text, short for files and text over 4 KiB). `--no-preview` suppresses
the 40-char echo of the text. Payloads are capped at 20 MiB. `URL:` and `PIN:` go to stdout (script-friendly); guidance goes to
stderr.
