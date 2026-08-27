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
URL: https://<your-worker>.workers.dev/#4BBZF-TAWN6-YQY
PIN: uguale-jersey-fogon
```

The link carries only a **code** — Crockford base32, case-insensitive, dashes
optional — so it can be read aloud or typed by hand: the recipient can open the
bare site and enter the code in a box instead of the address bar. Three sizes:
`--tiny` (13 chars, 40-bit key hardened by the PIN — **the default**), `--short`
(31 chars, 128-bit) and `--full` (57 chars, 256-bit, the formal post-quantum
bar); `--auto` (or `SHAREBUFF_TIER=auto`) picks short for files and text over
4 KiB so a leaked PIN plus a stolen copy is never enough to unlock them.
[docs/SECURITY.md](docs/SECURITY.md) has the numbers.

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

The CLI has **no built-in server** — you point it at your own instance with
`SHAREBUFF_URL` or `--server` (see *Getting started* below). This repository
ships no hosted service; deploy your own free Cloudflare Worker, or run the
self-hosted binary.

The PIN is **three dictionary words, each from a different language** (English,
Spanish, French, Italian, Portuguese, in random order — 40 bits), easy to read
out loud; the recipient types them in any case with spaces or dashes.
`--pin-words 4` (52 bits) or `6` (77), or `--pin-len N` for random characters.
Secrets expire after **1 hour** by default (`--ttl`, up to 7 days). Share the URL and the PIN over **two different channels**. The secret dies on
the first valid retrieve, after 10 wrong PINs (burn), or when it expires —
whichever comes first.

## Getting started

Sharebuff has no hosted service — you run your own. Two ways:

**A. Cloudflare Worker (free, recommended):**

```
cd worker
pnpm install
pnpm exec wrangler login            # once, opens a browser
pnpm exec wrangler deploy           # creates <your-worker>.workers.dev
```

Then point the CLI at it and use it:

```
export SHAREBUFF_URL=https://<your-worker>.workers.dev   # add to your shell profile
sharebuff --clip
```

The Worker needs a Cloudflare account (free tier is enough: Workers + Durable
Objects). Optional one-time hardening: pick a short account subdomain in the
dashboard (Workers & Pages → *your subdomain*), and set the alert/stats secrets
(see *Deploy* and *Metrics and logs* below).

**B. Self-hosted binary (no Cloudflare):**

```
make build
./sharebuff-server -addr 127.0.0.1:8091        # behind your own TLS proxy for real use
export SHAREBUFF_URL=http://127.0.0.1:8091
sharebuff --clip
```

The self-hosted server keeps secrets in memory (they don't survive a restart)
and serves the same page and API. Put it behind an HTTPS-terminating proxy for
anything beyond local testing.

## Security model (short version — full spec in [docs/SPEC.md](docs/SPEC.md))

- **End-to-end encrypted**: AES-256-GCM keyed via memory-hard scrypt
  (N=2^16, r=8, p=1) from a random key `K` **and** the PIN, salted by a random
  public locator. Nothing stored server-side is a function of `K` alone, so an
  attacker with the database must search key and PIN *jointly*: even the
  `--tiny` default (40-bit key + 40-bit PIN) costs 2⁸⁰ memory-hard scrypt
  evaluations offline. Encryption
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
- **Rate-limited per IP**: 10 creates and 30 claims per minute, plus 60
  creates and 256 MiB of uploads per hour (bulk dead-drop guard) — an exact
  per-IP Durable Object behind Cloudflare's (permissive, eventually-consistent)
  Rate Limiting binding, checked before any per-secret object is touched; the
  Go server has the same limits (`-create-per-hour`, `-mib-per-hour`). Refusals, burns, rate-limit and volume-cap hits are
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
Slack or Discord webhook URL; every `create_refused`, `secret_burned`, `rate_limited` and
`volume_limited` event is POSTed as JSON (`{"event","ts","reasons","asn_org",
"country"}` — no payloads, proofs or IPs). The same events always land in
Workers Logs (observability is on).

**Self-hosted (fallback, in-memory — secrets do not survive a restart):** run `dist/sharebuff-server-<platform>` (e.g.
`-addr 127.0.0.1:8091 -trust-proxy-headers -alert-webhook https://…`) behind
any TLS-terminating proxy, and point the CLI at it with `SHAREBUFF_URL`/
`--server`. Flags: `-create-rpm`/`-claim-rpm` (per-IP limits), `-enforce`
(corporate-network refusal), `-share=false` (retrieve-only).

## Metrics and logs

Three places, from raw to friendly:

- **Logs** — Cloudflare dashboard → Workers & Pages → `s` → *Logs* (observability is
  on), or `cd worker && pnpm exec wrangler tail --format pretty`. Every abnormal
  event (`create_refused`, `secret_burned`, `rate_limited`, `volume_limited`) is a
  JSON line with reasons, egress ASN organization and country — never payloads
  or IPs. `wrangler secret put ALERT_WEBHOOK` forwards them to ntfy/Slack/Discord.
- **`GET /api/stats`** — public, anonymized 30-day tallies per day and per
  place: country + city as seen by the edge, and the network only as a
  6-character keyed-hash tag (`HMAC(STATS_SALT, ASN org)`, so the same network
  is recognizable across rows but never named). No IPs, no locators, no sizes;
  the recent-events feed is minute-resolution and lists abnormal events only.
- **The 📊 Stats button** in the page footer opens the same data as a panel:
  totals, a per-day bar chart of created + retrieved, a "where from" table with
  flags and cities, and the recent abnormal events. The self-hosted server has the
  same endpoint (country/city from `CF-IPCountry`/`CF-IPCity` when proxied;
  `-stats-salt` for a stable tag across restarts).

## Verify the page you were served

The browser client is first-party JavaScript, so its integrity is what a
compromised origin would attack. `make integrity` writes `web/integrity.json`
(SHA-256 of every page file; a test fails if it goes stale) and the page
footer shows the first 12 hex characters of the `app.js` hash. Compare against
what you actually receive — the footer is a convenience, this is the check:

```
curl -s https://<your-worker>.workers.dev/app.js | shasum -a 256
```

Hashes for each tagged release are listed in the release notes.

## License

[MIT](LICENSE) © 2026 jmamblat ([github.com/sourcefrenchy](https://github.com/sourcefrenchy)).
Commercial use, modification and forks are welcome — keep the copyright and
license notice.

## CLI usage

```
sharebuff [--server URL] [--ttl 1h] [--pin-words 3 | --pin-len N] [--tiny|--short|--full|--auto] [--clip] [--file PATH] [--no-preview]
```

Input precedence: `--file`, then `--clip` (system clipboard), then piped
stdin; run bare, it prints usage and posts nothing. Code size comes from the
flag, else `SHAREBUFF_TIER` (`tiny`/`short`/`full`/`auto`), else tiny. `--no-preview` suppresses
the 40-char echo of the text. Payloads are capped at 20 MiB. `URL:` and `PIN:` go to stdout (script-friendly); guidance goes to
stderr.
