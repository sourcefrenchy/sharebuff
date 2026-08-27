# Sharebuff security model

This document explains *why* the v4 design looks the way it does and what
each mechanism defends against. The wire format itself is in [SPEC.md](SPEC.md).

## What a recipient holds

```
URL:   https://<host>/#K7Q4T-N8PX2-MW3      (or: open the site and type the code)
PIN:   TVT7AG                              (sent over a different channel)
```

A **code** is `LOCATOR-KEY`:

| part | size | who sees it | purpose |
|---|---|---|---|
| locator | 5 chars (25 bits), random | the server (it is the record id) | find the record; salt the KDF |
| key `K` | 40 / 128 / 256 bits (`--tiny` / `--short` / `--full`; **automatic**: tiny for small text, short for files and text > 4 KiB) | **only the sender and recipient** | the secret that actually protects the data |
| PIN | **4 dictionary words (50.3 bits)** by default; 3 or 6 words, or random characters (`--pin-len N`, 5 bits each; the page offers 16 = 80 bits) | only the sender and recipient | second factor, delivered out-of-band |

Everything the browser needs to decrypt — key and PIN — is entered client-side
(URL fragment or the page's input boxes). Fragments are never transmitted by
browsers, link previewers or URL scanners, and the page never sends the key or
the PIN anywhere. What crosses the wire is the locator plus a *proof* derived
from key+PIN.

## What the server stores

```
locator → { ciphertext, SHA-256(K_auth), attempts, expiry }
```

`K_enc` (AES-256-GCM key) and `K_auth` (claim proof) are both outputs of one
memory-hard KDF over `K || PIN`, salted by the locator:

```
root = scrypt(K || PIN, "sharebuff/v4/" + locator, N=2^16, r=8, p=1)   # 64 MiB, ~1 s
```

Two properties matter here:

1. **Zero knowledge.** The server never sees `K`, the PIN, `K_enc` or `K_auth`.
   The stored verifier is a hash of `K_auth`; even a full database dump does not
   let anyone *claim* a secret (that needs the hash preimage) or *decrypt* one.
2. **No key-only oracle.** Nothing stored is a function of `K` alone. The
   locator is random, not derived from the key. So an attacker with the
   database must search **key and PIN together** — the PIN's entropy
   *multiplies* the work instead of adding to it. This is what lets `--tiny`
   use a 40-bit key safely.

### Sending from the browser

The Share tab runs the sender side in page JavaScript: key, locator and PIN
from `crypto.getRandomValues`, AES-256-GCM via WebCrypto, the same scrypt.
This adds **no new trusted party** — the recipient already runs decryption in
JavaScript from this origin — and the server still receives only
`{locator, ciphertext, verifier}`. What it does add: plaintext briefly lives in
the sender's page (cleared after posting), and clipboard reads require a click
plus the browser's own permission prompt. The CLI remains the option for
scripts and for hosts where you don't want to trust a browser.

### Corporate and managed devices: creation is refused, and the Share UI is removed

Browser-side sharing is a convenience, and on a company machine it is also an
easy way to post company data somewhere it shouldn't go. Two layers handle
this. **The server enforces**: `POST /api/secrets` answers `403` (nothing
stored) when the request shows a corporate-network signal, so a patched page,
DevTools, or curl all get the same refusal (`SHARE_POLICY=advise` on the
Worker / `-enforce=false` on the Go server downgrade this to report-only).
**The page removes the Share tab entirely** — tab bar included — when the
same check (`GET /api/env`) or the managed-browser API says so, leaving
Retrieve and one line explaining why. The signals:

1. **Managed browser.** Chrome and Edge expose `navigator.managed` only when
   an enterprise policy is applied; if `getManagedConfiguration()` resolves,
   the device is managed.
2. **Secure web gateway / TLS-intercepting proxy** (server-side): the
   request's egress ASN organization matches a known SWG vendor (Zscaler,
   Netskope, Palo Alto Prisma, Forcepoint, iboss, Menlo, Symantec/Broadcom,
   Cisco Umbrella, Cato, Check Point, Fortinet, Skyhigh); it carries
   proxy-injected headers (`Via`, `X-BlueCoat-Via`, `X-Zscaler-*`,
   `X-Netskope-*`, `Proxy-Authorization`, or a multi-hop `X-Forwarded-For`);
   or a **current browser arrives over HTTP/1.x** — browsers speak HTTP/2/3 to
   Cloudflare, TLS-intercepting proxies usually re-originate as HTTP/1.1.
   None of these can be removed from inside the browser: the proxy stamps
   them on its own outbound connection, and the ASN is a property of the
   network.
3. **Organization kill-switch.** IT can inject `X-Sharebuff-Policy:
   retrieve-only` at their proxy (deterministic, no heuristics), run the
   self-hosted server with `-share=false`, or simply DNS-block the host.

**Decision (SB-001):** a fail-closed allow-list mode was considered and
declined for this instance — it is a network control either way, and the
hotspot/personal-device bypass is the organization's MDM/DLP problem; the
blocklist plus alerting is what ships.

**Limits, stated plainly:** this is a *network* control. A corporate laptop
on a phone hotspot, or a corporate network without a recognizable gateway,
looks like home Wi-Fi — device-level enforcement is the organization's MDM/DLP
job. Signal 1 is the only device-based tell and it stays client-side
(bypassable). Heuristics can also misfire on a personal device behind a
corporate proxy (use the CLI from another network). And no matter what,
an insider can use any other paste site; the goal is that *this* one refuses
to be the channel from recognizable corporate egress.

## Threat 1 — online guessing (someone has the code, not the PIN; or neither)

Each claim costs an honest client a full scrypt (~1 s, 64 MiB); note this is
**not** enforced server-side (an attacker can post raw proofs), so the real
online controls are the server's, per secret and per IP:

- **10 counted wrong attempts, then the secret burns** (fail-closed).
- **Exponential cooldown** after each miss: 2 s, 4 s, 8 s … capped at 5 min.
  Claims inside the window are rejected with `429` *before the proof is
  examined* and are **not counted**, so hammering can neither guess faster nor
  burn the secret by volume.
- The record is **tombstoned before the ciphertext is returned**; concurrent
  valid claims yield exactly one winner (Durable Objects serialize per id).

Per IP, creates are capped at 10/min and claims at 30/min (429 with
`Retry-After`). Two layers: Cloudflare's Rate Limiting binding as a cheap,
eventually-consistent outer layer (it is documented as permissive — measured:
150 claims in 45 s produced only 9 refusals), and an **exact** per-IP Durable
Object (`IPLimiter`, one object per client IP, in-memory windows) as the
authoritative count, consulted before any per-secret object is touched. That
bounds locator scanning and burn-by-volume, and means random-locator spam
instantiates one object per attacker IP rather than one per guessed locator. With 50.3 bits of PIN (or 90+ bits of key+PIN for someone
who only has the locator), 10 guesses succeed with probability about
1 in 140 trillion. Online attacks are not the limiting factor in any tier.

## Threat 2 — offline attack after a server breach

The attacker has `{locator, ciphertext, SHA-256(K_auth)}` for every live
secret and can test guesses locally. Each guess is one scrypt over a candidate
`(K, PIN)` pair — 64 MiB of memory per evaluation, which is what makes
scrypt hostile to GPUs and ASICs.

| tier | key | key + PIN | scrypt evaluations to exhaust | at 10⁶ guesses/s (an unrealistic memory-hard farm) |
|---|---|---|---|---|
| `--tiny` (small text) | 40 bits | **90.3 bits** | 2⁹⁰·³ ≈ 1.5 × 10²⁷ | ~50 trillion years |
| `--short` (files, large text) | 128 bits | 178.3 bits | 2¹⁷⁸·³ | beyond physics |
| `--full` | 256 bits | 306.3 bits | 2³⁰⁶·³ | beyond physics |

When the attacker *also* holds one of the two factors, the other is all that
is left:

| attacker also has | must search | `--tiny` | `--short` | `--full` |
|---|---|---|---|---|
| the **link** (K known) | PIN, 50.3 bits | 4.4 M core-years — 100 k cores ≈ 44 y | same | same |
| the **PIN** | K only | 40 bits: 3 500 core-years — 100 k cores ≈ 13 d, a 1 000-GPU farm ≈ 2 d | 2¹²⁸ — infeasible | 2²⁵⁶ — infeasible |

That second row is why the key size is automatic: anything that is a file or
larger than 4 KiB gets the 128-bit key, so a leaked PIN alone never unlocks a
stolen copy of it; the 13-char tiny code is reserved for short clipboard text.

Secrets also live at most 7 days and die on first retrieve, so the attacker's
window is short and most records in a dump are tombstones. Six words
(`--pin-words 6` → 75 bits) or a 16-character random PIN (80 bits) put the
leaked-link case beyond reach entirely.

The PIN is 4 words from a 6,134-word list (the EFF long list, 4–8 letters).
The list is public — assume the attacker has it; entropy is 4 × log₂(6134).
Words beat random characters at equal entropy because people type and read
them aloud correctly; adding more languages only helps by enlarging the pool.

The `--tiny` number is honest but relies on scrypt staying memory-hard and on
the PIN being kept apart from the code; if both the code *and* the PIN leak,
no tier can help — that is the recipient's endpoint, not the protocol.

## Threat 3 — quantum adversaries (harvest now, decrypt later)

- The scheme is **purely symmetric**: AES-256-GCM, SHA-256, scrypt. There is
  no RSA/ECDH key exchange anywhere in the application layer, so Shor's
  algorithm — the attack that breaks today's public-key crypto — has nothing
  to target. Recorded ciphertext cannot be "opened later" by a quantum
  computer the way TLS-only protection can.
- Grover's algorithm gives at most a square-root speed-up on symmetric search.
  For **`--full`** that leaves AES-256 / a 286-bit search at ≥128-bit
  post-quantum strength — the bar NIST accepts for symmetric crypto.
- For `--short` (178 → ~89 bits) and `--tiny` (90 → ~45 bits), Grover would
  have to evaluate *scrypt itself* inside a quantum circuit, keeping 64 MiB of
  state coherent per evaluation, in a sequential search. No known or projected
  hardware makes that practical; still, these tiers sit below the *formal*
  256-bit bar. `--tiny` is the default because typeability is the point of
  the tool; use `--full` (or `SHAREBUFF_TIER=full`) for material that must
  meet the formal post-quantum bar on paper.
- In transit, Cloudflare's edge negotiates hybrid post-quantum TLS
  (X25519 + ML-KEM) with modern browsers, so even the transport layer resists
  recording attacks — and what it carries is already AES-256 ciphertext.

## Not a command-and-control channel (SB-015)

Sharebuff is a poor C2 channel by construction, and this property is guarded
by a test (`TestNoPushChannels`): claims are one-shot (the record is
tombstoned *before* the ciphertext is returned, so there is no state to poll);
there is no server→client push of any kind (no WebSocket, SSE, long-poll or
subscribe endpoint); the code rides in the URL fragment, so the server cannot
tell who opened a link; and the Worker is not an open proxy (it routes
`/api/*` and static assets only). Using it as a dead-drop at scale is bounded
by the per-IP caps (10 creates/min, 60 creates and 256 MiB per hour, alerted
as `volume_limited`). Residual risks: an origin compromise turning the page
into a beacon (Threat 6 in the model), and a very slow covert channel via
locator liveness (404/403/410 differ) — bounded by the same rate limits and
visible in the alert stream as sustained probing.

**No open-tracking, by design (SB-016).** Because the fragment is never
transmitted, the server cannot record who opened a link or when. This is
anti-stalking and anti-C2, and it is a commitment: no "delivery confirmation"
feature will be added that requires transmitting the fragment.

## Threat 4 — the link itself

- **Preview bots / scanners**: the code rides in the URL fragment, which is
  never sent to any server. Opening a link changes no state; only a
  deliberately submitted PIN does.
- **URL shorteners**: never put a Sharebuff URL through one — the shortener
  would store the key. Shorten the hostname instead (custom domain), or type
  the code into the page.
- **Leaked link**: an adversary with the code but not the PIN gets 10 paced
  guesses at 50.3 bits; if the link leaks, the sender should assume the secret
  may be burned (10 garbage claims) — fail-closed by design.

## Threat 5 — the public locator

Locators are guessable (32⁵ ≈ 33.5 million). Knowing one grants nothing
without key+PIN, but an attacker could try to *burn* strangers' secrets by
sending 10 garbage claims to random locators. With `L` live secrets the
expected work to hit one is 33.5 M / L × 10 paced requests per hit — a
nuisance, not a break, and bounded by the 7-day lifetime. A per-IP rate limit
at the edge is the natural next step if it ever matters.

## One-page attack/timing summary

See [THREAT-MODEL.md](THREAT-MODEL.md) for the scenario table with concrete
work factors and timings, and [THREAT-REVIEW.md](THREAT-REVIEW.md) for the
independent review whose findings (T1–T12, F1–F13) shaped the current design.

## Detection: structured alerts

The Worker logs `create_refused` (with reasons, egress ASN organization and
country), `secret_burned` (locator) and `rate_limited` (bucket) as JSON to
Workers Logs, and POSTs the same events to `ALERT_WEBHOOK` when that secret
is set. Payloads, proofs and client IPs are never included. The self-hosted
server logs the same events and accepts `-alert-webhook`; it lacks the ASN
signal (headers and HTTP-version tells only), so its corporate detection is
weaker than the Worker's, and it is **in-memory** — secrets do not survive a
restart (availability only; nothing readable is ever on disk).

## Out of scope

- Compromised endpoints (malware on the sender's or recipient's machine, a
  malicious browser extension) see plaintext regardless of protocol.
- Coercion of the recipient. One-shot semantics at least make it evident
  *whether* a secret has already been retrieved.
