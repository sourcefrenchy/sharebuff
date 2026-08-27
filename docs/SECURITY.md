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
| key `K` | 40 / 128 / 256 bits (`--tiny` (default) / `--short` / `--full`) | **only the sender and recipient** | the secret that actually protects the data |
| PIN | 6 chars (30 bits), random | only the sender and recipient | second factor, delivered out-of-band |

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

## Threat 1 — online guessing (someone has the code, not the PIN; or neither)

Each claim costs the client a full scrypt (~1 s, 64 MiB) — a built-in
proof-of-work — and the server enforces, per secret:

- **10 counted wrong attempts, then the secret burns** (fail-closed).
- **Exponential cooldown** after each miss: 2 s, 4 s, 8 s … capped at 5 min.
  Claims inside the window are rejected with `429` *before the proof is
  examined* and are **not counted**, so hammering can neither guess faster nor
  burn the secret by volume.
- The record is **tombstoned before the ciphertext is returned**; concurrent
  valid claims yield exactly one winner (Durable Objects serialize per id).

With 30 bits of PIN (or 70+ bits of key+PIN for someone who only has the
locator), 10 guesses have a success probability of about 1 in 100 million at
best. Online attacks are not the limiting factor in any tier.

## Threat 2 — offline attack after a server breach

The attacker has `{locator, ciphertext, SHA-256(K_auth)}` for every live
secret and can test guesses locally. Each guess is one scrypt over a candidate
`(K, PIN)` pair — 64 MiB of memory per evaluation, which is what makes
scrypt hostile to GPUs and ASICs.

| tier | key | key + PIN | scrypt evaluations to exhaust | at 10⁶ guesses/s (an unrealistic memory-hard farm) |
|---|---|---|---|---|
| `--tiny` (default) | 40 bits | **70 bits** | 2⁷⁰ ≈ 1.2 × 10²¹ | ~37 million years |
| `--short` | 128 bits | 158 bits | 2¹⁵⁸ | beyond physics |
| `--full` | 256 bits | 286 bits | 2²⁸⁶ | beyond physics |

Secrets also live at most 7 days and die on first retrieve, so the attacker's
window is short and most records in a dump are tombstones. Raising the PIN
length (`--pin-len 8` → 40 bits) adds 10 bits to every tier.

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
- For `--short` (158 → ~79 bits) and `--tiny` (70 → ~35 bits), Grover would
  have to evaluate *scrypt itself* inside a quantum circuit, keeping 64 MiB of
  state coherent per evaluation, in a sequential search. No known or projected
  hardware makes that practical; still, these tiers sit below the *formal*
  256-bit bar. `--tiny` is the default because typeability is the point of
  the tool; use `--full` (or `SHAREBUFF_TIER=full`) for material that must
  meet the formal post-quantum bar on paper.
- In transit, Cloudflare's edge negotiates hybrid post-quantum TLS
  (X25519 + ML-KEM) with modern browsers, so even the transport layer resists
  recording attacks — and what it carries is already AES-256 ciphertext.

## Threat 4 — the link itself

- **Preview bots / scanners**: the code rides in the URL fragment, which is
  never sent to any server. Opening a link changes no state; only a
  deliberately submitted PIN does.
- **URL shorteners**: never put a Sharebuff URL through one — the shortener
  would store the key. Shorten the hostname instead (custom domain), or type
  the code into the page.
- **Leaked link**: an adversary with the code but not the PIN gets 10 paced
  guesses at 30 bits; if the link leaks, the sender should assume the secret
  may be burned (10 garbage claims) — fail-closed by design.

## Threat 5 — the public locator

Locators are guessable (32⁵ ≈ 33.5 million). Knowing one grants nothing
without key+PIN, but an attacker could try to *burn* strangers' secrets by
sending 10 garbage claims to random locators. With `L` live secrets the
expected work to hit one is 33.5 M / L × 10 paced requests per hit — a
nuisance, not a break, and bounded by the 7-day lifetime. A per-IP rate limit
at the edge is the natural next step if it ever matters.

## Out of scope

- Compromised endpoints (malware on the sender's or recipient's machine, a
  malicious browser extension) see plaintext regardless of protocol.
- Coercion of the recipient. One-shot semantics at least make it evident
  *whether* a secret has already been retrieved.
