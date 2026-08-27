# Sharebuff — independent static analysis & threat review

Date: 2026-08-27 · Scope: full repo (Go CLI, Go fallback server, Cloudflare Worker,
browser client, vendored crypto, tests, deploy config). Focus requested:
**(A)** a rogue employee exfiltrating data from inside a corporate network, and
**(B)** any adversary trying to retrieve/decrypt stored data (offline copy of the
ciphertext, brute force, large GPU farms, quantum).

This is an independent review. It confirms much of `SECURITY.md` / `THREAT-MODEL.md`
is accurate and unusually honest, and it surfaces a few gaps those documents understate
(§4, and threat rows T2/T3/T5 below).

---

## 1. What was verified (static analysis)

| Check | Tool | Result |
|---|---|---|
| Compile + vet | `go vet ./...` | clean |
| Unit + race | `go test ./... -race` | all pass |
| E2E lifecycle | `tests/e2e.sh` (create/claim/burn/cooldown/concurrent/3 MiB file/browser path) | pass |
| Cross-language crypto parity | `tests/parity.mjs` (Go vectors decrypted in JS + reverse) | byte-for-byte |
| Go SAST | `gosec` | 6 findings, all benign (see §5 F11) |
| Go vulns | `govulncheck` | 0 in code or called deps |
| Go lint | `staticcheck` | 1 real: broken test assertion (§5 F6) |
| JS/TS/Go SAST | `semgrep` (307 rules) | 0 findings |
| Worker types | `wrangler types && tsc --noEmit` | clean |
| **Supply chain** | re-bundled `@noble/hashes@2.3.0` with esbuild and diffed | **`web/scrypt.js` is byte-identical** to the official bundle |
| Wordlist | script | 6,134 unique words, all 4–8 lowercase ASCII, 12.58 bits/word; 4 words collide after O/I/L normalization (negligible) |
| Git history | full-rev grep for keys/tokens/private keys | none (only test-vector material) |
| Local state | `worker/.wrangler/` | gitignored; holds local dev DO sqlite only |

**Crypto construction (independently re-derived, matches SPEC):**
`root = scrypt(K ‖ normalize(PIN), "sharebuff/v4/"+locator, N=2¹⁶, r=8, p=1, dkLen=64)`;
`K_enc=root[0:32]`, `K_auth=root[32:64]`; server stores `SHA-256(K_auth)`;
payload = AES-256-GCM(`K_enc`, random 96-bit nonce, AAD=`"sharebuff/v4."+locator`).
Purely symmetric — no RSA/ECDH anywhere. Constant-time verifier compare in both
servers (`subtle.ConstantTimeCompare`, hand-rolled CT hex compare in the DO).
One-shot: tombstone written **before** the ciphertext is returned; DO serializes per id;
Go server holds a mutex. Cooldown is per-record (not per-IP), so multi-IP cannot bypass
the 10-counted-attempt cap. No nonce reuse (one envelope per key). AAD binds ct→locator.

**The one structural fact that drives everything below:** the *link* is
`locator ‖ base32(K)` — **the key `K` is inside the URL fragment.** The link is
channel 1 (carries `K`); the PIN is channel 2 (out-of-band). Security = `K` + `PIN`
held separately. Whoever holds the link already knows `K` exactly; whoever holds the
PIN still needs `K`. This is by design, but it means the effective strength against an
offline attacker depends on *which* of the two factors they also have — and the default
configuration is only ~38–40 bits in two of the three offline cases (§3).

---

## 2. How the two requested attack classes actually play out

### (A) Rogue employee exfiltrating from a corporate network

Server-side enforcement (`POST /api/secrets` → 403, nothing stored) fires on any of:
SWG egress ASN (Zscaler/Netskope/Palo-Alto/…), proxy-stamped headers (`Via`,
`X-Zscaler-*`, `X-Netskope-*`, `Proxy-Authorization`, multi-hop `X-Forwarded-For`),
a modern browser arriving over HTTP/1.x (TLS-intercepting proxy tell), or an
org-injected `X-Sharebuff-Policy: retrieve-only`. The page also removes the Share tab.
This is real and correctly server-enforced (a patched page or `curl` gets the same 403 —
verified by `TestCreateEnforcement`).

But it is **fail-open and network-only**, so the bypasses are:

1. **Phone hotspot / personal network** on the corporate laptop → no SWG ASN, no proxy
   headers, HTTP/2 → **creation allowed.** This is the primary bypass.
2. **On-prem SWG that does not stamp a recognized header**, or a corporate network with
   no TLS inspection → the ASN is the company's (not a SWG vendor's) and no header is
   present → **creation allowed.** The ASN signal only catches *cloud* SWGs.
3. **Personal, non-MDM device** on any network → `navigator.managed` is false (and it is
   the only device-level tell, and it is client-side/bypassable) → **creation allowed.**
4. **`SHARE_POLICY=advise` / `-enforce=false`** → no refusal at all (the deployed Worker
   is `enforce`; a self-hosted instance could be advise).
5. Any other channel (email, another paste site, USB) — out of scope by design.

Also: **the 403 is not logged or alerted anywhere** (`observability: enabled:false`, no
logging in the Worker). The org can only detect an attempt via its *own* proxy/SWG logs —
Sharebuff emits no tripwire. So the control deters and (for recognizable egress) blocks,
but it does not *detect*.

**Honest verdict:** for the user's primary concern, the app is a **deterrent + partial
block, not an exfiltration control.** A motivated insider with a hotspot or personal
device is not stopped. Real prevention is MDM/DLP, egress allow-listing, and monitoring —
outside the app. What the app *can* add is a fail-closed corporate mode and an alert
hook (§4, M1/M2).

### (B) Adversary trying to decrypt stored / stolen ciphertext

The server is zero-knowledge; a full DB dump yields `{locator, ciphertext,
SHA-256(K_auth)}` per live secret (≤7 days, most are tombstones). Nothing stored is a
function of `K` alone, so there is **no key-only oracle** — but the work factor depends
on what else the attacker has:

| Attacker also has… | Must search | `--tiny` (default) | `--short` | `--full` |
|---|---|---|---|---|
| **nothing** (dump only) | `K`+`PIN` jointly | 77.7 bits → infeasible | 165.7 bits | 293.7 bits |
| **the link** (`K` known) | `PIN` only | **37.7 bits → GPU-crackable** | **37.7 bits** | **37.7 bits** |
| **the PIN** (known) | `K` only | **40 bits → GPU-crackable** | 128 bits → safe | 256 bits → safe |
| **link + PIN** | — | **0 — immediate** | 0 — immediate | 0 — immediate |

GPU estimate (scrypt N=2¹⁶ r=8 p=1 ≈ 64 MiB/eval, memory-bound; ~6×10³ deriv/s per
A100/H100-class GPU, 1000-GPU farm ≈ 6×10⁶/s):

- **3-word PIN (37.7 bits, 2.2×10¹¹):** 100 GPUs ≈ **4 days**, 1000 GPUs ≈ **10 h**.
- **4-word PIN (50.3 bits, 1.8×10¹⁵):** 100 GPUs ≈ 95 y, 1000 GPUs ≈ **9.5 y**.
- **tiny `K` (40 bits, 1.1×10¹²):** 100 GPUs ≈ 21 d, 1000 GPUs ≈ **2 d**.
- **`K`+`PIN` joint (77.7 bits, 2.6×10²³):** 1000 GPUs ≈ 1.4 billion years.

So the default (`--tiny` + 3-word PIN) is safe **only while the attacker has neither the
link nor the PIN.** The moment they have *either* one plus the ciphertext, the barrier
drops to ~38–40 bits — crackable by a well-resourced offline adversary in hours-to-days.
This is the single most important quantitative finding, and it is **understated in
`THREAT-MODEL.md`**, which claims "tiny costs nothing" outside the breach+link case —
true for breach+link, but **false for breach+PIN-leak** (no row exists for it).

**Quantum:** the scheme is purely symmetric, so Shor has no target. Grover's √-speedup
would need to run the *memory-hard, sequential* scrypt in superposition (64 MiB coherent
state per eval) — no known or projected hardware. AES-256→128-bit and SHA-256→128-bit
post-Grover are fine. Transport uses Cloudflare's hybrid PQ TLS (X25519+ML-KEM), so
"harvest-now-decrypt-later" on the wire is mitigated, and the payload is AES-256 anyway.
On paper only `--full` meets the formal 128-bit PQ bar; `--tiny`/`--short` do not — but
the practical (non-quantum) numbers above dominate.

---

## 3. Ranked threat table (with mitigations)

Risk = Likelihood × Impact for *this* system. "L/M/H". Mitigations marked **[app]** are
code/config changes to Sharebuff; **[org]** are controls the deploying organization must
add (the app cannot do them alone).

| # | Threat | L | I | **Risk** | How it succeeds | Mitigation (to seriously reduce risk) |
|---|--------|---|---|:--------:|----------------|----------------------------------------|
| **T1** | **Rogue employee exfiltrates via non-monitored egress** (phone hotspot, personal device, on-prem SWG w/o header stamping) | H | H | **CRITICAL** | Corporate control is fail-open & network-only; any unrecognizable egress is allowed | **[app]** Add a **fail-closed corporate mode**: `-mode=corporate` + egress **ASN/IP allow-list** — refuse creation from anywhere not allow-listed (closes hotspot for a mandated instance). **[app]** Emit an **alert/webhook + structured log** on every 403 and on high claim-failure rates so the org gets a tripwire. **[org]** MDM/DLP, egress allow-listing, DNS-block the host for non-approved devices, monitor proxy logs. Position the app as one layer, not the control. |
| **T2** | **Offline PIN brute-force: attacker has ciphertext + the link** (3-word PIN = 37.7 bits) | M-H | H | **HIGH** | Link leaks (chat/email/shoulder-surf/shortener) + server dump or intercepted ct; 1000-GPU farm ≈ 10 h | **[app]** Make **4-word (50-bit) the default** and surface a **random-character PIN** option in the web UI (`--pin-len` exists only in CLI); 12-char char-PIN ≈ 60 bits ≈ millennia. **[app]** Warn in UI when a 3-word PIN is chosen for a large/sensitive payload. **[org/procedure]** Never send link and PIN on the same channel; treat the link as key material. |
| **T3** | **Offline key brute-force: attacker has ciphertext + the PIN** (`--tiny` 40-bit `K`) | M | H | **HIGH** | PIN leaks via the OOB channel (SIM swap, call tap, notes) + server dump; 1000-GPU farm ≈ 2 d. **Not covered by the current threat model.** | **[app]** Default to `--short` (128-bit) for file/large payloads, or require `--short`/`--full` when payload > threshold; document that `--tiny` is for low-value, type-by-hand cases. **[app]** Add the missing "breach + PIN-leak" row to `THREAT-MODEL.md` and correct the "tiny costs nothing" claim. |
| **T4** | **Link + PIN captured together** (same channel, or both from one compromised endpoint) | M | H | **HIGH** | Human error: both sent in one message; or malware/extension on one endpoint. **No tier helps.** | **[procedure]** Two-channel rule enforced in UX (the page already says it — make it a hard gate/checkbox). **[org]** Endpoint DLP/EDR, browser-extension allow-listing. **[app]** Optional: refuse to display link+PIN on the same screen simultaneously (show one, then the other). |
| **T5** | **Compromised origin** (Cloudflare account, deploy pipeline, or edge) serves altered page JS that exfiltrates the typed code+PIN | L | H | **MEDIUM-HIGH** | Attacker controls first-party JS; CSP blocks third-party but not first-party. Payload on the *next* retrieval. | **[app/org]** 2FA + branch protection + **signed commits / signed deploy** on the Worker path; pin & integrity-check the page (e.g., SRI is impossible first-party, so use a **published hash of `app.js`/`crypto.js`** users/IT can verify); offer the **self-hosted `sharebuff-server`** for high-trust use; consider a **subresource-integrity-style footer hash** shown on the page. |
| **T6** | **Recipient endpoint compromise** (clipboard managers, downloads folder, browser history holding the fragment, malware) | M | M-H | **MEDIUM** | Local capture after decrypt; history entries are dead links (tombstoned) but the fragment still shows the code. | **[app]** Zeroize DOM buffers where possible, clear the fragment (`history.replaceState`) after a successful claim, auto-expire the in-page plaintext. **[org]** EDR, disable/allow-list clipboard managers, full-disk encryption. |
| **T7** | **Sender endpoint exposure** (CLI scrollback prints code + PIN + 40-char plaintext preview; Share tab shows both on screen) | M | M | **MEDIUM** | Shoulder-surf / scrollback / screen capture on the sender's machine. | **[app]** Add `--no-preview` (or print a hash instead of the 40-char preview); optionally `--quiet` that suppresses the PIN from stdout (write to a file / prompt). **[procedure]** Clear scrollback, use a clean room for high-value shares. |
| **T8** | **Burn / availability DoS** — attacker with a locator sends 10 garbage claims (~14 min); or scans random locators (25-bit space) to burn strangers' secrets | M | M | **MEDIUM** | No edge rate limit; `404` vs `403` reveals liveness. Availability only (cannot read). | **[app]** Add a **Cloudflare rate-limiting rule** on `/api/secrets/*/claim` (per-IP + per-locator) and on `/api/secrets`; consider a **per-IP claim budget**. Document that a leaked link can always be burned (fail-closed by design). |
| **T9** | **DO instantiation / cost amplification** — spam `claim` on random valid locators, each instantiating an empty Durable Object (operator bill / free-plan quota) | M | L | **LOW-MEDIUM** | Valid 5-char locator + 64-hex auth is cheap to generate; no existence check before DO creation. | **[app]** Edge rate-limit (same rule as T8); optionally a cheap **KV "seen" bloom/set** gate before `idFromName`; monitor DO request metrics + alert. |
| **T10** | **Metadata exposure to a TLS-intercepting corporate proxy** (locator, create/claim timing, source IP, payload size) | H (if org inspects TLS) | L-M | **LOW-MEDIUM** | Proxy decrypts TLS; sees the API calls (but **not** content — ct is AES-256, `K_auth` doesn't decrypt). | **[org]** Accept as metadata risk; use the CLI over a non-inspected path for sensitive shares; constant-time sizing is not feasible. No content leak — confirm in org risk register. |
| **T11** | **Quantum "harvest now, decrypt later"** | L (near-term) | M | **LOW** | Record TLS/ciphertext now, decrypt with a future QC. | Already strong: **no asymmetric crypto** (Shor N/A), AES-256/SHA-256 (128-bit post-Grover), **hybrid PQ TLS** at the edge, memory-hard KDF makes Grover-in-superposition infeasible. **[app]** Use `--full` for archival-grade material to meet the formal PQ bar on paper. |
| **T12** | **Network MITM / recording** of the transport | L | L | **LOW** | Break TLS 1.3. | HSTS (+preload candidate), hybrid PQ TLS, and the payload is AES-256 regardless; claim proof is one-shot. No action beyond keeping HSTS/preload. |

**Bottom line for the two requested perspectives:**
- **(A) Rogue employee:** the app *blocks* recognizable corporate egress and *deters*,
  but is **bypassed by a hotspot/personal device** and **does not alert**. Close T1 with a
  fail-closed allow-list mode + alerting, and pair with org MDM/DLP/egress controls.
- **(B) Decrypt stored data:** the crypto core is sound and the "dump only" case is
  infeasible in every tier. The real exposures are **T2** (ciphertext+link → 37.7-bit PIN)
  and **T3** (ciphertext+PIN → 40-bit key on `--tiny`), both GPU-crackable in hours-to-days.
  Fix by **defaulting to a 50-bit+ PIN and a ≥128-bit key for anything sensitive** (T2/T3).

---

## 4. Highest-leverage mitigations (do these first)

1. **M1 — Fail-closed corporate mode + egress allow-list** (closes T1, the user's #1).
   New flag/Worker var: in corporate mode, creation is allowed **only** from allow-listed
   ASNs/IPs; everything else → 403. Without it, the current control is opt-out of a blocklist.
2. **M2 — Alerting on refusals & claim anomalies** (closes the "no tripwire" gap in T1/T8).
   Log 403s with reasons + source, and webhooks/metrics for burn attempts and claim-failure
   spikes. Today `observability` is off and nothing is recorded.
3. **M3 — Stronger default PIN + char-PIN in the web UI** (closes T2). Default 4 words
   (50 bits); offer `--pin-len`-equivalent (e.g., 12–16 random chars = 60–80 bits) in the
   Share tab. This is the single biggest offline-decryption reducer available in-app.
4. **M4 — Stronger default key for sensitive payloads** (closes T3). Default `--short`
   (128-bit) when the payload is a file or > N KB; keep `--tiny` only for small text.
   Add the missing "breach + PIN-leak" threat-model row and fix the "tiny costs nothing" claim.
5. **M5 — Edge rate limiting** (closes T8/T9): Cloudflare rate-limit rules on claim + create.
6. **M6 — Origin integrity** (reduces T5): signed deploy path + a published page-JS hash
   IT can verify; promote the self-hosted server for high-trust use.

---

## 5. Code-level findings (bugs & gaps)

| ID | Sev | Location | Finding |
|----|-----|----------|---------|
| **F1** | Med | `web/index.html`, `web/app.js` | Web Share tab offers only 3/4 **word** PINs (max 50 bits); the higher-entropy **character PIN** (`--pin-len`) exists only in the CLI. Limits offline resistance in the most common (browser) path. |
| **F2** | Med | `cmd/sharebuff/main.go:178`, `wire.go:30` | Default tier is `--tiny` (40-bit `K`). Fine for "dump only", but only 40 bits if the attacker has the PIN+ciphertext (T3). Underweighted for sensitive data. |
| **F3** | Med | `docs/THREAT-MODEL.md` | Missing row for **breach + PIN-leak (no link)**; the verdict "tiny costs nothing" is only true for breach+link, not breach+PIN. Correct the doc. |
| **F4** | Med | `worker/src/index.ts` | No edge rate limiting → burn DoS (T8) + DO cost amplification (T9). Known "next step", still open. |
| **F5** | Med | `worker/src/index.ts` | 403 exfiltration refusals are **not logged/alerted** (`observability:false`); org has no Sharebuff-side tripwire (T1). |
| **F6** | Low | `cmd/sharebuff/words_test.go:41` | `if newWordPIN(3) == pin && newWordPIN(3) == pin` — compares two fresh PINs to the *first* PIN, not to each other; the "PINs are random" test can essentially never fail. Should be `newWordPIN(3) == newWordPIN(3)`. (Test bug, not a security bug.) |
| **F7** | Low | `worker/src/secret.ts:90`, `sharebuff-server/main.go:236` | The client-side scrypt "proof-of-work" is **not enforced server-side** (server only does SHA-256 + CT compare). An online attacker skips scrypt and sends raw `auth` guesses; only the per-record cooldown paces them. By design and still safe (10-cap), but the docs overstate the PoW as a control. |
| **F8** | Low | `web/app.js:186-208` | After a successful claim, the PIN stays in `#pin`, the code stays in the URL fragment (→ browser history), and the plaintext is not zeroized. Minor; acknowledged in threat model #7. |
| **F9** | Low | `cmd/sharebuff/main.go:301` | CLI prints a 40-char **plaintext preview** to the terminal (scrollback leak, threat model #8). Add `--no-preview` / hash-only option. |
| **F10** | Low | `cmd/sharebuff-server/main.go` | Fallback server is **in-memory** (secrets lost on restart — availability only) and has **no ASN signal** (headers/HTTP-version only), so its corporate detection is weaker than the Worker's. Document the parity gap. |
| **F11** | Info | `wire.go:260` (G115), `main.go:80/66/222` (G304/G204/G704) | gosec findings are false-positives/by-design: `uint32(len(hj))` is bounded by the `MaxHeader` check; `--file` path, clipboard tool args, and `--server` URL are explicit user input to a CLI, not attacker-controlled. |
| **F12** | Info | `worker/.wrangler/` | Local dev Durable-Object sqlite (test secrets) on disk; gitignored. Hygiene: `wrangler delete`/clean before sharing a machine. |
| **F13** | Info | `web/index.html:93`, headers | PIN input is `type="text"` (visible to shoulder-surf) and there is no `Permissions-Policy` header. Minor hardening options. |

**Positives worth calling out:** zero-knowledge server; no key-only oracle; locator-salted
KDF; AAD-bound GCM; one-shot destroy-before-respond with per-id serialization; constant-time
verifier compare; strict canonical code decoding (rejects padding-bit variants); CSP
`default-src 'none'` + `no-referrer` + HSTS + `nosniff`; fragment-based key (never transmitted);
byte-identical vendored noble-hashes; strong cross-language vector tests; no secrets in history.

---

## 6. Residual / accepted risks (state explicitly)

- Compromised sender/recipient **endpoints** (malware, malicious extension) see plaintext —
  out of protocol scope; EDR/DLP is the org's job.
- The corporate control is a **network** control, not device DLP; a hotspot or another paste
  site bypasses it. No app can fully solve insider exfiltration alone.
- A holder of the full link can always **burn** a secret (fail-closed by design).
- `404` vs `403` leaks locator liveness (needed for usable errors; enables T8 scanning).
- The origin (page JS) is trusted, as in every browser-delivered E2E app (see T5 mitigations).
