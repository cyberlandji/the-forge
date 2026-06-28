# PA-03 — KongTuke / MintsLoader / GhostWeaver — Detection Findings & Validation Notes

Operation PA-03 of the PCAP Autopsy series, ported into The Forge as a Detection-as-Code
pipeline. A six-stage supply-chain intrusion: ClickFix initial access → MintsLoader →
GhostWeaver RAT, with command-and-control delivered over the long-dead **FINGER** protocol
(TCP/79) abused as a covert channel. 16 Suricata rules across DNS, TLS, HTTP, and TCP,
validated in both directions — detections fire on the malware, and the false-positive
surface is measured and pinned.

---

## Fixture set — three classes

| Class | Fixture | Purpose |
|---|---|---|
| known-bad | `fixtures/known-bad/kongtuke-mintsloader-ghostweaver-1.pcap` | Initial-access phase |
| known-bad | `fixtures/known-bad/kongtuke-mintsloader-ghostweaver-2.pcap` | Stager → C2 → delivery → callback |
| known-good | `fixtures/known-good/benign-clean.pcap` | Ordinary benign traffic — nothing may fire |
| benign-adversarial | `fixtures/benign-adversarial/cousins.pcap` | Technique-twins — broad rules fire by design |

Per-fixture SID assertions live in `expected.yaml` (the source of truth — not duplicated here
so the two can't drift).

**Why the known-good is crafted, not trimmed.** PA-02 sliced its known-good from the same
source capture and it worked, because that slice happened to be clean of the Lumma rules.
PA-03 cannot: the GhostWeaver C2 session (TCP to `173.232.146.62:25658`) runs to the end of
the capture, so an end-trim still fires `100008`, and a head-trim hits the initial-access DNS
and TLS rules instead. **The malware capture is malicious end to end — there is no benign
window inside it.** A known-good must be independent benign traffic, so it is crafted.
`benign-clean.pcap` and `cousins.pcap` are synthetic benign captures, deterministic for CI;
they may be swapped for trimmed real benign captures later without changing the manifest.

**The third class.** `cousins.pcap` carries the campaign's *technique* (a PowerShell
user-agent, a Werkzeug server header, a script-extension download, a `/m` check-in, a
`DllImport` snippet) but **none** of its indicators. There, the precise rules `must_not_fire`
and the broad rules `must_fire` — which pins the false-positive surface so it cannot change
silently. The manifest becomes the FP characterization, executable.

---

## Rule inventory

| SID | Layer | Detects | Tier |
|---|---|---|---|
| 100001 | DNS | `soulversr.com` (initial access) | high-confidence |
| 100002 | DNS | `sbwur1.top` (payload delivery) | high-confidence |
| 100003 | DNS | `4ec74y9kph5vko2.top` (C2 — DGA primary) | high-confidence |
| 100004 | DNS | `0auuj2cvzpntnfb.top` (C2 — DGA fallback) | high-confidence |
| 100005 | DNS | `gecdfcjcbcmmakk.top` (payload delivery) | high-confidence |
| 100006 | TLS | SNI `soulversr.com` (initial access) | high-confidence |
| 100007 | TLS | JA3 `07af4aa9…fbe3` (C2 — DGA primary, :25658) | high-confidence* |
| 100008 | TCP | to `173.232.146.62:25658` (C2 — DGA primary) | high-confidence |
| 100009 | HTTP | host `85.137.253.64` (loader/stager, :3456) | high-confidence |
| 100010 | HTTP | host `sbwur1.top` (payload delivery) | high-confidence |
| 100011 | HTTP | UA `WindowsPowerShell` (loader/stager) | triage |
| 100012 | HTTP | `Server: Werkzeug` (loader/stager) | triage |
| 100013 | HTTP | Content-Disposition + script ext (loader/stager) | triage |
| 100014 | HTTP | `POST` `/m` + `message=` (AV enumeration) | triage |
| 100015 | HTTP | `DllImport` + `windowstyle hidden` (payload delivery) | triage |
| 100016 | TCP | FINGER / port 79 (covert callback) | high-confidence |

\* JA3 is environment-dependent — see the 100007 note below.

---

## Validation — known-bad (16/16, fire-verified)

Two rules were silent on the first run and required root-cause analysis. Both turned out to
be stable engine behaviors — not version regressions — confirmed empirically against a live
Suricata engine.

**100009 — `http.host` strips the port.** The engine parses the Host header into separate
fields (`"hostname":"85.137.253.64","http_port":3456`). A content match of `…64:3456` against
`http.host` can never match. **Fix:** drop the port from the content match (port documented in
`msg`); rev:2.

**100013 — header-rule direction.** Content-Disposition is a *response* header, but the rule
was pointed `$HOME_NET → $EXTERNAL_NET` (the request side), where it never appears. `http.header`
exposes request vs response headers according to the rule's address direction. **Fix:** flip to
`$EXTERNAL_NET → $HOME_NET`, matching the working 100012/100015; rev:2.

**Why they were silent despite being "validated" in March.** A `git diff` showed the rule text
was byte-identical between the autopsy repo and the port — no drift. The fixes had been
*diagnosed* in March but not fully landed: 100009's corrected rule never reached the file, and
100013 carried a second bug (wrong direction) masked behind a pcre syntax error that *was*
fixed. Clearing the parse error made it load; "loads" was mistaken for "fires."

> **Principle.** *Validated* is not a property of a rule. It is a property of the tuple
> **(rule × engine × config × fixture)** at a point in time. Inspecting a rule and believing
> it correct is **inspection**, not validation — only machine firing against a fixture
> validates. This is the reason the operation is in CI.

---

## Validation — known-good (silent) and false-positive characterization

`benign-clean.pcap` fires nothing — all 16 silent on ordinary benign traffic.

Against technique-twins (`cousins.pcap`), **five behavioral rules fire by design:**

| SID | Benign cousin that triggers it |
|---|---|
| 100011 | Legitimate PowerShell `Invoke-WebRequest` |
| 100012 | Any external Flask / Werkzeug service |
| 100013 | Legitimate `.ps1` / `.psm1` download |
| 100014 | Messaging API whose endpoint ends in `/m` |
| 100015 | Page serving example / tutorial code |

Pattern: every false positive is a single behavioral condition; every silent rule is a literal
IOC, a fingerprint, or a multi-condition match. A lone behavioral predicate matches a
*technique*, which benign software shares. These do **not** fire on ordinary benign traffic —
only on technique-twins.

**100007 (JA3) — corrected.** Measured against real benign clients: curl/OpenSSL fingerprints
as `0149f47e…`, Python urllib/requests as `46531b76…` — neither collides with the rule's
`07af4aa9…`. The rule matches a *specific* TLS stack, not "Python at large" as first noted, so
it is narrower and less FP-prone than documented. Caveat: JA3 is library/OS-version dependent;
this is a single-environment sample, and JA3 silence is not pinned in CI.

---

## Rule classification

- **High-confidence** (alert / candidate to block): IOC literals, fingerprints, multi-condition
  matches, and the FINGER behavioral rule (near-zero benign base rate). Silent on benign traffic.
- **Triage / hunt** (alert, do not block): 100011–100015. Single behavioral predicates shared
  with legitimate software; broad by design, with a measured FP surface. Where higher confidence
  is wanted, the path is correlation (`flowbits` chaining the campaign) rather than tighter
  single matches.

---

## Running the validation

```bash
python3 suricata/harness/run_tests.py
```

The harness lints each ruleset (`suricata -T`), then replays each fixture and compares fired
SIDs to `expected.yaml` (`must_fire` and `must_not_fire`, evaluated independently per fixture).

---

## Lessons

1. `http.host` strips the port — the port lives in `http_port`. Never match a port in `http.host`.
2. Header-rule direction follows the technique: response headers `EXTERNAL → HOME`, request headers `HOME → EXTERNAL`.
3. "Loads" ≠ "fires." A cleared parse error is not a validated rule.
4. Inspection is not validation — only machine firing against a fixture is.
5. A known-good cannot be a slice of the malware capture; it must be independent benign traffic.
6. Single behavioral conditions are inherently FP-prone — precision comes from correlation or multi-condition matches.
7. Document false positives as a measured, pinned property, not a defect to hide.

---

## Open thread

`git log -p` on the autopsy repo for SID 100009 / 100013 — determine whether each was an
un-applied fix or a masked second bug. The answer indicates which step in the authoring process
to harden.

---
*Operation PA-03 — PCAP Autopsy / The Forge — cyberlandji*
