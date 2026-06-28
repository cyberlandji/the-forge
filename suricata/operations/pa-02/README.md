# PA-02 — Lumma Stealer — Detection Findings & Validation Notes

Operation PA-02 of the PCAP Autopsy series, ported into The Forge
detection-as-code pipeline. This document records the detection findings, two
rules that required debugging, one rule retired as a documented dead-end, and the
reasoning behind the false-positive guard.

**Rule count: 12 live rules** (one retired — see §1).
**Fixtures:** two known-bad captures (`lummah-1`, `lummah-2`), one known-good
capture (`lummah-kg`).

---

## Summary of the 12 live rules

| SID | Layer | Detects |
|---|---|---|
| 100001 | DNS | query to `hiyter[.]com` (initial beacon) |
| 100002 | DNS | query to `archfilemegahab4[.]sbs` (payload delivery) |
| 100003 | DNS | query to `media.megafilehub4[.]lat` (payload delivery) |
| 100004 | DNS | query to `whooptm[.]cyou` (staging/config) |
| 100005 | DNS | query to `whitepepper[.]su` (C2/exfiltration) |
| 100007 | TLS | SNI `whooptm[.]cyou` |
| 100008 | TLS | SNI `media.megafilehub4[.]lat` |
| 100009 | TLS | SNI `whitepepper.su` |
| 100010 | TLS | JA3 + SNI correlation to `whitepepper[.]su` (C2 exfil module) |
| 100011 | HTTP | `Host: whitepepper[.]su` (C2 exfiltration) |
| 100012 | HTTP | `POST /api/set_agent` to `whitepepper[.]su` |
| 100013 | HTTP | `POST /api/set_agent` (behavioral — C2 agent registration) |

**Retired:** 100006 (TLS SNI to `hiyter[.]com`) — see §1.

---

## 1. Rule 100006 (retired) — ECH defeats SNI-based detection

**Rule as written:** `alert tls ... tls.sni; content:"hiyter[.]com";`

**Symptom:** did not fire on the known-bad capture, despite `hiyter[.]com` being the
initial-beacon domain and clearly present in the traffic.

**Investigation:** the `hiyter[.]com` connection was followed end to end in the
capture:

| Packet | Event |
|---|---|
| 2373/2374 | DNS query for `hiyter[.]com` |
| 2377 | DNS response → `104[.]21[.]22[.]231` |
| 2378 → 2379 → 2380 | TCP handshake (SYN / SYN-ACK / ACK) to `104[.]21[.]22[.]231` |
| 2382 | **Client Hello — `SNI=cloudflare-ech.com`** |

**Root cause:** the flow uses **Encrypted Client Hello (ECH)**. The real SNI is
encrypted; the plaintext (outer) SNI on the wire is the Cloudflare cover name
`cloudflare-ech.com`, not `hiyter[.]com`. A `tls.sni; content:"hiyter[.]com"` rule is
therefore **structurally incapable** of matching this flow — the string it looks
for is not present in cleartext.

**Resolution:** the rule was removed from the rules file. Detection for
`hiyter[.]com` is correctly retained at the **DNS layer** (rule 100001), where the
real domain is still queried in cleartext.

**Takeaway:** the matchable detection surface for a domain depends on the TLS
privacy mechanism in use. Under ECH, SNI-based TLS detection is blind; detection
must fall back to the DNS layer (cleartext query) or to JA3 (the outer Client
Hello — and therefore the JA3 fingerprint — remains visible under ECH). Keeping a
rule that can never fire on its target in the live rules file would give false
assurance of TLS coverage; the reasoning is preserved here instead.

---

## 2. Rule 100010 — JA3+SNI correlation; failure was a stale rule literal

**Rule as written:**
`tls.sni; content:"whitepepper[.]su"; nocase; ja3.hash; content:"<JA3>";` —
requires **both** SNI and JA3 to match in a single signature.

**Symptom:** did not fire on the known-bad capture.

**Investigation:**

- `whitepepper[.]su`'s TLS flow is **not** ECH — packet 23728 shows
  `Client Hello (SNI=whitepepper[.]su)` in cleartext, so the SNI half of the rule
  matches.
- The JA3 computed for every Client Hello to `whitepepper[.]su` was
  **`2800f914a7a4ba98aa9df62d316a460c`**, consistent across all handshakes to that
  host.
- The rules file carried a **different, stale JA3 literal**
  (`966876ab31aa46bd3378db27b35b8d56`) from an earlier draft.

**Root cause:** because the rule requires SNI **AND** JA3, the wrong JA3 literal
sank the match even though the SNI matched correctly. A wrong-but-well-formed JA3
hash produces no parse error and fires nothing — indistinguishable from "traffic
absent" without inspecting `eve.json` / the capture.

**Resolution:** replace the JA3 literal with the value observed in the capture
(`2800f914a7a4ba98aa9df62d316a460c`). SNI half was already correct.

**Takeaways:**
- **Source the JA3 from the capture** (`eve.json` or Wireshark's JA3 field), never
  from memory or an external threat-intel post — an externally-sourced hash can be
  correct-looking yet not match what this client negotiated.
- **JA3 is stable per client.** The same client software produces the same JA3 on
  every connection — confirmed here: all handshakes to `whitepepper[.]su` carried the
  identical hash. JA3 does *not* vary per handshake. (If different JA3s appear for
  the same destination, that indicates *different client software*, not
  non-determinism.)
- A stale, well-formed literal is an invisible failure class — it looks identical
  to "no traffic." Guard against it by verifying values against ground truth before
  trusting the rule.

---

## 3. Rule 100013 — behavioral detection; the UA is camouflage, not the signal

**Rule as written:** `http.method; content:"POST"; http.uri; content:"/api/set_agent"; http.user_agent; content:"Chrome/144";`

**Behaviour:** fires correctly on the known-bad C2 registration POSTs.

### 3.1 The Chrome version does not discriminate

The malicious traffic to `whitepepper[.]su` carries a full, realistic UA:
`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36`.

Checking the victim's *real* browser traffic, the legitimate connection to
`clients2.google.com` carries the **same `Chrome/144.0.0.0`**. So the version is
**not** a discriminator — a rule keying on `Chrome/144` alone would also match the
victim's legitimate browsing. The realistic UA is **deliberate camouflage**: the
malware mimics the host's own browser to evade UA-based detection.

**The real discriminator is the behaviour: `POST` to `/api/set_agent`** — the C2's
agent-registration endpoint, which has no legitimate equivalent. The `Chrome/144`
content in the rule is a condition the malicious traffic happens to satisfy, not
the distinguishing feature.

### 3.2 Observed anomaly — double registration under two browser identities

The six requests to `whitepepper[.]su` reveal the C2 running its registration
sequence **twice, under two spoofed identities**:

| Frame | Method | URI (`agent=` param) | User-Agent |
|---|---|---|---|
| 24500 | GET | `/api/set_agent?...&agent=Chrome` | Chrome/144 |
| 24601 | POST | `/api/set_agent?...&agent=Chrome&act=log` | Chrome/144 |
| 24614 | GET | `/favicon.ico` | Chrome/144 |
| 25270 | GET | `/api/set_agent?...&agent=Edge` | Chrome/144 … **Edg/144** |
| 25286 | POST | `/api/set_agent?...&agent=Edge&act=log` | Chrome/144 … **Edg/144** |
| 25298 | GET | `/favicon.ico` | Chrome/144 … **Edg/144** |

The spoofed identity is reflected in **both** the UA header *and* the `agent=` URL
parameter (`agent=Chrome` ↔ plain Chrome UA; `agent=Edge` ↔ `Edg/144` UA). A single
host presenting two distinct browser identities to the same C2 endpoint in one
session is not browser behaviour.

**Scope note:** rule 100013 does **not** detect this inconsistency — it matches both
POSTs purely on method + URI regardless of the UA token. The double-registration is
an **analysis observation** and a **candidate for a future correlation rule** (same
source, same C2 endpoint, conflicting claimed browser identities), not a claim about
the current rule.

**Stronger primitive:** the `/api/set_agent?...&agent=&act=log` URI structure is
attacker-infrastructure-side (the C2's own API design) and harder to vary without
breaking the C2 protocol. It is a stronger detection primitive than any UA-based
match — consistent with the general principle that structural/behavioural features
outperform easily-spoofed headers.

---

## 4. False-positive guard (known-good fixture)

**Fixture:** `lummah-kg.pcap` — a benign slice trimmed from the same source capture.

**Composition (verified):**
- **Benign TLS SNIs:** `drive.google.com`, `login.live.com`, `edge.microsoft.com`,
  `www.bing.com`, `www.gstatic.com`, `assets.msn.com`, `config.edge.skype.com`,
  `odc.officeapps.live.com`, `watson.events.data.microsoft.com`, and others.
- **Benign cleartext HTTP:** `msftconnecttest.com GET /connecttest.txt`, SSDP
  M-SEARCH.
- **IOC check:** grep for all six Lumma domains returned **empty** — no malicious
  indicators leaked into the benign slice.

This fixture validates the `must_not_fire` (restraint) axis for **11 of the 12
rules** against confusable benign traffic: the DNS rules vs. benign DNS, the
TLS-SNI rules vs. benign HTTPS to Microsoft/Google infrastructure, and HTTP rules
100011/100012 vs. benign cleartext HTTP.

### 4.1 Limitation — rule 100013 cannot be FP-tested against benign Chrome/144

All `Chrome/144` traffic in the source capture **coexists with C2 activity** — there
is no benign-only window that contains it. A second known-good PCAP would not solve
this: it would be trimmed from the same source and face the identical scarcity. The
required traffic does not exist in benign form anywhere in this capture.

This is treated as a **documented limitation, not a hidden gap**, for the following
reason: 100013's discriminator is `POST /api/set_agent` — an endpoint with **no
legitimate equivalent**. A benign false positive would require benign traffic that
POSTs to `/api/set_agent`, which does not occur in normal browsing. The realistic
false-positive surface for this rule is therefore effectively empty, and the rule's
**specificity is its own guard**. 100013 passes on `lummah-kg` because the slice
correctly contains no POST to `/api/set_agent` — a real (if narrow) confirmation
that it does not fire on normal browsing, NCSI, SSDP, or benign TLS.

Manufacturing a synthetic benign `Chrome/144` POST purely to give 100013 something
to not-fire on would test against traffic that does not reflect reality. An honest,
reasoned limitation is preferred over a hollow green.

---

## 5. Cross-cutting lessons

1. **The detection surface depends on the transport's privacy mechanism.** ECH moves
   detection off TLS-SNI (100006 → DNS layer); plaintext SNI keeps it (100009).
2. **JA3 is stable per client and independent of SNI.** Failures that look like
   "JA3 varies" are either different client software or unsourced/stale literals.
3. **Easily-spoofed fields (UA) are camouflage; structural behaviour (C2 endpoint,
   URI parameters) is signal.** 100013's strength is `POST /api/set_agent`, not
   `Chrome/144`.
4. **Fixture-based validation has limits.** When confusable benign traffic does not
   exist, document the limitation and the reason the rule's specificity covers it —
   rather than fabricating coverage.
5. **Invisible failure classes** (stale JA3 literal, ECH-hidden SNI, manifest/rule
   SID mismatch) all look like "no traffic." Verify values against the capture
   before trusting a rule.

---

*Operation PA-02 — PCAP Autopsy / The Forge — cyberlandji*
