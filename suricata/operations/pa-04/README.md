# PA-04 — NetSupport Manager RAT — Detection Findings & Validation Notes

Operation PA-04 of the PCAP Autopsy series, and the **final** operation of the
series, ported into The Forge as a Detection-as-Code pipeline. It targets
**NetSupport Manager** — a legitimate commercial remote-administration product
weaponised as a RAT. That dual-use nature is the defining problem of this
operation: the tool-family signatures fire on *any* NetSupport deployment,
sanctioned or hostile, so the detection value concentrates at the two ends of the
ruleset — brittle campaign IOCs above, durable behavioural anomalies below.

The headline behaviour is a protocol/port anomaly: the C2 speaks **plaintext HTTP
over port 443** — cleartext where TLS is expected — to ride the "looks like HTTPS"
egress allowance. The evasion choice is itself the signal.

**Rule count: 7 rules** across DNS, IP, and HTTP, organised in three tiers.
**Fixtures:** one known-bad capture (`easyas123-1`), one known-good capture
(`easyas123-kg`, crafted).
**Status:** validated green on both axes — all seven fire on the known-bad, all
seven stay silent on the known-good FP-guard.

---

## Fixture set — two classes

| Class | Fixture | Purpose |
|---|---|---|
| known-bad | `fixtures/known-bad/easyas123-1.pcap` | NetSupport C2 session — all 7 rules fire |
| known-good | `fixtures/known-good/easyas123-kg.pcap` | Crafted benign traffic — nothing may fire |

Per-fixture SID assertions live in `expected.yaml` (the source of truth — not
duplicated here so the two cannot drift).

**Why the known-good is crafted, not trimmed — and doubly so.** Like PA-03, the
malware capture is malicious end to end, so there is no benign window to slice.
PA-04 adds a second, stronger reason: **NetSupport Manager is dual-use.** Even a
*legitimate* NetSupport session carries the `NetSupport Manager` client UA and the
`NetSupport Gateway` server banner, so it would trip rules 1000004/1000005 by
design. A benign baseline carved from any NetSupport traffic — malicious or not —
cannot be silent. The known-good must therefore be independent benign traffic that
contains no NetSupport at all. `easyas123-kg.pcap` is a synthetic, deterministic
capture built for CI; it may be swapped for a trimmed real benign capture later
without changing the manifest.

---

## Rule inventory

| SID | rev | Layer | Detects | Tier |
|---|---|---|---|---|
| 1000001 | 1 | DNS | query for `vadusa[.]xyz` (C2 domain) | IOC |
| 1000002 | 1 | IP | traffic to C2 IP `45[.]131[.]214[.]85` | IOC |
| 1000003 | 1 | HTTP | `POST` to `/fakeurl.htm` (C2 check-in URI) | IOC |
| 1000004 | 1 | HTTP | client UA `NetSupport Manager` (request) | signature — tool family |
| 1000005 | 1 | HTTP | server banner `NetSupport Gateway` (response) | signature — tool family |
| 1000006 | 1 | HTTP | `CMD=POLL` / `CMD=ENCD` command protocol in POST body | behavioural |
| 1000007 | 1 | HTTP | plaintext HTTP on port `443` (protocol/port anomaly) | behavioural |

### Tiering against the Pyramid of Pain

- **Tier 1 — IOC (brittle).** 1000001–1000003 pin to this campaign's domain, IP,
  and check-in URI. High confidence, low cost to the adversary to change — they
  rotate. Bottom of the pyramid.
- **Tier 2 — signature, tool family (dual-use).** 1000004/1000005 identify
  *NetSupport itself*, not the threat actor. They fire on every NetSupport flow,
  legitimate or hostile. In a real environment these are **triage/hunt-tier**, not
  block-tier: they would alert on any sanctioned NetSupport deployment. Their job
  is to surface the tool's presence for an analyst to adjudicate against an
  allowlist of approved RMM.
- **Tier 3 — behavioural (durable).** 1000006/1000007 key on *how this C2 operates*
  — the shape of its command protocol and its choice to run cleartext on the TLS
  port. These survive infrastructure rotation and cost the adversary real
  re-engineering to defeat. Top of the useful range.

---

## Validation — known-bad (7/7, fire-verified)

All seven rules fire on `easyas123-1.pcap`. Unlike PA-02 (ECH-hidden SNI, stale
JA3) and PA-03 (two engine-behaviour bugs), PA-04's rules validated without a
silent-rule investigation — the port-anomaly rule, the one most likely to be
mis-specified, was confirmed correct (see below) rather than merely assumed.

> **Principle (carried from PA-03).** *Validated* is not a property of a rule. It is
> a property of the tuple **(rule × engine × config × fixture × harness ×
> environment)** at a point in time. Inspecting a rule and believing it correct is
> inspection, not validation — only machine firing against a fixture validates.
> That is why this operation lives in CI.

---

## Validation — known-good (silent) and the 1000007 FP-challenge

`easyas123-kg.pcap` fires nothing — all seven silent on benign traffic. The
fixture is built so each rule's silence is *earned*, not silence-by-absence: it
carries a benign DNS lookup (vs. 1000001), a benign HTTP POST with a benign URI,
client UA, body, and server banner (vs. 1000003–1000006), and traffic only to
benign IPs (vs. 1000002).

**The deliberate challenge — 1000007 against real HTTPS.** Rule 1000007 is
`alert http $HOME_NET any -> $EXTERNAL_NET 443`. The `443` is only the
destination-port filter; the `http` token anchors the rule to Suricata's HTTP
**app-layer**, which is decided by **payload inspection, not the port number**. The
known-good therefore includes a genuine TLS handshake (ClientHello / ServerHello)
on port 443. The test:

| Flow on :443 | `app_proto` | 1000007 |
|---|---|---|
| known-bad — plaintext HTTP request | `http` | **fires** (the anomaly) |
| known-good — real ClientHello/ServerHello | `tls` | **silent** (correct) |

A legitimate HTTPS connection parses as `app_proto: tls`, so the `http` rule is
never evaluated against it. **If 1000007 fired on real TLS, the rule would be
broken** — it would be matching on the port alone and would false-positive on every
HTTPS connection on the network. The silence on TLS is the proof of soundness, and
it is verified by machine, not asserted.

**Taxonomy note.** Real HTTPS belongs in the **known-good** — it is ordinary benign
traffic that fires nothing; it is not a "cousin." The true benign-adversarial
cousin for 1000007 would be a *legitimate* service that happens to run plaintext
HTTP on 443 (some internal/legacy services do). That would fire 1000007 **by
design**, the same way PA-03's cousins trip its broad behavioural rules — and is a
candidate for a future `benign-adversarial/` fixture, not a defect.

---

## Analysis observation — keepalive beaconing (candidate future rule)

The C2 session exhibits fixed-size keepalive beaconing at a regular interval
(~286-byte packets at ~60 s). No current rule keys on this — the seven rules above
match content and protocol, not volume over time. It is recorded here as an
**analysis observation** and a candidate for a future volumetric/threshold rule in
the style of PA-01's 1000003 (`threshold: both, by_dst, …`), which would add a
durable, content-independent primitive on top of the tool-family signatures. Not a
claim about the present ruleset.

---

## Running the validation

```bash
python3 suricata/harness/run_tests.py
```

The harness lints each ruleset (`suricata -T`), then replays each fixture and
compares fired SIDs to `expected.yaml` (`must_fire` and `must_not_fire`, evaluated
independently per fixture). CI runs the same harness on every push.

---

## Lessons

1. **Dual-use tools split the ruleset.** When the malware *is* a legitimate product,
   tool-family signatures (UA, banner) cannot be block-tier — they fire on
   sanctioned deployments. Value moves to campaign IOCs (brittle) and behavioural
   anomalies (durable); the middle is triage.
2. **A protocol rule anchors on the protocol, not the port.** `alert http … 443`
   fires on HTTP-parsed-on-443, decided by payload inspection — not on every packet
   to 443. Real TLS on 443 stays silent because it parses as `tls`.
3. **An adversary's evasion choice can be the signal.** Running cleartext on the TLS
   port to dodge port-based egress control is exactly what makes the flow anomalous
   and detectable at the app layer.
4. **A dual-use known-good must contain none of the tool.** Even legitimate
   NetSupport trips the tool-family rules, so the benign baseline must be
   independent traffic with no NetSupport present at all.
5. **Earned silence, not silence-by-absence.** Build the FP-guard so each rule is
   actually exercised against confusable-but-benign traffic — including a real TLS
   handshake to challenge the port-anomaly rule — so a green means "did not fire on
   something it saw," not "saw nothing."

---

*Operation PA-04 — PCAP Autopsy / The Forge — cyberlandji*
