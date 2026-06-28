# PA-01 — STRRAT — Detection Notes

Operation PA-01 of the PCAP Autopsy series, and the **foundational operation** of
The Forge detection-as-code pipeline — the first operation built into the harness.
It targets **STRRAT**, a Java-based remote access trojan with information-stealing,
keylogging, and remote-control capabilities.

**Rule count: 3 behavioral rules.**
**Fixtures:** one known-bad capture (`straat-c2.pcap`), one known-good capture
(`pa-01-known-good.pcap`).
**Status:** validated green on both axes — all three rules fire on the known-bad
capture and stay silent on the known-good FP-guard.

---

## Detection approach

PA-01's rules are **behavioral** rather than indicator-of-compromise based. Rather
than pinning to a specific domain or hash (which rotate), each rule keys on a
characteristic of STRRAT's C2 behaviour — the port it calls out on, the recon
service it abuses, and the shape of its beacon traffic. This makes the rules
resilient to infrastructure changes.

| SID | rev | Layer | Detects |
|---|---|---|---|
| 1000001 | 2 | TCP | Outbound established connection to port `12132` — STRRAT's C2 channel on a non-standard high port. Rate-limited (`threshold: limit, by_src, count 1 / 300s`) to alert once per source per window. |
| 1000002 | 1 | HTTP | GeoIP recon — request to `ip-api[.]com` with URI `/json`. A victim-geolocation lookup; a legitimate service abused for post-infection reconnaissance. Matches both the host and the `/json` endpoint. |
| 1000003 | 2 | TCP | Sustained small-packet C2 (`dsize < 200`) on **non-standard ports** — explicitly excludes `80, 443, 53, 8080` (`![80,443,53,8080]`), isolating beacon/keepalive traffic from normal web and DNS. Fires on volume: `threshold: both, by_dst, count 20 / 60s` (20+ small packets to one destination in a minute). |

> **SID scheme:** PA-01 uses the 7-digit `1000001` series. Later operations such as
> PA-02 use a 6-digit `100001` series — the schemes are independent per operation.
>
> Rules 1000001 and 1000003 are at `rev:2` (revised once during tuning); 1000002 is
> at `rev:1`.

---

## Why this operation has no rule-level "findings" section

Unlike PA-02 (which required debugging ECH-hidden SNI and a stale JA3 literal),
PA-01's three detection rules validated correctly against the capture. The
debugging effort during this operation was in the **harness and CI machinery
itself** — PA-01 was the first operation built into The Forge, so the pipeline
plumbing (repo-local Suricata config, the lint/validate stages, the CI workflow)
was being constructed and debugged in parallel. Those lessons belong to The Forge's
setup story, not to PA-01's detection logic. The rules themselves were sound.

---

## Note on behavioral rules and fixture trimming

Because these rules are behavioral, the known-bad fixture must preserve **enough of
the flow for the behaviour to manifest**:

- Rule 1000003 fires on *volume over time* (20 packets in 60s) — a fixture trimmed
  too tightly would not contain enough beacon packets to cross the threshold.
- Rule 1000001 requires an *established* connection (`flow:established,to_server`) —
  the handshake must be intact in the slice.

This is the PA-01 lesson: behavioral rules depend on flow context, so trim to keep
the behaviour observable, not just a single triggering packet.

---

## Fixtures

- **Known-bad — `straat-c2.pcap`:** a packet slice containing STRRAT C2 traffic,
  carved from a larger capture (range-select export of the relevant flows). All
  three rules fire on this fixture.
- **Known-good — `pa-01-known-good.pcap`:** benign traffic used as the
  false-positive guard. All three rules stay silent (`must_not_fire`), confirming
  they do not trip on normal traffic.

The known-bad fixture contains real malicious traffic samples (sourced from a
public malware-traffic capture). It is an inert packet capture, retained
deliberately as the detection fixture.

---

## Validation

Both axes pass under The Forge harness:

- **`must_fire`** (detection): SIDs 1000001, 1000002, 1000003 all fire on
  `straat-c2.pcap`.
- **`must_not_fire`** (restraint): none of the three fire on
  `pa-01-known-good.pcap`.

Run via `python3 suricata/harness/run_tests.py` from the repo root; CI runs the
same harness on every push.

---

*Operation PA-01 — PCAP Autopsy / The Forge — cyberlandji*
