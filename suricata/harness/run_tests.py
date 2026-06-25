#!/usr/bin/env python3
"""
The Forge -- Suricata rule validation harness.

For every operation under operations/ that has an expected.yaml, this:
  1. LINT  -- `suricata -T` loads the config + that op's rules, fails on any parse error.
  2. VALIDATE -- runs Suricata offline over each fixture PCAP using ONLY that op's
     rules, then checks the fired SIDs against the manifest.

Exit code 0 = everything matched the manifest. Non-zero = at least one problem.

The CI run and a local run are identical -- run this on your machine before you push
and you'll see exactly what GitHub Actions will see.

    python harness/run_tests.py
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml  # pip install pyyaml

ROOT = Path(__file__).resolve().parent.parent
OPERATIONS_DIR = ROOT / "operations"


def lint(rules, workdir):
    """suricata -T: load config + this rule file, return (ok, output)."""
    result = subprocess.run(
        ["suricata", "-T", "-S", str(rules), "-l", str(workdir)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.returncode == 0, result.stdout


def fired_sids(pcap, rules, workdir):
    """Run Suricata offline over one pcap with one rule file; return the set of alerted SIDs."""
    subprocess.run(
        [
            "suricata",
            "-r", str(pcap),     # offline mode: read this pcap
            "-S", str(rules),    # EXCLUSIVE: use only this rule file, ignore system rules
            "-l", str(workdir),  # write logs (incl. eve.json) here
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    sids = set()
    eve = workdir / "eve.json"
    if not eve.exists():
        return sids
    with eve.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if event.get("event_type") == "alert":
                sids.add(event["alert"]["signature_id"])
    return sids


def check_operation(op_dir):
    """Lint then validate one operation. Returns a list of failure strings (empty = pass)."""
    manifest = yaml.safe_load((op_dir / "expected.yaml").read_text())
    rules = op_dir / manifest["rules"]
    failures = []

    # --- Stage 1: lint ---
    with tempfile.TemporaryDirectory() as tmp:
        ok, output = lint(rules, Path(tmp))
    if not ok:
        failures.append(f"[{op_dir.name}] rules failed to parse (suricata -T):\n{output}")
        return failures  # don't try to validate rules that won't even load
    print(f"  LINT  OK  [{op_dir.name}] {manifest['rules']}")

    # --- Stage 2: validate against fixtures ---
    for case in manifest.get("fixtures", []):
        pcap = op_dir / case["pcap"]
        must_fire = set(case.get("must_fire", []))
        must_not_fire = set(case.get("must_not_fire", []))

        with tempfile.TemporaryDirectory() as tmp:
            seen = fired_sids(pcap, rules, Path(tmp))

        missing = must_fire - seen       # should have fired, didn't
        wrongly = must_not_fire & seen   # fired, but should not have

        if missing:
            failures.append(
                f"[{op_dir.name}] {case['pcap']}: expected SIDs {sorted(missing)} did NOT fire"
            )
        if wrongly:
            failures.append(
                f"[{op_dir.name}] {case['pcap']}: SIDs {sorted(wrongly)} fired but should NOT have"
            )
        if not missing and not wrongly:
            print(f"  PASS      [{op_dir.name}] {case['pcap']}")

    return failures


def main():
    op_dirs = sorted(
        d for d in OPERATIONS_DIR.iterdir()
        if d.is_dir() and (d / "expected.yaml").exists()
    )
    if not op_dirs:
        print("No operations with an expected.yaml found -- nothing to test yet.")
        return 0

    all_failures = []
    for op_dir in op_dirs:
        print(f"\n== {op_dir.name} ==")
        all_failures.extend(check_operation(op_dir))

    print("\n" + "=" * 44)
    if all_failures:
        print(f"FAILED -- {len(all_failures)} problem(s):\n")
        for f in all_failures:
            print("  " + f)
        return 1
    print("All operations passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
