#!/usr/bin/env python3
"""The Forge -- Suricata rule validation harness (repo-local config via -c)."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OPERATIONS_DIR = ROOT / "operations"
CONFIG = ROOT / "harness" / "suricata.yaml"


def lint(rules, workdir):
    result = subprocess.run(
        ["suricata", "-T", "-c", str(CONFIG), "-S", str(rules), "-l", str(workdir)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return result.returncode == 0, result.stdout


def fired_sids(pcap, rules, workdir):
    subprocess.run(
        ["suricata", "-r", str(pcap), "-c", str(CONFIG), "-S", str(rules), "-l", str(workdir)],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
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
    manifest = yaml.safe_load((op_dir / "expected.yaml").read_text())
    rules = op_dir / manifest["rules"]
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        ok, output = lint(rules, Path(tmp))
    if not ok:
        failures.append(f"[{op_dir.name}] rules failed to parse (suricata -T):\n{output}")
        return failures
    print(f"  LINT  OK  [{op_dir.name}] {manifest['rules']}")
    for case in manifest.get("fixtures", []):
        pcap = op_dir / case["pcap"]
        must_fire = set(case.get("must_fire", []))
        must_not_fire = set(case.get("must_not_fire", []))
        with tempfile.TemporaryDirectory() as tmp:
            seen = fired_sids(pcap, rules, Path(tmp))
        missing = must_fire - seen
        wrongly = must_not_fire & seen
        if missing:
            failures.append(f"[{op_dir.name}] {case['pcap']}: expected SIDs {sorted(missing)} did NOT fire")
        if wrongly:
            failures.append(f"[{op_dir.name}] {case['pcap']}: SIDs {sorted(wrongly)} fired but should NOT have")
        if not missing and not wrongly:
            print(f"  PASS      [{op_dir.name}] {case['pcap']}")
    return failures


def main():
    op_dirs = sorted(d for d in OPERATIONS_DIR.iterdir() if d.is_dir() and (d / "expected.yaml").exists())
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
