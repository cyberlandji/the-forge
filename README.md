# The Forge

Detection-as-Code for my validated detection rules. Every push runs the rules
through CI, so a rule that breaks parsing or stops detecting turns the build red
automatically.

Two independent tracks (Sigma and Suricata are complementary, not interchangeable
-- Suricata = network, Sigma = logs):

```
the-forge/
├── .github/workflows/
│   └── suricata.yml     CI for the Suricata track (sigma.yml added later)
├── suricata/            <- active
│   ├── harness/         run_tests.py: lints + validates each operation
│   └── operations/      one folder per PCAP Autopsy op (rules + fixtures + spec)
└── sigma/               <- placeholder, not started
```

## Suricata track -- run locally

On the machine where Suricata + the rules + the PCAPs live (the Kali VM):

```
pip install pyyaml
python suricata/harness/run_tests.py
```

Same command CI runs. Adding an operation = one new `suricata/operations/<op>/`
folder; nothing else changes.
