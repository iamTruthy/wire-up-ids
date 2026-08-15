# wire-up-ids

A network intrusion-detection engine built from raw packet parsing up. It goes
from a hand-rolled packet parser, to a rule-based detector, to a machine-learning
detector benchmarked on a public dataset, and finally to an adversarial-evasion
and hardening study against my own detector. Everything runs on my own machine
and my own traffic, and the parser was written from scratch to understand network
analysis from the wire up rather than to wrap a library.

## The claim

I built each layer of a detection stack myself and tested every layer against
traffic I generated, so that each claim in this repository is checkable. The
parser is verified against tshark on the same packets. The rules are verified to
fire on real attacks and stay silent on real benign traffic. The ML detector is
benchmarked honestly, including a cross-day test that shows where it fails. The
evasion study measures how fragile the detector is and whether hardening helps.
The signal I care about is understanding, from the packet bytes up through
adversarial robustness, not a turnkey tool.

## Scope and posture

Everything here is self-contained and defensive. Traffic was captured on my own
machine, attacks were generated against my own listening services and my own
loopback, and the ML stage trained on a public labelled dataset. The evasion
stage attacks my own model in its own feature space. Nothing in this project
targets any system I do not own.

## Reproducibility

Environment: Ubuntu 24.04, Python 3.12, an isolated virtual environment.

Capture privilege was granted the reversible way, as a file capability on a
project-local Python interpreter rather than as root or a group change, and
revoked at the end. The exact grant, verification, and revoke commands are in
00-environment/interface-and-perms.txt. The machine ends this project in the
same state it started.

    # grant (only needed to run the live capture stages)
    sudo setcap cap_net_raw+ep .venv/bin/python3
    # revoke (restores baseline)
    sudo setcap -r .venv/bin/python3

Dataset: CIC-IDS2017 MachineLearningCSV. The original hosts now return an HTML
stub, so the data is fetched from a Kaggle mirror. Full instructions are in
datasets/README.md. The data is gitignored and not committed.

Running each stage:

    # Stage 01, live parser (needs the capability granted)
    .venv/bin/python3 01-parser/sniffer.py

    # Stage 02, rule engine (pass an interface, e.g. lo or wlp0s20f3)
    .venv/bin/python3 02-rules-engine/rules.py lo

    # Stage 03, train and benchmark the ML detector
    .venv/bin/python3 03-ml-detector/train.py
    .venv/bin/python3 03-ml-detector/benchmark.py

    # Stage 04, evasion and hardening
    .venv/bin/python3 04-evasion-and-hardening/generate_traffic.py
    .venv/bin/python3 04-evasion-and-hardening/evade.py
    .venv/bin/python3 04-evasion-and-hardening/harden.py

## The four stages

### Stage 01, the parser

A raw-socket sniffer that parses Ethernet, IPv4, and TCP/UDP headers by hand
with no packet-parsing library. It reads whole link-layer frames and walks each
one field by field from known byte offsets. Key design points are handling the
IPv4 IHL and TCP data-offset nibbles to find where each header actually ends,
decoding the TCP flags byte bit by bit, accounting for network byte order, and
dropping truncated frames rather than crashing on them. Verified against tshark
on the same live connection, where every TCP flag combination matched. Details
in 01-parser/NOTES.md.

### Stage 02, the rule engine

A transparent detection layer on the parsed stream, with three rules: a port
scan seen as many distinct destination ports from one source, a SYN flood seen
as many half-open SYNs without completing ACKs, and NULL/Xmas scans seen as
illegal TCP flag combinations. Testing against real nmap and hping3 traffic
surfaced three genuine detection-engineering bugs: alert fatigue from firing
once per packet, a port-scan rule that counted the victim's own replies as scan
probes, and lost alerts from stdout buffering on shutdown. Each is documented
with its fix. Verified to fire on real attacks and stay silent through 45
seconds of ordinary browsing. Details in 02-rules-engine/NOTES.md and ruleset.md.

### Stage 03, the ML detector

A Random Forest trained on flow features from CIC-IDS2017, framed as a binary
BENIGN-versus-ATTACK problem. The pipeline cleans the dataset's real quirks,
whitespace in every column name, infinities and NaNs from division by zero, a
duplicate column, and splits before fitting to avoid leakage. On a standard
same-distribution split it scores 0.9976 F1. That number is misleading, and the
benchmark says so. Details in 03-ml-detector/NOTES.md and benchmark.md.

### Stage 04, evasion and hardening

An adversarial study of the Stage 03 model in its own feature space. Realistic
packet padding, pushing packet-size features toward benign-typical values, hides
about 93 percent of detected port scans with only five or six changed features.
Adversarial training on padded samples closes that evasion completely, from
0.4345 to 0.0000, with no loss of normal detection. An adaptive attacker using
timing instead of size still finds some headroom. Details in
04-evasion-and-hardening/NOTES.md and harden.md.

## The honest results

The ML detector scores 0.9976 F1 on a same-distribution split. Trained on
Monday through Thursday and tested on an unseen Friday, recall collapses from
0.9985 to 0.0843. It misses almost every port scan and every botnet flow on the
unseen day. The near-perfect number was largely an artifact of train and test
coming from the same captures, and Destination Port being the single most
important feature was the warning sign that the model had memorized this
dataset rather than learned generalizable attack behavior.

The evasion study confirms the fragility from the other side. Padding packet
sizes toward benign values hides about 93 percent of port scans. Adversarial
training drops that specific evasion to zero without harming normal detection or
benign specificity, but a timing-based attack the model was not trained against
still evades it partially, at 8.7 percent and rising. Robustness here is an arms
race in which hardening raises the cost of evasion rather than ending it.

## Limitations

This is a study engine, not a production IDS. The rules are simple heuristics
with real false-positive modes. The ML detector is trained on a single,
known-flawed dataset and evaluated mostly on a same-distribution split, which
overstates real-world performance, as the cross-day test shows. The evasion
study works in feature space, and some perturbed features cannot be set fully
independently in real traffic, so the evasion rate is an upper estimate. The
numbers are what they are, and where they are unflattering the writeup keeps
them.

## What I take from it

Rules broke on crafted packets, the model broke on a change of day,
and again on packets padded toward benign sizes. A detector is
only as trustworthy as the attacks that have actually been run against it, and
there is always one more that hasn't. Building this from the packet bytes up
is what made that visible, because at every layer I could point to exactly
what fired, what missed, and why.
