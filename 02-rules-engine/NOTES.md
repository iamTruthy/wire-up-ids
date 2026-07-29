# Stage 02 — The Rule-Based Detection Engine

## What this is

A transparent detection layer that consumes the parsed packet stream from
Stage 01 and flags suspicious behaviour that no single packet reveals. It
imports the Stage 01 parsers directly, so there is one source of truth for
how the wire is decoded. Three detectors run on every TCP packet, each
maintaining its own small amount of per-source state. This is the low rung
of detection. Its virtue is that every alert traces to exactly one rule and
one condition, with no opacity.

## The three rules

See ruleset.md for the full signal, threshold, and false-positive writeup.
In short:

Port scan. One source sending bare SYNs to 20 or more distinct destination
ports inside a 10-second sliding window. A sliding window per source holds
recent (timestamp, port) pairs, old entries are expired off the left, and
the distinct-port count is the size of the set of ports remaining.

SYN flood. 100 or more bare SYNs from one source in a 5-second window where
SYN count exceeds completing-ACK count. The ratio is the fingerprint, since
a real handshake completes with an ACK and a flood does not.

NULL and Xmas scans. Any single packet with no flags set (NULL) or with
exactly FIN, PSH, and URG set (Xmas). These flag combinations do not occur
in legitimate traffic, so one packet is enough to alert.

## Three things testing revealed

The rules were written from the diagrams and then tested against real
attack traffic generated with nmap and hping3 against this machine only.
Three genuine detection-engineering problems surfaced, and fixing them is
most of what this stage taught.

### Alert fatigue

The first version of the NULL and Xmas detectors fired once per packet. A
single nmap NULL scan produced dozens of identical alerts. That is how real
operators get buried and miss the alert that matters. The fix is
deduplication: each detector remembers which sources it has already alerted
for a given event and stays silent afterward, so one scan is one alert.

### A rule that fired on its own victim's replies

Flooding a single port with hping3 tripped the port-scan rule, which made no
sense at first since every packet targeted one port. The cause was that
hping3 randomises its source port per packet, the target answers each SYN to
the closed port with a RST back to those random ports, and on a link that
carries both directions the engine saw those RSTs as traffic to many
distinct destination ports. The naive rule counted every packet's
destination port regardless of direction or TCP state, so the victim's own
replies looked like a scan. The fix was to count only bare-SYN packets
toward the port total. Scan probes are SYNs, responses are not. This is a
concrete example of why per-packet rules are fragile and it is part of the
motivation for the flow-based ML detector in Stage 03.

### A detector that silently lost its alerts

When run under a timeout for automated testing, the engine produced an empty
log even though it had run. Python buffers stdout when writing to a file, and
the process was killed by SIGTERM before the buffer flushed, so any alerts
were lost. A detection tool must never hold an alert in a buffer. The fix was
to flush on every alert and to handle SIGTERM so shutdown is clean. An alert
that does not leave the process is not an alert.

## Verification

True positives, on loopback against 127.0.0.1: port scan, SYN flood, NULL
scan, and Xmas scan each produced exactly one alert. Records in
verification/positive-tests.txt and
verification/synflood-and-portscan-interaction.txt.

True negative, on the real interface during 45 seconds of ordinary
browsing, DNS, and ping: zero alerts. Record in
verification/negative-test.txt.

The engine fires on the behaviours each rule targets and stays silent on
legitimate traffic. That discrimination is the whole point.

## What i learnt

The finding that taught me the most was the port-scan rule firing on a flood I aimed at a single port. I expected the distinct-port count to stay at one, and when the alert fired anyway I had to actually trace where those ports were coming from, and it turned out to be the victim's own RST replies on a link that carries both directions.
A signature rule does not understand a connection, it only sees packets, and it will happily count the defender's responses as if they were the attacker's probes. 
Tightening it to count only bare SYNs fixed this case, but the deeper lesson is that per-packet heuristics have no concept of direction or state, and that is exactly the gap a flow-based detector is meant to close. The alert-buffering bug showed that an alert which never leaves the process is not an alert at all.
