# Stage 02 - Ruleset

Three detection rules operate on the parsed packet stream from Stage 01.
Each rule names the signal it keys on, the threshold that triggers it, and
its likely false-positive mode. The rules are deliberately simple and
transparent. Any alert can be traced to exactly one rule and one condition.

## Rule 1 - Port scan

Signal: one source IP contacts many distinct destination ports in a short
window. A normal client opens a few ports to a host. A scanner sweeps many.

Threshold: 20 or more distinct destination ports from one source IP within
a 10-second sliding window. The 20-port figure follows common IDS defaults.
The window is kept short because a fast scanner trips it quickly and a short
window holds less state.

False positive mode: peer-to-peer clients, connection pooling, or a browser
opening many parallel CDN connections can hit many ports fast. On a busy
production network this threshold would need tuning. On a controlled test
host it is clean.

## Rule 2 - SYN flood

Signal: a burst of SYN packets from one source without the completing ACK of
the handshake. Normal handshakes complete SYN, SYN+ACK, ACK. A flood sends
SYN after SYN and never completes, leaving half-open connections.

Threshold: 100 or more SYN packets from one source IP within a 5-second
window, where SYN count greatly exceeds the completing ACK count from that
source. The ratio of SYN to ACK is the real fingerprint, not the raw count.

False positive mode: a client on a lossy link retransmits SYNs and can look
flood-like at low volume. The high threshold keeps ordinary retransmission
from tripping the rule.

## Rule 3 - Known-bad flag pattern (NULL and Xmas scans)

Signal: TCP packets with flag combinations that never occur in legitimate
traffic but are used in stealth scans. A NULL scan sets no flags. An Xmas
scan sets FIN, PSH, and URG together. Both exploit an RFC 793 loophole to
probe ports while evading simple filters.

Threshold: any single packet with no flags set, or with exactly FIN, PSH,
and URG set. No window is needed because these packets should not appear in
normal traffic at all. One is enough to alert.

False positive mode: very rare. A broken or exotic stack might emit unusual
flags. On this host such a packet almost certainly indicates a scan.
