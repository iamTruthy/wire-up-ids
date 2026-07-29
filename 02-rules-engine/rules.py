import os
import sys
import signal
import socket
import time
from collections import defaultdict, deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "01-parser"))
import sniffer


class PortScanDetector:
    WINDOW = 10
    PORT_THRESHOLD = 20

    def __init__(self):
        # per source IP, a deque of (timestamp, dst_port)
        self.seen = defaultdict(deque)
        self.alerted = set()

    def check(self, ip, tcp, now):
        if tcp["flags"] != "SYN":
            return None
        src = ip["src_ip"]
        dst_port = tcp["dst_port"]

        # 1. Append (now, dst_port)
        self.seen[src].append((now, dst_port))

        # 2. Drop entries older than sliding window
        window_start = now - self.WINDOW
        while self.seen[src] and self.seen[src][0][0] < window_start:
            self.seen[src].popleft()

        # 3. Count distinct destination ports in the window
        distinct_ports = len({p for _, p in self.seen[src]})

        # 4. Alert if threshold exceeded and not previously alerted
        if distinct_ports >= self.PORT_THRESHOLD and src not in self.alerted:
            self.alerted.add(src)
            return f"Port scan detected from {src} ({distinct_ports} distinct ports in {self.WINDOW}s)"

        return None


class SynFloodDetector:
    WINDOW = 5
    SYN_THRESHOLD = 100

    def __init__(self):
        # per source IP, a deque of (timestamp, is_syn_only, is_ack)
        self.events = defaultdict(deque)
        self.alerted = set()

    def check(self, ip, tcp, now):
        src = ip["src_ip"]
        flags = tcp["flags"]

        # 1. Classify packet flags
        syn_only = (flags == "SYN")
        has_ack = "ACK" in flags.split("+")

        # 2. Append event tuple
        self.events[src].append((now, syn_only, has_ack))

        # 3. Drop expired entries
        window_start = now - self.WINDOW
        while self.events[src] and self.events[src][0][0] < window_start:
            self.events[src].popleft()

        # 4. Count SYN-only and ACK occurrences in current window
        syn_count = sum(1 for _, is_syn, _ in self.events[src] if is_syn)
        ack_count = sum(1 for _, _, is_ack in self.events[src] if is_ack)

        # 5. Alert condition
        if syn_count >= self.SYN_THRESHOLD and syn_count > ack_count and src not in self.alerted:
            self.alerted.add(src)
            return f"SYN flood detected from {src} ({syn_count} SYNs vs {ack_count} ACKs in {self.WINDOW}s)"

        return None


class BadFlagDetector:
    def __init__(self):
        self.alerted_null = set()
        self.alerted_xmas = set()

    def check(self, ip, tcp, now):
        src = ip["src_ip"]
        flags = tcp["flags"]
        flag_set = set(flags.split("+"))

        # NULL scan: no flags set
        if flags == "NONE" and src not in self.alerted_null:
            self.alerted_null.add(src)
            return f"NULL scan packet detected from {src}"

        # Xmas scan: FIN, PSH, and URG set simultaneously
        if flag_set == {"FIN", "PSH", "URG"} and src not in self.alerted_xmas:
            self.alerted_xmas.add(src)
            return f"Xmas scan packet detected from {src}"

        return None


def _handle_sigterm(signum, frame):
    raise KeyboardInterrupt


def main(iface):
    signal.signal(signal.SIGTERM, _handle_sigterm)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((iface, 0))

    port_scan = PortScanDetector()
    syn_flood = SynFloodDetector()
    bad_flags = BadFlagDetector()

    print(f"rules engine running on {iface}, Ctrl-C to stop", flush=True)
    try:
        while True:
            frame, _ = s.recvfrom(65535)
            eth = sniffer.parse_ethernet(frame)
            if eth is None or eth["ethertype"] != 0x0800:
                continue
            ip = sniffer.parse_ipv4(frame, eth["payload_offset"])
            if ip is None or ip["protocol"] != 6:
                continue
            tcp = sniffer.parse_tcp(frame, ip["payload_offset"])
            if tcp is None:
                continue

            now = time.time()
            for detector in (port_scan, syn_flood, bad_flags):
                alert = detector.check(ip, tcp, now)
                if alert:
                    ts = time.strftime("%H:%M:%S")
                    print(f"[{ts}] ALERT {alert}", flush=True)
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        s.close()


if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlp0s20f3"
    main(iface)
