import socket
import struct
IFACE = "wlp0s20f3"
def parse_ethernet(frame):
    if len(frame) < 14:
        return None
    dest_mac, src_mac, ethertype = struct.unpack("!6s6sH", frame[:14])
    
    # Format MAC addresses into human-readable strings (aa:bb:cc:dd:ee:ff)
    format_mac = lambda b: ":".join(f"{x:02x}" for x in b)
    
    return {
        "dest_mac": format_mac(dest_mac),
        "src_mac": format_mac(src_mac),
        "ethertype": ethertype,
        "payload_offset": 14
    }
def parse_ipv4(frame, offset):
    if len(frame) < offset + 20:
        return None
    b0, tos, total_len, ident, flags_frag, ttl, proto, checksum, src_ip, dst_ip = \
        struct.unpack("!BBHHHBBH4s4s", frame[offset:offset+20])
    
    version = b0 >> 4
    ihl = b0 & 0x0F
    header_len = ihl * 4
    
    return {
        "version": version,
        "ihl": ihl,
        "header_len": header_len,
        "total_len": total_len,
        "ttl": ttl,
        "protocol": proto,
        "src_ip": socket.inet_ntoa(src_ip),
        "dst_ip": socket.inet_ntoa(dst_ip),
        "payload_offset": offset + header_len
    }
def parse_tcp(frame, offset):
    if len(frame) < offset + 20:
        return None
    src_port, dst_port, seq, ack, off_reserved, flags, window, checksum, urg = \
        struct.unpack("!HHIIBBHHH", frame[offset:offset+20])
    
    data_offset = off_reserved >> 4
    header_len = data_offset * 4
    
    # Map out TCP flags
    flag_mapping = [
        ("FIN", 0x01),
        ("SYN", 0x02),
        ("RST", 0x04),
        ("PSH", 0x08),
        ("ACK", 0x10),
        ("URG", 0x20),
        ("ECE", 0x40),
        ("CWR", 0x80)
    ]
    
    active_flags = [name for name, bit in flag_mapping if flags & bit]
    flags_str = "+".join(active_flags) if active_flags else "NONE"
    
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "header_len": header_len,
        "flags": flags_str
    }
def parse_udp(frame, offset):
    if len(frame) < offset + 8:
        return None
    src_port, dst_port, length, checksum = \
        struct.unpack("!HHHH", frame[offset:offset+8])
    
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length
    }
def format_packet(eth, ip, l4, l4_name):
    src_endpoint = f"{ip['src_ip']}:{l4['src_port']}"
    dst_endpoint = f"{ip['dst_ip']}:{l4['dst_port']}"
    
    if l4_name == "TCP":
        # Calculate application layer length: total IP length - IP header length - TCP header length
        payload_len = ip["total_len"] - ip["header_len"] - l4["header_len"]
        return f"{l4_name:<4} {src_endpoint} -> {dst_endpoint:<25} {l4['flags']:<10} len={payload_len}"
    
    elif l4_name == "UDP":
        # UDP payload length: UDP header length field minus its own 8-byte header size
        payload_len = l4["length"] - 8
        return f"{l4_name:<4} {src_endpoint} -> {dst_endpoint:<25} len={payload_len}"
    
    return ""
def main():
    # Note: Requires root privileges to execute because of AF_PACKET/SOCK_RAW
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((IFACE, 0))
    try:
        while True:
            frame, _ = s.recvfrom(65535)
            eth = parse_ethernet(frame)
            if eth is None or eth["ethertype"] != 0x0800:
                continue
            ip = parse_ipv4(frame, eth["payload_offset"])
            if ip is None:
                continue
            if ip["protocol"] == 6:
                tcp = parse_tcp(frame, ip["payload_offset"])
                if tcp is None:
                    continue
                print(format_packet(eth, ip, tcp, "TCP"))
            elif ip["protocol"] == 17:
                udp = parse_udp(frame, ip["payload_offset"])
                if udp is None:
                    continue
                print(format_packet(eth, ip, udp, "UDP"))
            else:
                continue
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass
    finally:
        s.close()
if __name__ == "__main__":
    main()