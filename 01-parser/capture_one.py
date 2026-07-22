import socket

IFACE = "wlp0s20f3"

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind((IFACE, 0))

frame, addr = s.recvfrom(65535)
s.close()

print(f"captured {len(frame)} bytes from {addr}")
print()
for i in range(0, min(len(frame), 96), 16):
    chunk = frame[i:i+16]
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    print(f"{i:04x}  {hex_part:<48}  {ascii_part}")
