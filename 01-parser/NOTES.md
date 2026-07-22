# Stage 01 — The Parser

## What this is

A raw-socket packet sniffer that parses Ethernet, IPv4, and TCP/UDP headers
by hand, with no packet-parsing library. It opens an AF_PACKET raw socket on
the capture interface, reads whole link-layer frames, and walks each frame
field by field from known byte offsets. The point is to understand the wire
directly rather than to wrap a tool that hides the bytes.

## Why raw sockets

An AF_PACKET SOCK_RAW socket receives frames at the link layer, before the
kernel's IP stack processes them. This is why the parser sees frames that are
not addressed to this machine's IP, forwarded onto the wire by the access
point on shared wireless. A normal application socket never sees these,
because the IP stack drops them before delivery. Reading at the link layer is
what makes this a sniffer and not just a client.

Opening such a socket needs the CAP_NET_RAW capability. This project grants
that capability to a project-local Python interpreter only, and revokes it at
the end. See 00-environment/interface-and-perms.txt.

## Byte layouts parsed

### Ethernet II (14 bytes, fixed)

    offset  size  field
      0      6    destination MAC
      6      6    source MAC
     12      2    EtherType (0x0800 = IPv4)

The EtherType at offset 12 is the dispatch key for the next layer. Only IPv4
is carried forward. Everything else is skipped.

### IPv4 (20 bytes minimum, variable)

    offset  size  field
      0      1    Version (high nibble) | IHL (low nibble)
      1      1    Type of Service
      2      2    Total Length
      8      1    TTL
      9      1    Protocol (6 = TCP, 17 = UDP)
     12      4    source address
     16      4    destination address

Two subtleties handled here. The first byte packs two 4-bit fields, so
Version is byte0 >> 4 and IHL is byte0 & 0x0F. IHL is a count of 32-bit
words, so the header length in bytes is IHL * 4, and that computed length is
what tells the parser where the transport header begins. Assuming a fixed 20
would break on any packet carrying IP options.

### TCP (20 bytes minimum, variable)

    offset  size  field
      0      2    source port
      2      2    destination port
      4      4    sequence number
      8      4    acknowledgment number
     12      1    Data Offset (high nibble) | reserved
     13      1    flags (CWR ECE URG ACK PSH RST SYN FIN)
     14      2    window

Data Offset is again a count of 32-bit words, so the TCP header length is
that nibble * 4. The flags byte at offset 13 is decoded bit by bit into a
readable string like SYN, SYN+ACK, PSH+ACK.

### UDP (8 bytes, fixed)

    offset  size  field
      0      2    source port
      2      2    destination port
      4      2    length
      6      2    checksum

## Network byte order

Every multi-byte integer in these headers is big-endian. This machine is
little-endian x86-64, so the parser unpacks with struct format strings that
begin with "!", which forces network byte order. Reading the bytes natively
would reverse them and produce garbage.

## Robustness

The kernel occasionally delivers truncated or runt frames. Each parser checks
that enough bytes are present before unpacking and returns None otherwise, and
the main loop drops any frame it cannot fully parse rather than crashing. A
parser reading from the network must never assume the buffer is as long as the
headers claim.

## Verification

The parser was cross-checked against tshark on the same interface and the same
live connection to host 104.20.23.154 on port 443. Every TCP flag combination
the parser emitted matched tshark's decoding of the same packets, across the
full handshake, data transfer, and teardown. The record is in
verification/tshark-crosscheck.txt.

Writing this by hand changed how I read a packet. Before this, a packet was an abstraction I trusted a library to decode. Attempting the byte math myself made it concrete: the IHL nibble is the thing that tells you where the next header starts. The flags byte was the most satisfying part, because a single byte tells you the connection works, SYN to open, SYN+ACK to accept, FIN to close, and once you decode it by hand you stop needing a tool to tell you what a handshake looks like. The other thing I did not expect was seeing traffic on the wire that was not addressed to me, which made it more obvious or clear that capturing at the link layer is a genuinely different vantage point from a normal socket. I built the parser this way, because I wanted network analysis to be something I understand from first principles.
