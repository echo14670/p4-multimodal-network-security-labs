#!/usr/bin/env python3
"""Decode class-2 polymorphic pcap captures into readable replica evidence.

Usage:
    python3 decode-poly.py pcaps/s1-eth2_out.pcap [more.pcap ...]

For every captured frame the script prints the outer modality header, the
PolyShim fields and the inner IPv4/UDP/protected_data view.  The trailing
summary answers the class-2 questions: how many frames were captured, which
sequence numbers and modality ids were seen, and whether all replicas share one
reference CRC32.

Only the field contract of STUDENT_TODO.md is assumed:
    Ethernet / outer modality header / PolyShim / inner IPv4 / UDP /
    protected_data
"""

import argparse
import struct
import sys

from scapy.all import rdpcap

POLY_MAGIC = 0x504F
POLY_IP_PROTOCOL = 253
TYPE_IPV4 = 0x0800
TYPE_IPV6 = 0x86DD
TYPE_SRCROUTING = 0x1234
SHIM_LEN = 14        # 112 bit
PROTECTED_BYTES = 16


class Reader(object):
    """Sequential big-endian reader over a raw Ethernet frame."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, size):
        chunk = self.data[self.pos:self.pos + size]
        if len(chunk) != size:
            raise ValueError("truncated frame")
        self.pos += size
        return chunk

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("!H", self.take(2))[0]

    def u32(self):
        return struct.unpack("!I", self.take(4))[0]

    def peek_u16(self):
        """Look at the next 16 bit without consuming them (0 if truncated)."""
        chunk = self.data[self.pos:self.pos + 2]
        if len(chunk) != 2:
            return None
        return struct.unpack("!H", chunk)[0]


def ip4(data):
    return ".".join(str(b) for b in bytearray(data))


def ip6(data):
    words = struct.unpack("!8H", data)
    return ":".join("%x" % word for word in words)


def parse_ipv4(reader, label):
    first = reader.u8()
    ihl = (first & 0x0F) * 4
    reader.take(1)                       # diffserv
    total_len = reader.u16()
    reader.take(4)                       # identification, flags + fragOffset
    ttl = reader.u8()
    protocol = reader.u8()
    reader.take(2)                       # header checksum
    src = ip4(reader.take(4))
    dst = ip4(reader.take(4))
    if ihl > 20:
        reader.take(ihl - 20)
    return ("%s %s>%s proto=%d ttl=%d totalLen=%d"
            % (label, src, dst, protocol, ttl, total_len), protocol)


def parse_ipv6(reader, label):
    reader.take(1)                       # version + traffic class
    reader.take(3)                       # traffic class + flow label
    payload_len = reader.u16()
    next_hdr = reader.u8()
    hop_limit = reader.u8()
    src = ip6(reader.take(16))
    dst = ip6(reader.take(16))
    return ("%s %s>%s nextHdr=%d hopLimit=%d payloadLen=%d"
            % (label, src, dst, next_hdr, hop_limit, payload_len), next_hdr)


def parse_srcroutes(reader):
    hops = []
    while True:
        word = reader.u16()
        bos = word >> 15
        hops.append((word & 0x7FFF, bos))
        if bos:
            break
    stack = " ".join("%d%s" % (port, "(bos)" if bos else "")
                     for port, bos in hops)
    return "srcRoute stack=%s" % stack


def parse_polyshim(reader):
    magic = reader.u16()
    direction = reader.u8()
    sequence = reader.u32()
    modality = reader.u8()
    crc = reader.u32()
    inner_type = reader.u16()
    text = ("polyShim magic=0x%04x direction=%d sequence=%d modality=%d "
            "crc32=0x%08x inner_ether_type=0x%04x"
            % (magic, direction, sequence, modality, crc, inner_type))
    if magic != POLY_MAGIC:
        text += "  <-- unexpected magic"
    return text, {"sequence": sequence, "modality": modality, "crc": crc,
                  "direction": direction}


def parse_udp(reader):
    sport = reader.u16()
    dport = reader.u16()
    reader.take(4)                       # length + checksum
    return sport, dport


def decode_frame(data):
    """Return (list of text lines, replica info dict or None)."""
    reader = Reader(data)
    dst_mac = ":".join("%02x" % b for b in bytearray(reader.take(6)))
    src_mac = ":".join("%02x" % b for b in bytearray(reader.take(6)))
    ether_type = reader.u16()

    lines = ["etherType=0x%04x src=%s dst=%s" % (ether_type, src_mac, dst_mac)]
    info = None

    if ether_type == TYPE_SRCROUTING:
        lines.append(parse_srcroutes(reader))
        # A scheduled source-routed replica carries a PolyShim behind the port
        # stack; the original demo's source-routed packets carry IPv4 there.
        if reader.peek_u16() != POLY_MAGIC:
            lines.append("plain source-routed packet (no PolyShim)")
            return lines, None
        shim_line, info = parse_polyshim(reader)
        lines.append(shim_line)
    elif ether_type == TYPE_IPV4:
        outer_line, outer_protocol = parse_ipv4(reader, "IPv4")
        lines.append(outer_line)
        if outer_protocol == POLY_IP_PROTOCOL:
            shim_line, info = parse_polyshim(reader)
            lines.append(shim_line)
    elif ether_type == TYPE_IPV6:
        outer_line, outer_protocol = parse_ipv6(reader, "IPv6")
        lines.append(outer_line)
        if outer_protocol == POLY_IP_PROTOCOL:
            shim_line, info = parse_polyshim(reader)
            lines.append(shim_line)
    else:
        return lines, None

    if info is None:
        return lines, None

    inner_line, inner_protocol = parse_ipv4(reader, "inner")
    lines.append(inner_line)
    if inner_protocol == 17:
        sport, dport = parse_udp(reader)
        payload = reader.take(PROTECTED_BYTES)
        lines.append("inner udp %d>%d protected_hex=%s text=%r"
                     % (sport, dport, payload.hex(),
                        payload.rstrip(b"\x00").decode("utf-8",
                                                       errors="replace")))
    return lines, info


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pcaps", nargs="+", help="pcap files to decode")
    parser.add_argument("--quiet-empty", action="store_true",
                        help="do not print files without matching frames")
    args = parser.parse_args()

    total = 0
    sequences = set()
    modalities = set()
    crcs = set()
    directions = set()

    for path in args.pcaps:
        packets = rdpcap(path)
        matched = 0
        for index, packet in enumerate(packets, start=1):
            try:
                lines, info = decode_frame(bytes(packet))
            except (ValueError, struct.error) as exc:
                print("%s frame#%d undecodable: %s" % (path, index, exc))
                continue
            if info is None:
                continue
            matched += 1
            total += 1
            sequences.add(info["sequence"])
            modalities.add(info["modality"])
            crcs.add(info["crc"])
            directions.add(info["direction"])
            print("%s frame#%d" % (path, index))
            for line in lines:
                print("    " + line)
        if matched == 0 and not args.quiet_empty:
            print("%s: no polymorphic replica in %d captured frames"
                  % (path, len(packets)))
        elif matched:
            print("%s frames=%d replicas=%d" % (path, len(packets), matched))
        print("")

    print("SUMMARY frames_with_polyshim=%d sequence_numbers=%s modalities=%s "
          "directions=%s source_crc32=%s same_sequence=%s same_crc=%s"
          % (total, sorted(sequences), sorted(modalities), sorted(directions),
             ["0x%08x" % crc for crc in sorted(crcs)],
             "yes" if len(sequences) <= 1 else "no",
             "yes" if len(crcs) <= 1 else "no"))
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())