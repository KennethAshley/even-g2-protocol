#!/usr/bin/env python3
"""
Extract protobuf payloads for service 0x01-0x20 from Samsung BTSnoop BLE capture.

Samsung BTSnoop format (datalink type 768):
  - File header: "btsnoop\0" + version(4) + datalink(4) = 16 bytes
  - Records contain BLE HCI data

EVEN G2 Protocol frame (AA-header):
  AA[0] Type[1] Seq[2] Len[3] PktTot[4] PktSer[5] SvcHi[6] SvcLo[7] Payload[8:N-2] CRC[N-1:N]

In the GATT capture, the AA magic byte is not present. We search for:
  ATT Write Command (0x52) + Handle 0x0842 (LE: 42 08) + Type 0x21
The G2 frame in the capture starts at the Type byte (0x21).
"""

import struct
import sys


def extract_ascii_strings(data: bytes, min_len: int = 3) -> list[str]:
    """Extract runs of printable ASCII characters from binary data."""
    strings = []
    i = 0
    while i < len(data):
        if 0x20 <= data[i] <= 0x7E:
            start = i
            while i < len(data) and 0x20 <= data[i] <= 0x7E:
                i += 1
            if i - start >= min_len:
                strings.append(data[start:i].decode("ascii"))
        else:
            i += 1
    return strings


def main():
    capture_file = "/Users/ken/Projects/Personal/even-g2-protocol/captures/scripted-session.log"

    with open(capture_file, "rb") as f:
        data = f.read()

    # Verify BTSnoop header
    if data[:8] != b"btsnoop\x00":
        print(f"ERROR: Not a BTSnoop file (magic: {data[:8]})")
        sys.exit(1)

    version = struct.unpack(">I", data[8:12])[0]
    datalink = struct.unpack(">I", data[12:16])[0]
    print(f"BTSnoop file: version={version}, datalink={datalink}")
    print(f"File size: {len(data):,} bytes")
    print()

    # Search for ATT Write Command (0x52) to handle 0x0842 with type 0x21
    marker = bytes([0x52, 0x42, 0x08, 0x21])
    positions = []
    for i in range(len(marker), len(data) - len(marker)):
        if data[i : i + len(marker)] == marker:
            positions.append(i)

    print(f"Total GATT Write Command packets to handle 0x0842 (type 0x21): {len(positions)}")
    print()

    # G2 frame layout (without the AA magic byte):
    #   [0]=Type(0x21) [1]=Seq [2]=Len [3]=PktTot [4]=PktSer [5]=SvcHi [6]=SvcLo
    #   [7 .. 7+Len-3] = Protobuf payload
    #   [7+Len-2 .. 7+Len-1] = CRC-16 (LE)
    # Len = protobuf_size + 2 (includes CRC)

    service_packets = []
    for pos in positions:
        gatt_start = pos + 3  # skip ATT opcode(1) + handle(2)
        frame = data[gatt_start:]
        if len(frame) < 7:
            continue

        seq = frame[1]
        pkt_len = frame[2]
        pkt_tot = frame[3]
        pkt_ser = frame[4]
        svc_hi = frame[5]
        svc_lo = frame[6]

        if svc_hi != 0x01 or svc_lo != 0x20:
            continue
        if pkt_len < 2:
            continue

        protobuf_len = pkt_len - 2
        if len(frame) < 7 + pkt_len:
            continue

        protobuf = frame[7 : 7 + protobuf_len]
        crc_bytes = frame[7 + protobuf_len : 7 + protobuf_len + 2]

        service_packets.append({
            "file_offset": pos,
            "seq": seq,
            "pkt_len": pkt_len,
            "pkt_tot": pkt_tot,
            "pkt_ser": pkt_ser,
            "protobuf": protobuf,
            "crc_bytes": crc_bytes,
        })

    print(f"Service 0x01-0x20 packets found: {len(service_packets)}")
    print("=" * 90)
    print()

    # Print first 20 payloads
    limit = min(20, len(service_packets))
    for i, pkt in enumerate(service_packets[:limit]):
        seq = pkt["seq"]
        proto = pkt["protobuf"]

        print(f"--- Payload {i + 1}/{len(service_packets)} | Seq=0x{seq:02x} | Pkt {pkt['pkt_ser']}/{pkt['pkt_tot']} | {len(proto)} bytes | offset 0x{pkt['file_offset']:06x} ---")

        # Print hex dump with ASCII sidebar
        for row_start in range(0, len(proto), 16):
            row = proto[row_start : row_start + 16]
            hex_part = " ".join(f"{b:02x}" for b in row)
            ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in row)
            print(f"  {row_start:04x}: {hex_part:<48s}  |{ascii_part}|")

        # Extract readable ASCII strings
        ascii_strings = extract_ascii_strings(proto)
        if ascii_strings:
            print(f"  Strings: {' | '.join(repr(s) for s in ascii_strings)}")

        print()

    # Summary
    print("=" * 90)
    print(f"SUMMARY")
    print(f"  Total service 0x01-0x20 packets: {len(service_packets)}")

    single = sum(1 for p in service_packets if p["pkt_tot"] == 1)
    multi = len(service_packets) - single
    print(f"  Single-packet messages: {single}")
    print(f"  Multi-packet fragments: {multi}")

    seqs = sorted(set(p["seq"] for p in service_packets))
    print(f"  Unique sequence numbers ({len(seqs)}): {', '.join(f'0x{s:02x}' for s in seqs)}")

    # Multi-packet message reassembly summary
    if multi > 0:
        print()
        print("MULTI-PACKET MESSAGES (reassembled text):")
        multi_seqs = sorted(set(p["seq"] for p in service_packets if p["pkt_tot"] > 1))
        for s in multi_seqs:
            parts = sorted(
                [p for p in service_packets if p["seq"] == s and p["pkt_tot"] > 1],
                key=lambda x: x["pkt_ser"],
            )
            tot = parts[0]["pkt_tot"]
            reassembled = b"".join(p["protobuf"] for p in parts)
            text_parts = extract_ascii_strings(reassembled, min_len=5)
            text_preview = " [...] ".join(text_parts)[:120] if text_parts else "(binary only)"
            print(f"  Seq 0x{s:02x}: {len(parts)}/{tot} parts, {len(reassembled)} bytes")
            print(f"    {text_preview}")


if __name__ == "__main__":
    main()
