#!/usr/bin/env python3
"""
Proper BTSnoop parser for Samsung BLE captures.

Instead of raw byte pattern matching (which produces false positives),
this parser properly reads BTSnoop record headers to find ATT Write
Commands, then extracts G2 protocol frames.

Samsung BTSnoop uses datalink type 768 (0x0300).
Record format: standard BTSnoop with Samsung HCI extensions.
"""

import struct
import sys
from collections import defaultdict


def decode_varint(data, offset=0):
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        result |= (b & 0x7F) << shift
        shift += 7
        offset += 1
        if not (b & 0x80):
            break
    return result, offset


def extract_strings(data, min_len=4):
    strings = []
    i = 0
    while i < len(data):
        if 0x20 <= data[i] <= 0x7E:
            start = i
            while i < len(data) and 0x20 <= data[i] <= 0x7E:
                i += 1
            if i - start >= min_len:
                strings.append(data[start:i].decode('ascii'))
        else:
            i += 1
    return strings


def parse_btsnoop(filename):
    with open(filename, "rb") as f:
        data = f.read()

    # File header
    magic = data[:8]
    if magic != b"btsnoop\x00":
        print(f"Not a BTSnoop file: {magic}")
        return

    version = struct.unpack(">I", data[8:12])[0]
    datalink = struct.unpack(">I", data[12:16])[0]
    print(f"BTSnoop v{version}, datalink={datalink} (0x{datalink:04X})")
    print(f"File size: {len(data):,} bytes\n")

    # Parse records
    offset = 16
    records = []
    while offset + 24 <= len(data):
        orig_len = struct.unpack(">I", data[offset:offset+4])[0]
        incl_len = struct.unpack(">I", data[offset+4:offset+8])[0]
        flags = struct.unpack(">I", data[offset+8:offset+12])[0]
        drops = struct.unpack(">I", data[offset+12:offset+16])[0]
        ts = struct.unpack(">q", data[offset+16:offset+24])[0]

        if offset + 24 + incl_len > len(data):
            break

        pkt_data = data[offset+24:offset+24+incl_len]
        direction = flags & 0x01  # 0=sent, 1=received
        records.append({
            "offset": offset,
            "orig_len": orig_len,
            "incl_len": incl_len,
            "flags": flags,
            "direction": direction,
            "ts": ts,
            "data": pkt_data,
        })
        offset += 24 + incl_len

    print(f"Total BTSnoop records: {len(records)}\n")

    # Find ATT Write Commands in record data
    # Samsung format wraps HCI packets. Look for ATT Write Command (0x52)
    # followed by handle 0x0842 (LE: 42 08)
    g2_packets = []
    att_marker = bytes([0x52, 0x42, 0x08])

    for rec in records:
        pkt = rec["data"]
        # Search for ATT Write Command pattern within the record
        pos = 0
        while pos < len(pkt) - 10:
            idx = pkt.find(att_marker, pos)
            if idx == -1:
                break

            frame_start = idx + 3  # Skip ATT opcode + handle
            frame = pkt[frame_start:]

            if len(frame) < 7:
                pos = idx + 1
                continue

            pkt_type = frame[0]
            seq = frame[1]
            pkt_len = frame[2]
            pkt_tot = frame[3]
            pkt_ser = frame[4]
            svc_hi = frame[5]
            svc_lo = frame[6]

            if pkt_type != 0x21:
                pos = idx + 1
                continue

            if pkt_len < 2 or pkt_len > 200:
                pos = idx + 1
                continue

            proto_len = pkt_len - 2
            if len(frame) < 7 + pkt_len:
                pos = idx + 1
                continue

            protobuf = frame[7:7+proto_len]

            g2_packets.append({
                "index": len(g2_packets),
                "rec_offset": rec["offset"],
                "direction": rec["direction"],
                "ts": rec["ts"],
                "seq": seq,
                "pkt_len": pkt_len,
                "pkt_tot": pkt_tot,
                "pkt_ser": pkt_ser,
                "svc_hi": svc_hi,
                "svc_lo": svc_lo,
                "service": f"0x{svc_hi:02X}-{svc_lo:02X}",
                "protobuf": protobuf,
                "raw": frame[:7+pkt_len],
            })

            # Only take first match per record to avoid duplicates
            break

        pos = idx + 1 if idx != -1 else len(pkt)

    print(f"G2 protocol packets found: {len(g2_packets)}\n")

    # Filter to single-packet-per-record (deduplicate)
    # Group by record offset, take first
    seen_offsets = set()
    unique_packets = []
    for p in g2_packets:
        key = (p["rec_offset"], p["seq"], p["service"])
        if key not in seen_offsets:
            seen_offsets.add(key)
            unique_packets.append(p)

    print(f"Unique packets (deduped by record): {len(unique_packets)}\n")

    # =========================================================================
    # Service distribution
    # =========================================================================
    print("=" * 80)
    print("SERVICE DISTRIBUTION")
    print("=" * 80)

    svc_counts = defaultdict(int)
    for p in unique_packets:
        svc_counts[p["service"]] += 1

    for svc in sorted(svc_counts.keys()):
        known = {
            "0x80-00": "Auth Control",
            "0x80-20": "Auth Data",
            "0x01-20": "Widget Data",
            "0x02-20": "Notification",
            "0x04-20": "Display Wake",
            "0x06-20": "Teleprompter",
            "0x07-20": "Dashboard",
            "0x09-20": "Device Info",
            "0x0A-20": "Dashboard Enable",
            "0x0B-20": "Conversate",
            "0x0E-20": "Display Config",
            "0x10-20": "Screen Mode",
        }.get(svc, "")
        print(f"  {svc}: {svc_counts[svc]:4d} packets  {known}")

    # =========================================================================
    # Full sequence (first 100)
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("FULL PACKET SEQUENCE (first 200)")
    print("=" * 80)

    for p in unique_packets[:200]:
        proto = p["protobuf"]
        svc = p["service"]

        # Decode protobuf fields
        fields = {}
        try:
            i = 0
            while i < len(proto):
                tag_val, new_i = decode_varint(proto, i)
                fn = tag_val >> 3
                wt = tag_val & 7
                i = new_i
                if wt == 0:
                    val, i = decode_varint(proto, i)
                    fields[fn] = ('v', val)
                elif wt == 2:
                    ln, i = decode_varint(proto, i)
                    if i + ln <= len(proto):
                        fields[fn] = ('b', proto[i:i+ln])
                        i += ln
                    else:
                        break
                elif wt == 5:
                    if i + 4 <= len(proto):
                        fields[fn] = ('f', struct.unpack('<f', proto[i:i+4])[0])
                        i += 4
                    else:
                        break
                else:
                    break
        except Exception:
            pass

        type_val = fields.get(1, ('', ''))
        msg_id = fields.get(2, ('', ''))
        type_str = f"type={type_val[1]}" if type_val[0] == 'v' else ""
        mid_str = f"mid={msg_id[1]}" if msg_id[0] == 'v' else ""

        strings = extract_strings(proto)
        str_info = f"  \"{strings[0][:35]}\"" if strings else ""

        multi = ""
        if p["pkt_tot"] > 1:
            multi = f" [{p['pkt_ser']}/{p['pkt_tot']}]"

        dir_arrow = "->" if p["direction"] == 0 else "<-"
        print(f"  [{p['index']:3d}] {dir_arrow} seq={p['seq']:02X} {svc}"
              f" ({len(proto):3d}b){multi} {type_str} {mid_str}{str_info}")

    # =========================================================================
    # Dashboard sequence detail
    # =========================================================================
    dashboard_svcs = {"0x01-20", "0x04-20", "0x07-20", "0x0A-20", "0x0E-20", "0x10-20"}
    print(f"\n{'=' * 80}")
    print("DASHBOARD-RELATED PACKETS (with hex)")
    print("=" * 80)

    for p in unique_packets:
        if p["service"] in dashboard_svcs:
            proto = p["protobuf"]
            strings = extract_strings(proto, 3)
            str_info = f"\n         strings: {strings}" if strings else ""
            print(f"  [{p['index']:3d}] seq={p['seq']:02X} {p['service']}"
                  f" ({len(proto):3d}b){str_info}")
            # Show hex in rows of 32
            for row in range(0, min(len(proto), 64), 32):
                chunk = proto[row:row+32]
                print(f"         {chunk.hex()}")

    # =========================================================================
    # Responses from glasses (direction=1)
    # =========================================================================
    responses = [p for p in unique_packets if p["direction"] == 1]
    if responses:
        print(f"\n{'=' * 80}")
        print(f"RESPONSES FROM GLASSES ({len(responses)} packets)")
        print("=" * 80)
        for p in responses[:30]:
            proto = p["protobuf"]
            print(f"  [{p['index']:3d}] seq={p['seq']:02X} {p['service']}"
                  f" ({len(proto):3d}b): {proto.hex()[:60]}")


if __name__ == "__main__":
    fn = sys.argv[1] if len(sys.argv) > 1 else \
        "/Users/ken/Projects/Personal/even-g2-protocol/captures/scripted-session.log"
    parse_btsnoop(fn)
