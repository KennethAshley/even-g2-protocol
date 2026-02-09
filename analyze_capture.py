#!/usr/bin/env python3
"""
Comprehensive capture analyzer - extract ALL services from Samsung BTSnoop capture.

Parses the full session to understand:
1. Complete service sequence and timing
2. Which services are used during dashboard activation
3. The mysterious 0x20-08 service packets
4. Response patterns (type 0x12 vs 0x21 commands)
"""

import struct
import sys
from collections import defaultdict


def decode_varint(data, offset=0):
    """Decode a protobuf varint, return (value, bytes_consumed)."""
    result = 0
    shift = 0
    consumed = 0
    while offset < len(data):
        b = data[offset]
        result |= (b & 0x7F) << shift
        shift += 7
        consumed += 1
        offset += 1
        if not (b & 0x80):
            break
    return result, consumed


def decode_protobuf_fields(data):
    """Simple protobuf decoder - returns list of (field_num, wire_type, value)."""
    fields = []
    i = 0
    while i < len(data):
        if i >= len(data):
            break
        tag, consumed = decode_varint(data, i)
        i += consumed
        field_num = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 0:  # varint
            val, consumed = decode_varint(data, i)
            i += consumed
            fields.append((field_num, 'varint', val))
        elif wire_type == 2:  # length-delimited
            length, consumed = decode_varint(data, i)
            i += consumed
            if i + length <= len(data):
                val = data[i:i+length]
                fields.append((field_num, 'bytes', val))
                i += length
            else:
                break
        elif wire_type == 5:  # 32-bit fixed
            if i + 4 <= len(data):
                val = struct.unpack('<f', data[i:i+4])[0]
                fields.append((field_num, 'fixed32', val))
                i += 4
            else:
                break
        elif wire_type == 1:  # 64-bit fixed
            if i + 8 <= len(data):
                val = struct.unpack('<d', data[i:i+8])[0]
                fields.append((field_num, 'fixed64', val))
                i += 8
            else:
                break
        else:
            break  # unknown wire type
    return fields


def extract_strings(data, min_len=4):
    """Extract ASCII strings from binary data."""
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


def main():
    capture_file = sys.argv[1] if len(sys.argv) > 1 else \
        "/Users/ken/Projects/Personal/even-g2-protocol/captures/scripted-session.log"

    with open(capture_file, "rb") as f:
        data = f.read()

    if data[:8] != b"btsnoop\x00":
        print(f"ERROR: Not a BTSnoop file")
        sys.exit(1)

    version = struct.unpack(">I", data[8:12])[0]
    datalink = struct.unpack(">I", data[12:16])[0]
    print(f"BTSnoop: version={version}, datalink={datalink}, size={len(data):,} bytes\n")

    # Find ALL ATT Write Commands to handle 0x0842
    # Marker: 0x52 (ATT Write Cmd) + 0x42 0x08 (handle LE) + type byte
    marker_cmd = bytes([0x52, 0x42, 0x08])
    positions = []
    for i in range(len(data) - 4):
        if data[i:i+3] == marker_cmd:
            positions.append(i)

    print(f"Total GATT Write Command packets to handle 0x0842: {len(positions)}\n")

    # Parse all packets
    all_packets = []
    for pos in positions:
        gatt_start = pos + 3  # skip ATT opcode(1) + handle(2)
        frame = data[gatt_start:]
        if len(frame) < 7:
            continue

        pkt_type = frame[0]  # 0x21 = command, 0x12 = response?
        seq = frame[1]
        pkt_len = frame[2]
        pkt_tot = frame[3]
        pkt_ser = frame[4]
        svc_hi = frame[5]
        svc_lo = frame[6]

        if pkt_len < 2:
            continue

        protobuf_len = pkt_len - 2
        if len(frame) < 7 + pkt_len:
            continue

        protobuf = frame[7:7+protobuf_len]

        all_packets.append({
            "index": len(all_packets),
            "file_offset": pos,
            "type": pkt_type,
            "seq": seq,
            "pkt_len": pkt_len,
            "pkt_tot": pkt_tot,
            "pkt_ser": pkt_ser,
            "svc_hi": svc_hi,
            "svc_lo": svc_lo,
            "service": f"0x{svc_hi:02X}-{svc_lo:02X}",
            "protobuf": protobuf,
        })

    # =========================================================================
    # Summary by service
    # =========================================================================
    print("=" * 80)
    print("SERVICE DISTRIBUTION")
    print("=" * 80)

    svc_counts = defaultdict(int)
    svc_types = defaultdict(set)
    for p in all_packets:
        svc_counts[p["service"]] += 1
        svc_types[p["service"]].add(p["type"])

    for svc in sorted(svc_counts.keys()):
        types = sorted(svc_types[svc])
        type_str = ", ".join(f"0x{t:02X}" for t in types)
        print(f"  {svc}: {svc_counts[svc]:4d} packets  (types: {type_str})")

    # =========================================================================
    # Full packet-by-packet sequence
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("FULL PACKET SEQUENCE")
    print("=" * 80)

    for i, p in enumerate(all_packets):
        proto = p["protobuf"]
        svc = p["service"]
        type_label = "CMD" if p["type"] == 0x21 else f"t=0x{p['type']:02X}"

        # Decode first few protobuf fields
        fields = decode_protobuf_fields(proto)
        field_str = ""
        for fn, wt, val in fields[:5]:
            if wt == 'varint':
                field_str += f" f{fn}={val}"
            elif wt == 'bytes':
                if len(val) <= 20:
                    field_str += f" f{fn}=[{len(val)}b]"
                else:
                    field_str += f" f{fn}=[{len(val)}b]"
            elif wt == 'fixed32':
                field_str += f" f{fn}={val:.1f}"

        # Extract strings
        strings = extract_strings(proto)
        str_str = ""
        if strings:
            str_str = f"  \"{strings[0][:40]}\""

        multi = ""
        if p["pkt_tot"] > 1:
            multi = f" [{p['pkt_ser']}/{p['pkt_tot']}]"

        print(f"  [{i:3d}] seq=0x{p['seq']:02X} {type_label:6s} {svc}"
              f" ({len(proto):3d}b){multi}{field_str}{str_str}")

    # =========================================================================
    # Dashboard-related sequence (services: 0x01, 0x04, 0x07, 0x0A, 0x0E, 0x10)
    # =========================================================================
    dashboard_services = {"0x01-20", "0x04-20", "0x07-20", "0x0A-20", "0x0E-20", "0x10-20"}
    print(f"\n{'=' * 80}")
    print("DASHBOARD-RELATED PACKETS")
    print("=" * 80)

    for i, p in enumerate(all_packets):
        if p["service"] in dashboard_services:
            proto = p["protobuf"]
            fields = decode_protobuf_fields(proto)
            strings = extract_strings(proto)

            field_str = ""
            for fn, wt, val in fields[:8]:
                if wt == 'varint':
                    field_str += f" f{fn}={val}"
                elif wt == 'bytes':
                    sub = decode_protobuf_fields(val)
                    sub_str = " ".join(f"f{sf}={sv}" for sf, st, sv in sub[:3] if st == 'varint')
                    field_str += f" f{fn}=[{len(val)}b: {sub_str}]"

            str_info = ""
            if strings:
                str_info = f"\n         strings: {strings}"

            print(f"  [{i:3d}] seq=0x{p['seq']:02X} {p['service']}"
                  f" ({len(proto):3d}b){field_str}{str_info}")

    # =========================================================================
    # Unknown/interesting services deep dive
    # =========================================================================
    unknown_services = set()
    for p in all_packets:
        if p["service"] not in {"0x80-00", "0x80-20", "0x0B-20", "0x06-20",
                                 "0x01-20", "0x04-20", "0x07-20", "0x0A-20",
                                 "0x0E-20", "0x10-20", "0x02-20"}:
            unknown_services.add(p["service"])

    if unknown_services:
        print(f"\n{'=' * 80}")
        print(f"UNKNOWN/UNEXPLORED SERVICES: {sorted(unknown_services)}")
        print("=" * 80)

        for svc in sorted(unknown_services):
            pkts = [p for p in all_packets if p["service"] == svc]
            print(f"\n  --- {svc}: {len(pkts)} packets ---")
            for p in pkts[:10]:
                proto = p["protobuf"]
                fields = decode_protobuf_fields(proto)
                field_str = ""
                for fn, wt, val in fields[:8]:
                    if wt == 'varint':
                        field_str += f" f{fn}={val}"
                    elif wt == 'bytes':
                        field_str += f" f{fn}=[{len(val)}b:{val.hex()[:30]}]"
                strings = extract_strings(proto)
                str_info = ""
                if strings:
                    str_info = f" \"{strings[0][:40]}\""
                print(f"    [{p['index']:3d}] seq=0x{p['seq']:02X} ({len(proto):3d}b)"
                      f"{field_str}{str_info}")
                print(f"          hex: {proto.hex()[:80]}")

    # =========================================================================
    # Look for service-related configuration patterns
    # =========================================================================
    print(f"\n{'=' * 80}")
    print("SERVICE 0x01-20 DEEP DIVE (Widget/Service Config)")
    print("=" * 80)

    svc01_pkts = [p for p in all_packets if p["service"] == "0x01-20"]
    for p in svc01_pkts:
        proto = p["protobuf"]
        fields = decode_protobuf_fields(proto)
        strings = extract_strings(proto, min_len=3)

        # Get type and msg_id
        type_val = None
        msg_id = None
        for fn, wt, val in fields:
            if fn == 1 and wt == 'varint':
                type_val = val
            if fn == 2 and wt == 'varint':
                msg_id = val

        print(f"\n  [{p['index']:3d}] seq=0x{p['seq']:02X} type={type_val} msg_id={msg_id}"
              f" ({len(proto)}b)")

        # Deep decode field 4 (the main content)
        for fn, wt, val in fields:
            if fn == 4 and wt == 'bytes':
                sub = decode_protobuf_fields(val)
                print(f"    field 4 ({len(val)}b):")
                for sfn, swt, sval in sub:
                    if swt == 'varint':
                        print(f"      f{sfn} = {sval}")
                    elif swt == 'bytes':
                        sub2 = decode_protobuf_fields(sval)
                        print(f"      f{sfn} [{len(sval)}b]:")
                        for s2fn, s2wt, s2val in sub2:
                            if s2wt == 'varint':
                                print(f"        f{s2fn} = {s2val}")
                            elif s2wt == 'bytes':
                                sub3 = decode_protobuf_fields(s2val)
                                s3_strings = extract_strings(s2val, 3)
                                print(f"        f{s2fn} [{len(s2val)}b]: {s2val.hex()[:40]}")
                                if s3_strings:
                                    print(f"          strings: {s3_strings}")
                                for s3fn, s3wt, s3val in sub3[:6]:
                                    if s3wt == 'varint':
                                        print(f"          f{s3fn}={s3val}")
                                    elif s3wt == 'bytes':
                                        s3_str = extract_strings(s3val, 3)
                                        if s3_str:
                                            print(f"          f{s3fn}=\"{s3_str[0]}\"")
                                        else:
                                            print(f"          f{s3fn}=[{len(s3val)}b]:{s3val.hex()[:30]}")

        if strings:
            print(f"    strings: {strings}")

        print(f"    hex: {proto.hex()[:100]}")


if __name__ == "__main__":
    main()
