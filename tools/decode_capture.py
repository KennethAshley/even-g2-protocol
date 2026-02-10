#!/usr/bin/env python3
"""
Decode Samsung BTSnoop capture using PR#1 parser with proper protobuf decoding.

Extracts AA frames from the proprietary Samsung capture format and runs
them through the PR#1 MsgHandler for full protobuf decode of all services.
"""

import struct
import sys
import os
import hashlib

# Add the pbgenerated path so the parser can find compiled protos
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "pbgenerated", "g2"))

from parser import MsgHandler, EvenBleTransport, service_name_mapping


def extract_frames_from_samsung_btsnoop(data):
    """Extract G2 frames from Samsung proprietary btsnoop format.

    Samsung datalink 768 is proprietary. We find frames by searching for
    the ATT Write Command pattern: 0x52 (ATT Write Cmd) + 0x42 0x08 (handle 0x0842 LE).

    In Samsung captures, there is NO 0xAA prefix - frames start directly
    with the src+dest byte (0x21 for phone→glasses, 0x12 for glasses→phone).
    """
    marker = bytes([0x52, 0x42, 0x08])
    frames = []
    seen_hashes = set()

    for i in range(len(data) - 10):
        if data[i:i+3] != marker:
            continue

        # Frame starts after ATT header (3 bytes)
        frame_start = i + 3

        # Sanity check: first byte should be 0x21 or 0x12 (src+dest)
        if frame_start >= len(data):
            continue
        src_dest = data[frame_start]
        if src_dest not in (0x21, 0x12):
            continue

        # Read length from frame[2] (payloadLen)
        if frame_start + 3 >= len(data):
            continue
        payload_len = data[frame_start + 2]

        # Total frame: 8-byte header + payloadLen (includes 2-byte CRC for single packets)
        frame_len = 8 + payload_len
        if frame_start + frame_len > len(data):
            continue

        # Reconstruct AA frame by prepending 0xAA
        raw_frame = bytes([0xAA]) + data[frame_start:frame_start + frame_len]

        # Dedup (dual lens traffic is interleaved)
        h = hashlib.md5(raw_frame[8:]).hexdigest()  # hash payload only
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        frames.append(raw_frame)

    return frames


def main():
    capture_file = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(os.path.dirname(__file__), "..", "captures", "scripted-session.log")

    with open(capture_file, "rb") as f:
        data = f.read()

    print(f"Capture: {capture_file} ({len(data):,} bytes)")

    if data[:8] == b"btsnoop\x00":
        version = struct.unpack(">I", data[8:12])[0]
        datalink = struct.unpack(">I", data[12:16])[0]
        print(f"BTSnoop v{version}, datalink={datalink}")

    frames = extract_frames_from_samsung_btsnoop(data)
    print(f"Extracted {len(frames)} unique frames\n")

    # Filter: only first-fragments (pkt_ser == 1 or single-packet)
    handler = MsgHandler()
    service_order = []

    for idx, frame in enumerate(frames):
        transport = EvenBleTransport.fromBytes(frame)
        if transport is None:
            continue

        svc_name = service_name_mapping.get(transport.serviceId, f"UNKNOWN(0x{transport.serviceId:02X})")
        direction = "APP→G2" if transport.sourceId == 2 else "G2→APP"

        # Skip ACK/status packets (resultCode != 0 means no payload)
        if transport.resultCode != 0:
            service_order.append((idx, svc_name, direction, f"ACK/result={transport.resultCode}"))
            continue

        print(f"\n{'='*70}")
        print(f"[{idx:3d}] {direction}  service={svc_name}  "
              f"sync=0x{transport.syncId:02X}  "
              f"pkt={transport.packetSerialNum}/{transport.packetTotalNum}  "
              f"notify={transport.notify}  result={transport.resultCode}")

        # Accumulate multipart
        try:
            result = handler.accum_multipart_done(transport)
        except (AssertionError, Exception) as e:
            print(f"      multipart error: {e}")
            continue
        if result is None:
            print(f"      (multipart fragment, waiting for more)")
            continue

        # Decode protobuf
        if result.payload:
            print(f"      payload ({len(result.payload)}b): {result.payload.hex()[:80]}")
            try:
                pkg = result.dataPackage()
                if pkg is not None:
                    # Format protobuf nicely
                    decoded_str = str(pkg).strip()
                    if len(decoded_str) > 200:
                        decoded_str = decoded_str[:200] + "..."
                    print(f"      decoded: {decoded_str}")
            except Exception as e:
                print(f"      decode error: {e}")

        service_order.append((idx, svc_name, direction, "DATA"))

    # Summary
    print(f"\n\n{'='*70}")
    print("SERVICE SEQUENCE SUMMARY")
    print('='*70)
    for idx, svc, direction, info in service_order:
        if info == "DATA":
            print(f"  [{idx:3d}] {direction:8s} {svc}")
        else:
            print(f"  [{idx:3d}] {direction:8s} {svc}  ({info})")


if __name__ == "__main__":
    main()
