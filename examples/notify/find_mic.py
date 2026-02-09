#!/usr/bin/env python3
"""
Find G2 microphone audio channel.

Subscribes to ALL notify-capable characteristics on the G2,
starts a Conversate session (which activates the mic), and
records everything that comes in on any channel.
"""

import asyncio
import time
from collections import defaultdict
from bleak import BleakClient, BleakScanner


UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)


def crc16_ccitt(data, init=0xFFFF):
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def add_crc(packet):
    crc = crc16_ccitt(packet[8:])
    return packet + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def encode_varint(value):
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def build_aa(seq, svc_hi, svc_lo, payload):
    header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, svc_hi, svc_lo])
    return add_crc(header + payload)


def pb_varint(field, value):
    return bytes([(field << 3) | 0]) + encode_varint(value)

def pb_bytes(field, data):
    return bytes([(field << 3) | 2]) + encode_varint(len(data)) + data

def pb_string(field, text):
    return pb_bytes(field, text.encode('utf-8'))


def build_auth_packets():
    timestamp = int(time.time())
    ts = encode_varint(timestamp)
    txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])
    p = []
    p.append(add_crc(bytes([0xAA,0x21,0x01,0x0C,0x01,0x01,0x80,0x00,0x08,0x04,0x10,0x0C,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x02,0x0A,0x01,0x01,0x80,0x20,0x08,0x05,0x10,0x0E,0x22,0x02,0x08,0x02])))
    pl = bytes([0x08,0x80,0x01,0x10,0x0F,0x82,0x08,0x11,0x08]) + ts + bytes([0x10]) + txid
    p.append(add_crc(bytes([0xAA,0x21,0x03,len(pl)+2,0x01,0x01,0x80,0x20]) + pl))
    p.append(add_crc(bytes([0xAA,0x21,0x04,0x0C,0x01,0x01,0x80,0x00,0x08,0x04,0x10,0x10,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x05,0x0C,0x01,0x01,0x80,0x00,0x08,0x04,0x10,0x11,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x06,0x0A,0x01,0x01,0x80,0x20,0x08,0x05,0x10,0x12,0x22,0x02,0x08,0x01])))
    pl = bytes([0x08,0x80,0x01,0x10,0x13,0x82,0x08,0x11,0x08]) + ts + bytes([0x10]) + txid
    p.append(add_crc(bytes([0xAA,0x21,0x07,len(pl)+2,0x01,0x01,0x80,0x20]) + pl))
    return p


# Packet storage
packets = defaultdict(list)
start_time = None


def make_handler(char_uuid):
    """Create a notification handler that tags packets with their source."""
    # Extract the short ID from UUID
    short = char_uuid.split("72e")[1][:4] if "72e" in char_uuid else char_uuid[:8]
    def handler(sender, data):
        elapsed = time.time() - start_time if start_time else 0
        packets[short].append((elapsed, bytes(data)))
    return handler


async def main():
    global start_time

    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 glasses found!")
        return
    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Using: {device.name}\n")

    async with BleakClient(device) as client:
        # Step 1: Enumerate ALL services and characteristics
        print("=" * 60)
        print("ALL SERVICES AND CHARACTERISTICS")
        print("=" * 60)
        notify_chars = []
        for service in client.services:
            print(f"\nService: {service.uuid}")
            print(f"  Description: {service.description}")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                short = char.uuid.split("72e")[1][:4] if "72e" in char.uuid else char.uuid[:8]
                print(f"  Char 0x{short}: {props}")
                if "notify" in char.properties or "indicate" in char.properties:
                    notify_chars.append(char)

        print(f"\n{'=' * 60}")
        print(f"NOTIFY-CAPABLE CHARACTERISTICS: {len(notify_chars)}")
        print(f"{'=' * 60}")
        for char in notify_chars:
            short = char.uuid.split("72e")[1][:4] if "72e" in char.uuid else char.uuid[:8]
            print(f"  0x{short}: {', '.join(char.properties)}")

        # Step 2: Subscribe to ALL notify characteristics
        print(f"\nSubscribing to all {len(notify_chars)} notify channels...")
        subscribed = []
        for char in notify_chars:
            try:
                await client.start_notify(char.uuid, make_handler(char.uuid))
                short = char.uuid.split("72e")[1][:4] if "72e" in char.uuid else char.uuid[:8]
                subscribed.append(short)
                print(f"  Subscribed: 0x{short}")
            except Exception as e:
                short = char.uuid.split("72e")[1][:4] if "72e" in char.uuid else char.uuid[:8]
                print(f"  FAILED 0x{short}: {e}")

        # Step 3: Auth
        print("\nAuthenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)

        auth_summary = {k: len(v) for k, v in packets.items()}
        print(f"Auth responses: {auth_summary}")

        # Step 4: Record baseline (no Conversate session)
        print(f"\n{'=' * 60}")
        print("PHASE 1: Baseline (5s, no session)")
        print("=" * 60)
        packets.clear()
        start_time = time.time()
        await asyncio.sleep(5.0)
        baseline = {k: len(v) for k, v in packets.items()}
        print(f"Baseline packets: {baseline}")

        # Step 5: Start Conversate session and record
        print(f"\n{'=' * 60}")
        print("PHASE 2: Conversate session active (10s)")
        print("        *** SPEAK INTO YOUR GLASSES ***")
        print("=" * 60)
        packets.clear()
        start_time = time.time()

        seq = 0x08
        msg_id = 0x14

        # Start Conversate session (type=1)
        inner = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)
        session = pb_varint(1, 1) + pb_bytes(2, inner)
        payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
        pkt = build_aa(seq, 0x0B, 0x20, payload)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1

        # Send periodic empty transcriptions to keep session alive
        for i in range(10):
            await asyncio.sleep(1.0)
            elapsed = time.time() - start_time
            total = sum(len(v) for v in packets.values())
            by_chan = {k: len(v) for k, v in packets.items() if v}
            print(f"  [{elapsed:.0f}s] {total} packets: {by_chan}")

            # Keep session alive with empty transcription
            trans = pb_string(1, "") + pb_varint(2, 0)
            payload = pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, trans)
            pkt = build_aa(seq, 0x0B, 0x20, payload)
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            seq += 1; msg_id += 1

        # Step 6: Analysis
        print(f"\n{'=' * 60}")
        print("RESULTS")
        print("=" * 60)
        for chan, pkts in sorted(packets.items()):
            sizes = [len(d) for _, d in pkts]
            total_bytes = sum(sizes)
            unique_sizes = sorted(set(sizes))
            print(f"\n  Channel 0x{chan}:")
            print(f"    Packets: {len(pkts)}")
            print(f"    Total bytes: {total_bytes}")
            print(f"    Sizes: {unique_sizes[:10]}")
            if pkts:
                print(f"    Rate: {len(pkts)/10:.1f} pkt/s")
                print(f"    First packet: {pkts[0][1][:32].hex()}")
                print(f"    Last packet:  {pkts[-1][1][:32].hex()}")

                # Check if data looks like audio
                import numpy as np
                all_bytes = b"".join(d for _, d in pkts)
                arr = np.frombuffer(all_bytes, dtype=np.uint8)
                entropy = 0
                for i in range(256):
                    p = np.sum(arr == i) / len(arr)
                    if p > 0:
                        entropy -= p * np.log2(p)
                print(f"    Entropy: {entropy:.2f} bits/byte")
                mean = np.mean(arr.astype(float))
                print(f"    Mean: {mean:.1f} (128=center)")

        print(f"\n{'=' * 60}")
        print("CHANNELS THAT HAD DATA (excluding 6402 display):")
        for chan, pkts in sorted(packets.items()):
            if chan != "6402" and pkts:
                print(f"  0x{chan}: {len(pkts)} packets, {sum(len(d) for _,d in pkts)} bytes")
                for t, d in pkts[:5]:
                    print(f"    [{t:.1f}s] ({len(d)}b) {d.hex()[:80]}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
