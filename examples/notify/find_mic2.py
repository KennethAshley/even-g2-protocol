#!/usr/bin/env python3
"""
Find G2 mic audio - try different activation methods.

Experiment 1: Start Conversate session, DON'T send transcriptions, just listen
Experiment 2: Try writing to unexplored channels (0x0001, 0x7401, Nordic UART)
Experiment 3: Try different Conversate types (3, 4, 6, 7, 8)
"""

import asyncio
import time
from collections import defaultdict
from bleak import BleakClient, BleakScanner


UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)
CHAR_WRITE_0001 = UUID_BASE.format(0x0001)
CHAR_WRITE_7401 = UUID_BASE.format(0x7401)
UART_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"


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


packets = defaultdict(list)
start_time = None

def make_handler(label):
    def handler(sender, data):
        elapsed = time.time() - start_time if start_time else 0
        packets[label].append((elapsed, bytes(data)))
        # Print non-6402 data immediately
        if label != "6402":
            print(f"  *** [{label}] ({len(data)}b): {data.hex()[:80]}")
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
        # Subscribe to all notify channels
        for uuid, label in [
            (UUID_BASE.format(0x0002), "0002"),
            (UUID_BASE.format(0x5402), "5402"),
            (UUID_BASE.format(0x6402), "6402"),
            (UUID_BASE.format(0x7402), "7402"),
            ("6e400003-b5a3-f393-e0a9-e50e24dcca9e", "UART"),
        ]:
            try:
                await client.start_notify(uuid, make_handler(label))
            except Exception as e:
                print(f"  Failed {label}: {e}")

        # Auth
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print(f"Auth done\n")

        seq = 0x08
        msg_id = 0x14

        # ================================================================
        # EXP 1: Conversate session, NO transcriptions - just listen
        # ================================================================
        print("=" * 60)
        print("EXP 1: Conversate session start, then SILENT (5s)")
        print("       *** SPEAK INTO GLASSES ***")
        print("=" * 60)
        packets.clear()
        start_time = time.time()

        inner = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)
        session = pb_varint(1, 1) + pb_bytes(2, inner)
        payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
        pkt = build_aa(seq, 0x0B, 0x20, payload)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1

        for i in range(5):
            await asyncio.sleep(1.0)
            non6402 = {k: len(v) for k, v in packets.items() if k != "6402"}
            n6402 = len(packets.get("6402", []))
            print(f"  [{i+1}s] 6402={n6402} other={non6402}")

        # ================================================================
        # EXP 2: Write to 0x0001 (unknown service)
        # ================================================================
        print(f"\n{'=' * 60}")
        print("EXP 2: Write to 0x0001 characteristic")
        print("=" * 60)
        packets.clear()
        start_time = time.time()
        try:
            # Try a simple ping-like write
            await client.write_gatt_char(CHAR_WRITE_0001, bytes([0x01]), response=False)
            print("  Wrote 0x01 to 0x0001")
            await asyncio.sleep(2.0)
            non6402 = {k: len(v) for k, v in packets.items() if k != "6402"}
            print(f"  Responses: {non6402}")
        except Exception as e:
            print(f"  Error: {e}")

        # ================================================================
        # EXP 3: Write to 0x7401
        # ================================================================
        print(f"\n{'=' * 60}")
        print("EXP 3: Write to 0x7401 characteristic")
        print("=" * 60)
        packets.clear()
        start_time = time.time()
        try:
            await client.write_gatt_char(CHAR_WRITE_7401, bytes([0x01]), response=False)
            print("  Wrote 0x01 to 0x7401")
            await asyncio.sleep(2.0)
            non6402 = {k: len(v) for k, v in packets.items() if k != "6402"}
            print(f"  Responses: {non6402}")
        except Exception as e:
            print(f"  Error: {e}")

        # ================================================================
        # EXP 4: Write to Nordic UART TX
        # ================================================================
        print(f"\n{'=' * 60}")
        print("EXP 4: Write to Nordic UART TX")
        print("=" * 60)
        packets.clear()
        start_time = time.time()
        try:
            await client.write_gatt_char(UART_TX, b"AT\r\n", response=False)
            print("  Wrote 'AT\\r\\n' to UART TX")
            await asyncio.sleep(2.0)
            non6402 = {k: len(v) for k, v in packets.items() if k != "6402"}
            print(f"  Responses: {non6402}")
        except Exception as e:
            print(f"  Error: {e}")

        # ================================================================
        # EXP 5: Try Conversate types 3, 4, 6, 7, 8
        # ================================================================
        print(f"\n{'=' * 60}")
        print("EXP 5: Different Conversate types (3,4,6,7,8)")
        print("       *** SPEAK INTO GLASSES ***")
        print("=" * 60)

        for conv_type in [3, 4, 6, 7, 8]:
            packets.clear()
            start_time = time.time()
            print(f"\n  Type={conv_type}:")

            payload = pb_varint(1, conv_type) + pb_varint(2, msg_id)
            pkt = build_aa(seq, 0x0B, 0x20, payload)
            try:
                await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
                seq += 1; msg_id += 1
                await asyncio.sleep(3.0)
                non6402 = {k: len(v) for k, v in packets.items() if k != "6402"}
                n6402 = len(packets.get("6402", []))
                print(f"    6402={n6402} other={non6402}")
                # Show any 5402 responses
                for t, d in packets.get("5402", []):
                    print(f"    [5402] ({len(d)}b): {d.hex()[:80]}")
            except Exception as e:
                print(f"    Error: {e}")

        # ================================================================
        # EXP 6: Try Conversate type=1 with different inner settings
        # Maybe field values 0 instead of 1 = "send me audio"
        # ================================================================
        print(f"\n{'=' * 60}")
        print("EXP 6: Conversate type=1 with settings={0,0,0,0}")
        print("       *** SPEAK INTO GLASSES ***")
        print("=" * 60)
        packets.clear()
        start_time = time.time()

        inner = pb_varint(1, 0) + pb_varint(2, 0) + pb_varint(3, 0) + pb_varint(4, 0)
        session = pb_varint(1, 1) + pb_bytes(2, inner)
        payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
        pkt = build_aa(seq, 0x0B, 0x20, payload)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1

        for i in range(5):
            await asyncio.sleep(1.0)
            non6402 = {k: len(v) for k, v in packets.items() if k != "6402"}
            n6402 = len(packets.get("6402", []))
            print(f"  [{i+1}s] 6402={n6402} other={non6402}")
            for t, d in packets.get("5402", []):
                print(f"    [5402] ({len(d)}b): {d.hex()[:80]}")

        # ================================================================
        # EXP 7: Try service 0x0C-20 and 0x0D-20 (adjacent to 0x0B-20)
        # ================================================================
        print(f"\n{'=' * 60}")
        print("EXP 7: Adjacent services 0x0C-20, 0x0D-20")
        print("=" * 60)

        for svc_hi in [0x0C, 0x0D, 0x09, 0x0A]:
            packets.clear()
            start_time = time.time()
            print(f"\n  Service 0x{svc_hi:02X}-20:")

            payload = pb_varint(1, 1) + pb_varint(2, msg_id)
            pkt = build_aa(seq, svc_hi, 0x20, payload)
            try:
                await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
                seq += 1; msg_id += 1
                await asyncio.sleep(2.0)
                non6402 = {k: len(v) for k, v in packets.items() if k != "6402"}
                n6402 = len(packets.get("6402", []))
                print(f"    6402={n6402} other={non6402}")
                for t, d in packets.get("5402", []):
                    print(f"    [5402] ({len(d)}b): {d.hex()[:80]}")
            except Exception as e:
                print(f"    Error: {e}")

        print(f"\n{'=' * 60}")
        print("DONE")
        print("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
