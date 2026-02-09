#!/usr/bin/env python3
"""
Find G2 mic audio - listen after physical tap activation.

Subscribes to ALL channels, then waits for user to TAP the glasses
to activate the mic. Records everything for 15 seconds.
"""

import asyncio
import time
from collections import defaultdict
from bleak import BleakClient, BleakScanner


UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)


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
        if label != "6402":
            svc = ""
            if len(data) >= 8 and data[0] == 0xAA:
                svc = f" svc=0x{data[6]:02X}-{data[7]:02X}"
            print(f"  >>> [{label}] ({len(data)}b){svc}: {data.hex()[:100]}")
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
        # Subscribe to ALL notify channels
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
        start_time = time.time()
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print("Auth done\n")

        packets.clear()
        start_time = time.time()

        print("=" * 60)
        print("READY - TAP YOUR GLASSES NOW, THEN SPEAK!")
        print("Recording all channels for 15 seconds...")
        print("=" * 60)
        print()

        for i in range(15):
            await asyncio.sleep(1.0)
            summary = {}
            for k, v in packets.items():
                summary[k] = len(v)
            print(f"  [{i+1:2d}s] {summary}")

        # Results
        print(f"\n{'=' * 60}")
        print("RESULTS")
        print("=" * 60)

        for chan in sorted(packets.keys()):
            pkts = packets[chan]
            if not pkts:
                continue
            sizes = sorted(set(len(d) for _, d in pkts))
            total = sum(len(d) for _, d in pkts)
            print(f"\n  Channel {chan}: {len(pkts)} packets, {total} bytes")
            print(f"    Unique sizes: {sizes[:15]}")

            if chan != "6402":
                print(f"    ALL packets:")
                for t, d in pkts:
                    svc = ""
                    if len(d) >= 8 and d[0] == 0xAA:
                        svc = f" svc=0x{d[6]:02X}-{d[7]:02X}"
                    print(f"      [{t:5.1f}s] ({len(d):3d}b){svc} {d.hex()}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
