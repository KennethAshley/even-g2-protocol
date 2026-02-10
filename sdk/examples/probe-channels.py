#!/usr/bin/env python3
"""
Probe Nordic UART Service and unknown channels on G2 glasses.

Subscribes to all notify channels, then sends test probes on NUS and 0x7401.
"""
import asyncio
import time
from bleak import BleakClient, BleakScanner

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"

CHANNELS = {
    "0x0002": UUID_BASE.format(0x0002),
    "0x5402": UUID_BASE.format(0x5402),
    "0x6402": UUID_BASE.format(0x6402),
    "0x7402": UUID_BASE.format(0x7402),
    "NUS_TX": "6e400003-b5a3-f393-e0a9-e50e24dcca9e",
}

WRITE_CHARS = {
    "0x0001": UUID_BASE.format(0x0001),
    "0x5401": UUID_BASE.format(0x5401),
    "0x6401": UUID_BASE.format(0x6401),
    "0x7401": UUID_BASE.format(0x7401),
    "NUS_RX": "6e400002-b5a3-f393-e0a9-e50e24dcca9e",
}

# Auth packets (needed before anything works on 0x5401)
def build_auth_packets():
    from notify_helpers import crc16_ccitt, encode_varint
    def add_crc(packet):
        crc = crc16_ccitt(packet[8:])
        return packet + bytes([crc & 0xFF, (crc >> 8) & 0xFF])

    timestamp = int(time.time())
    ts_varint = encode_varint(timestamp)
    txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])
    packets = []
    packets.append(add_crc(bytes([0xAA, 0x21, 0x01, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x0C, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x02, 0x0A, 0x01, 0x01, 0x80, 0x20,
        0x08, 0x05, 0x10, 0x0E, 0x22, 0x02, 0x08, 0x02])))
    payload = bytes([0x08, 0x80, 0x01, 0x10, 0x0F, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    packets.append(add_crc(bytes([0xAA, 0x21, 0x03, len(payload) + 2, 0x01, 0x01, 0x80, 0x20]) + payload))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x04, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x10, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x05, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x11, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x06, 0x0A, 0x01, 0x01, 0x80, 0x20,
        0x08, 0x05, 0x10, 0x12, 0x22, 0x02, 0x08, 0x01])))
    payload = bytes([0x08, 0x80, 0x01, 0x10, 0x13, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    packets.append(add_crc(bytes([0xAA, 0x21, 0x07, len(payload) + 2, 0x01, 0x01, 0x80, 0x20]) + payload))
    return packets


# Inline the helpers to avoid import issues
def crc16_ccitt(data, init=0xFFFF):
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc

def encode_varint(value):
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)

def add_crc(packet):
    crc = crc16_ccitt(packet[8:])
    return packet + bytes([crc & 0xFF, (crc >> 8) & 0xFF])

def build_auth():
    timestamp = int(time.time())
    ts_varint = encode_varint(timestamp)
    txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])
    packets = []
    packets.append(add_crc(bytes([0xAA, 0x21, 0x01, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x0C, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x02, 0x0A, 0x01, 0x01, 0x80, 0x20,
        0x08, 0x05, 0x10, 0x0E, 0x22, 0x02, 0x08, 0x02])))
    payload = bytes([0x08, 0x80, 0x01, 0x10, 0x0F, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    packets.append(add_crc(bytes([0xAA, 0x21, 0x03, len(payload) + 2, 0x01, 0x01, 0x80, 0x20]) + payload))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x04, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x10, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x05, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x11, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x06, 0x0A, 0x01, 0x01, 0x80, 0x20,
        0x08, 0x05, 0x10, 0x12, 0x22, 0x02, 0x08, 0x01])))
    payload = bytes([0x08, 0x80, 0x01, 0x10, 0x13, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    packets.append(add_crc(bytes([0xAA, 0x21, 0x07, len(payload) + 2, 0x01, 0x01, 0x80, 0x20]) + payload))
    return packets


async def main():
    print("Scanning for G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 found!")
        return

    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Connecting to {device.name}...\n")

    async with BleakClient(device) as client:
        # Subscribe to ALL notify channels
        for name, uuid in CHANNELS.items():
            def make_handler(ch_name):
                def handler(sender, data):
                    try:
                        text = data.decode("utf-8")
                        if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in text):
                            print(f"  [{ch_name}] TEXT: {repr(text)}")
                        else:
                            print(f"  [{ch_name}] {data.hex()}")
                    except:
                        print(f"  [{ch_name}] {data.hex()}")
                return handler
            try:
                await client.start_notify(uuid, make_handler(name))
                print(f"Subscribed to {name}")
            except Exception as e:
                print(f"Failed to subscribe {name}: {e}")

        await asyncio.sleep(0.5)

        # Auth on 0x5401
        print("\n=== Authenticating on 0x5401 ===")
        for pkt in build_auth():
            await client.write_gatt_char(WRITE_CHARS["0x5401"], pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)

        # Probe Nordic UART
        print("\n=== Probing Nordic UART ===")
        nus_probes = [
            b"\r\n",
            b"help\r\n",
            b"AT\r\n",
            b"info\r\n",
            b"version\r\n",
            b"\x03",  # Ctrl+C
            b"?\r\n",
            b"ls\r\n",
        ]
        for probe in nus_probes:
            try:
                print(f"  NUS TX -> {repr(probe)}")
                await client.write_gatt_char(WRITE_CHARS["NUS_RX"], probe, response=False)
                await asyncio.sleep(0.5)
            except Exception as e:
                print(f"  NUS write error: {e}")

        # Try NUS with write-with-response
        print("\n=== NUS with response flag ===")
        for probe in [b"help\r\n", b"AT\r\n"]:
            try:
                print(f"  NUS TX (resp) -> {repr(probe)}")
                await client.write_gatt_char(WRITE_CHARS["NUS_RX"], probe, response=True)
                await asyncio.sleep(0.5)
            except Exception as e:
                print(f"  NUS write error: {e}")

        # Probe 0x7401
        print("\n=== Probing 0x7401 ===")
        probes_7401 = [
            bytes([0x00]),
            bytes([0x01]),
            bytes([0xFF]),
            b"hello",
            bytes([0xAA, 0x21, 0x08, 0x04, 0x01, 0x01, 0x00, 0x00, 0x08, 0x00]),  # minimal AA packet
        ]
        for probe in probes_7401:
            try:
                print(f"  0x7401 -> {probe.hex()}")
                await client.write_gatt_char(WRITE_CHARS["0x7401"], probe, response=False)
                await asyncio.sleep(0.5)
            except Exception as e:
                print(f"  0x7401 write error: {e}")

        # Probe 0x0001
        print("\n=== Probing 0x0001 ===")
        probes_0001 = [
            bytes([0x00]),
            bytes([0x01]),
            b"hello",
        ]
        for probe in probes_0001:
            try:
                print(f"  0x0001 -> {probe.hex()}")
                await client.write_gatt_char(WRITE_CHARS["0x0001"], probe, response=False)
                await asyncio.sleep(0.5)
            except Exception as e:
                print(f"  0x0001 write error: {e}")

        # Wait for any late responses
        print("\n=== Waiting 3s for late responses ===")
        await asyncio.sleep(3.0)
        print("\nDone.")


asyncio.run(main())
