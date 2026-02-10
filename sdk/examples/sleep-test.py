#!/usr/bin/env python3
"""
Test sending text to sleeping display.

Waits 20 seconds for display to sleep, then sends text.
Tests whether the display wakes automatically.
"""
import asyncio
import time
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

def build_aa_packet(seq, svc_hi, svc_lo, payload):
    header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, svc_hi, svc_lo])
    return add_crc(header + payload)

def pb_varint(field, value):
    return bytes([(field << 3) | 0]) + encode_varint(value)

def pb_bytes(field, data):
    return bytes([(field << 3) | 2]) + encode_varint(len(data)) + data

def pb_string(field, text):
    return pb_bytes(field, text.encode('utf-8'))

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

def build_conversate_config(seq, msg_id):
    inner_settings = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)
    session = pb_varint(1, 1) + pb_bytes(2, inner_settings)
    payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
    return build_aa_packet(seq, 0x0B, 0x20, payload)

def build_transcription(seq, msg_id, text, is_final=False):
    transcript = pb_string(1, text) + pb_varint(2, 1 if is_final else 0)
    payload = pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, transcript)
    return build_aa_packet(seq, 0x0B, 0x20, payload)

# Display Wake service 0x04-20
def build_display_wake(seq, msg_id):
    payload = pb_varint(1, 1) + pb_varint(2, msg_id)
    return build_aa_packet(seq, 0x04, 0x20, payload)


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
        def on_notify(sender, data):
            svc_hi = data[6] if len(data) > 7 else 0
            svc_lo = data[7] if len(data) > 7 else 0
            print(f"  <- [0x{svc_hi:02x}-{svc_lo:02x}] {data.hex()}")

        await client.start_notify(CHAR_NOTIFY, on_notify)

        print("Authenticating...")
        for pkt in build_auth():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)

        seq = 0x08
        msg_id = 0x14

        # Send initial text so we know it works
        print("\n=== Sending 'Display is AWAKE' ===")
        pkt = build_conversate_config(seq, msg_id)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)
        pkt = build_transcription(seq, msg_id, "", is_final=False)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)
        pkt = build_transcription(seq, msg_id, "Display is AWAKE", is_final=True)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1

        # Wait for display to sleep
        print("\n=== Waiting 20s for display to sleep... ===")
        for i in range(20, 0, -1):
            print(f"  {i}s...", end="\r")
            await asyncio.sleep(1.0)
        print("  Display should be sleeping now.")

        # Test 1: Send text WITHOUT display wake
        print("\n=== TEST 1: Sending text WITHOUT display wake ===")
        pkt = build_conversate_config(seq, msg_id)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)
        pkt = build_transcription(seq, msg_id, "", is_final=False)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)
        pkt = build_transcription(seq, msg_id, "Sent while SLEEPING (no wake)", is_final=True)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        print("  Did the display wake up?")
        await asyncio.sleep(5.0)

        # Wait again
        print("\n=== Waiting 20s for display to sleep again... ===")
        for i in range(20, 0, -1):
            print(f"  {i}s...", end="\r")
            await asyncio.sleep(1.0)

        # Test 2: Send display wake FIRST, then text
        print("\n=== TEST 2: Display Wake (0x04-20) then text ===")
        pkt = build_display_wake(seq, msg_id)
        print(f"  Wake -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(1.0)

        pkt = build_conversate_config(seq, msg_id)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)
        pkt = build_transcription(seq, msg_id, "", is_final=False)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)
        pkt = build_transcription(seq, msg_id, "Sent AFTER display wake!", is_final=True)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        print("  Did the display wake up this time?")
        await asyncio.sleep(5.0)

        print("\nDone.")

asyncio.run(main())
