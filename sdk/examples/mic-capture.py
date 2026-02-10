#!/usr/bin/env python3
"""
Attempt to capture audio from G2 glasses microphones.

Opens audio pipe and transcribe session, monitors all BLE channels
for incoming audio data.
"""
import asyncio
import time
from bleak import BleakClient, BleakScanner

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)

ALL_NOTIFY = {
    "0x0002": UUID_BASE.format(0x0002),
    "0x5402": UUID_BASE.format(0x5402),
    "0x6402": UUID_BASE.format(0x6402),
    "0x7402": UUID_BASE.format(0x7402),
    "NUS_TX": "6e400003-b5a3-f393-e0a9-e50e24dcca9e",
}

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
    return encode_varint((field << 3) | 0) + encode_varint(value)

def pb_bytes(field, data):
    return encode_varint((field << 3) | 2) + encode_varint(len(data)) + data

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

    total_bytes = {}

    async with BleakClient(device) as client:
        # Subscribe to ALL channels
        for name, uuid in ALL_NOTIFY.items():
            def make_handler(ch_name):
                def handler(sender, data):
                    total_bytes[ch_name] = total_bytes.get(ch_name, 0) + len(data)
                    if ch_name == "0x5402" and len(data) > 8:
                        svc_hi = data[6]
                        svc_lo = data[7]
                        print(f"  [{ch_name}] {len(data)}B svc=0x{svc_hi:02x}-{svc_lo:02x} {data[:20].hex()}...")
                    else:
                        print(f"  [{ch_name}] {len(data)}B {data[:30].hex()}{'...' if len(data) > 30 else ''}")
                return handler
            try:
                await client.start_notify(uuid, make_handler(name))
                print(f"Subscribed to {name}")
            except Exception as e:
                print(f"Failed {name}: {e}")

        await asyncio.sleep(0.5)

        # Auth
        print("\nAuthenticating...")
        for pkt in build_auth():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print("Auth done.\n")

        seq = 0x08
        msg_id = 0x14

        # Method 1: AudControl OPEN on 0x80-20
        # DevCfgDataPackage: commandId=129 (AUD_CONTROL), audControl={cmd=1 (OPEN)}
        print("=== Method 1: AudControl OPEN (0x80-20, cmd=129) ===")
        aud_ctrl = pb_varint(1, 1)  # cmd = AUD_CMD_OPEN
        # commandId=129 is encoded as varint: 0x81 0x01
        payload = pb_varint(1, 129) + pb_varint(2, msg_id) + pb_bytes(129, aud_ctrl)
        pkt = build_aa_packet(seq, 0x80, 0x20, payload)
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        print("  Listening 5s for audio data...")
        await asyncio.sleep(5.0)

        # Close audio
        aud_ctrl = pb_varint(1, 2)  # cmd = AUD_CMD_CLOSE
        payload = pb_varint(1, 129) + pb_varint(2, msg_id) + pb_bytes(129, aud_ctrl)
        pkt = build_aa_packet(seq, 0x80, 0x20, payload)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(1.0)

        # Method 2: Transcribe OPEN on 0x0A-20
        print("\n=== Method 2: Transcribe OPEN (0x0A-20) ===")
        # TranscribeDataPackage: commandId=1 (TRANSCRIBE_CTRL), ctrl={cmd=1 (OPEN)}
        ctrl = pb_varint(1, 1)  # cmd = OPEN
        payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, ctrl)
        pkt = build_aa_packet(seq, 0x0A, 0x20, payload)
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        print("  Listening 10s — speak into the glasses mic...")
        await asyncio.sleep(10.0)

        # Close transcribe
        ctrl = pb_varint(1, 2)  # cmd = CLOSE
        payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, ctrl)
        pkt = build_aa_packet(seq, 0x0A, 0x20, payload)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(1.0)

        # Method 3: Conversate START with useAudio=1 on 0x0B-20
        print("\n=== Method 3: Conversate START with useAudio=1 (0x0B-20) ===")
        settings = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)  # useAudio=1
        ctrl = pb_varint(1, 1) + pb_bytes(2, settings)  # cmd=START
        payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, ctrl)
        pkt = build_aa_packet(seq, 0x0B, 0x20, payload)
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        print("  Listening 10s — speak into the glasses mic...")
        await asyncio.sleep(10.0)

        # Close conversate
        ctrl = pb_varint(1, 2)  # cmd=CLOSE
        payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, ctrl)
        pkt = build_aa_packet(seq, 0x0B, 0x20, payload)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(1.0)

        print(f"\n=== Total bytes received per channel ===")
        for ch, count in sorted(total_bytes.items()):
            print(f"  {ch}: {count} bytes")

        print("\nDone.")

asyncio.run(main())
