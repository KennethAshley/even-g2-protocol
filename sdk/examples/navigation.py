#!/usr/bin/env python3
"""
Probe navigation service on G2 glasses.

Sends APP_REQUEST_START_UP then APP_SEND_BASIC_INFO with custom HUD data.
Service: 0x08-20 (UI_BACKGROUND_NAVIGATION_ID = 8)
"""
import asyncio
import sys
import time
from bleak import BleakClient, BleakScanner

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)


# --- Packet building ---

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


# --- Navigation messages ---

def build_nav_startup(seq, msg_id):
    """APP_REQUEST_START_UP (cmd=5)"""
    payload = pb_varint(1, 5) + pb_varint(2, msg_id)
    return build_aa_packet(seq, 0x08, 0x20, payload)

def build_nav_basic_info(seq, msg_id, direction_idx=0, distance="", road="",
                          spend_time="", remain_dist="", eta="", speed="", work_method=0):
    """APP_SEND_BASIC_INFO (cmd=7) with basic_info_msg in field 5"""
    info = pb_varint(1, direction_idx)
    if distance: info += pb_string(2, distance)
    if road: info += pb_string(3, road)
    if spend_time: info += pb_string(4, spend_time)
    if remain_dist: info += pb_string(5, remain_dist)
    if eta: info += pb_string(6, eta)
    if speed: info += pb_string(7, speed)
    info += pb_varint(8, work_method)

    payload = pb_varint(1, 7) + pb_varint(2, msg_id) + pb_bytes(5, info)
    return build_aa_packet(seq, 0x08, 0x20, payload)

def build_nav_heartbeat(seq, msg_id):
    """APP_SEND_HEARTBEAT_CMD (cmd=0)"""
    payload = pb_varint(1, 0) + pb_varint(2, msg_id)
    return build_aa_packet(seq, 0x08, 0x20, payload)

def build_nav_exit(seq, msg_id):
    """APP_REQUEST_EXIT (cmd=12)"""
    payload = pb_varint(1, 12) + pb_varint(2, msg_id)
    return build_aa_packet(seq, 0x08, 0x20, payload)


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
        # Notify handler
        def on_notify(sender, data):
            svc_hi = data[6] if len(data) > 7 else 0
            svc_lo = data[7] if len(data) > 7 else 0
            print(f"  <- [0x{svc_hi:02x}-{svc_lo:02x}] {data.hex()}")

        await client.start_notify(CHAR_NOTIFY, on_notify)

        # Auth
        print("Authenticating...")
        for pkt in build_auth():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print("Auth done.\n")

        seq = 0x08
        msg_id = 0x14

        # Step 1: Start navigation
        print("=== Sending APP_REQUEST_START_UP (cmd=5) ===")
        pkt = build_nav_startup(seq, msg_id)
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(2.0)

        # Step 2: Send basic info - custom HUD data
        print("\n=== Sending APP_SEND_BASIC_INFO (cmd=7) ===")
        # directionSignIndex: try values 0-15 to see which icons exist
        # Let's try index 1 (probably a straight arrow)
        pkt = build_nav_basic_info(
            seq, msg_id,
            direction_idx=1,        # direction arrow icon
            distance="0.3 mi",      # distance to next turn
            road="Market St",       # road name
            spend_time="2 min",     # time spent
            remain_dist="1.2 mi",   # remaining distance
            eta="7:35 PM",          # estimated arrival
            speed="25 mph",         # current speed
            work_method=0,
        )
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(2.0)

        # Step 3: Send another update
        print("\n=== Sending updated info ===")
        pkt = build_nav_basic_info(
            seq, msg_id,
            direction_idx=3,        # try a different direction icon
            distance="0.1 mi",
            road="Turn right on 5th Ave",
            spend_time="3 min",
            remain_dist="0.9 mi",
            eta="7:36 PM",
            speed="15 mph",
            work_method=0,
        )
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(3.0)

        # Heartbeat
        print("\n=== Heartbeat ===")
        pkt = build_nav_heartbeat(seq, msg_id)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(2.0)

        # Exit navigation
        print("\n=== Sending APP_REQUEST_EXIT ===")
        pkt = build_nav_exit(seq, msg_id)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(1.0)

        print("\nDone. Did you see navigation on the glasses?")

asyncio.run(main())
