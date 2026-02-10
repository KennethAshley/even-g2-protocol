#!/usr/bin/env python3
"""
Use Even AI skill commands to switch between glasses services.

EvenAIDataPackage on service 0x07-20:
  commandId=6 (SKILL), skillInfo = { skillId = N }

Skills: TELEPROMPT=4, NAVIGATE=5, CONVERSATE=6, QUICKLIST=7

Also tries CTRL command to wake up Even AI first.
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


# --- Even AI messages (service 0x07-20) ---

def build_ai_ctrl(seq, msg_id, status):
    """EvenAIDataPackage: commandId=1 (CTRL), ctrl={status=N}
    status: 1=WAKE_UP, 2=ENTER, 3=EXIT
    """
    ctrl = pb_varint(1, status)
    payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, ctrl)
    return build_aa_packet(seq, 0x07, 0x20, payload)

def build_ai_skill(seq, msg_id, skill_id, param=0, text=""):
    """EvenAIDataPackage: commandId=6 (SKILL), skillInfo={skillId=N}
    Skills: BRIGHTNESS=1, TRANSLATE=2, NOTIFICATION=3, TELEPROMPT=4,
            NAVIGATE=5, CONVERSATE=6, QUICKLIST=7, AUTO_BRIGHTNESS=8
    """
    skill_info = pb_varint(2, skill_id)
    if param: skill_info += pb_varint(3, param)
    if text: skill_info += pb_bytes(4, text.encode('utf-8'))
    payload = pb_varint(1, 6) + pb_varint(2, msg_id) + pb_bytes(8, skill_info)
    return build_aa_packet(seq, 0x07, 0x20, payload)

def build_ai_reply(seq, msg_id, text, stream=1, text_mode=0):
    """EvenAIDataPackage: commandId=5 (REPLY), replyInfo={text=...}"""
    reply = pb_varint(1, 1) + pb_varint(2, stream) + pb_varint(3, text_mode) + pb_bytes(4, text.encode('utf-8'))
    payload = pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, reply)
    return build_aa_packet(seq, 0x07, 0x20, payload)

def build_ai_event(seq, msg_id, event_type):
    """EvenAIDataPackage: commandId=8 (EVENT), event={event=N}
    event: 0=NONE, 1=SCROLL, 2=STREAM_COMPLETE
    """
    event = pb_varint(1, event_type)
    payload = pb_varint(1, 8) + pb_varint(2, msg_id) + pb_bytes(10, event)
    return build_aa_packet(seq, 0x07, 0x20, payload)


SKILLS = {
    1: "BRIGHTNESS",
    2: "TRANSLATE",
    3: "NOTIFICATION",
    4: "TELEPROMPT",
    5: "NAVIGATE",
    6: "CONVERSATE",
    7: "QUICKLIST",
    8: "AUTO_BRIGHTNESS",
}

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
        print("Auth done.\n")

        seq = 0x08
        msg_id = 0x14

        # Step 1: Wake up Even AI
        print("=== CTRL: EVEN_AI_WAKE_UP ===")
        pkt = build_ai_ctrl(seq, msg_id, 1)
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(1.5)

        # Step 2: Enter Even AI
        print("\n=== CTRL: EVEN_AI_ENTER ===")
        pkt = build_ai_ctrl(seq, msg_id, 2)
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(1.5)

        # Step 3: Try AI Reply (streaming text display)
        print("\n=== REPLY: 'Hello from the SDK!' ===")
        pkt = build_ai_reply(seq, msg_id, "Hello from the SDK!")
        print(f"  -> {pkt.hex()}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.5)

        # Mark stream complete
        pkt = build_ai_event(seq, msg_id, 2)  # STREAM_COMPLETE
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(2.0)

        # Step 4: Try skill switching
        for skill_id in [4, 5, 6, 7]:  # TELEPROMPT, NAVIGATE, CONVERSATE, QUICKLIST
            name = SKILLS[skill_id]
            print(f"\n=== SKILL: {name} ({skill_id}) ===")
            pkt = build_ai_skill(seq, msg_id, skill_id)
            print(f"  -> {pkt.hex()}")
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            seq += 1; msg_id += 1
            await asyncio.sleep(3.0)

        # Exit AI
        print("\n=== CTRL: EVEN_AI_EXIT ===")
        pkt = build_ai_ctrl(seq, msg_id, 3)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(1.0)

        print("\nDone. What did you see?")

asyncio.run(main())
