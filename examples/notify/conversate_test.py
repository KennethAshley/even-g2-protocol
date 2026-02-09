#!/usr/bin/env python3
"""
Conversate/AI service test for G2 text display.

The Conversate service (0x0B-20) sends speech transcription text that
the glasses display in real-time. This test sends custom text through
that path to see if it appears on the glasses.

Protocol (from capture analysis):
  type=1: Session config/start
  type=5: Speech transcription text (field 7 = {text, is_final})
"""

import asyncio
import time
from bleak import BleakClient, BleakScanner

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)
CHAR_DISPLAY_N = UUID_BASE.format(0x6402)


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


def pb_varint(field, value):
    return bytes([(field << 3) | 0]) + encode_varint(value)

def pb_bytes(field, data):
    return bytes([(field << 3) | 2]) + encode_varint(len(data)) + data

def pb_string(field, text):
    return pb_bytes(field, text.encode('utf-8'))


def build_conversate_config(msg_id):
    """Build type=1 Conversate session start (exact captured format)."""
    # field 3 = {field 1=1, field 2={field 1=1, field 2=1, field 3=1, field 4=1}}
    inner_settings = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)
    session = pb_varint(1, 1) + pb_bytes(2, inner_settings)
    return pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)


def build_transcription(msg_id, text, is_final=False):
    """Build type=5 speech transcription packet."""
    # field 7 = {field 1 = text, field 2 = is_final}
    transcript = pb_string(1, text) + pb_varint(2, 1 if is_final else 0)
    return pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, transcript)


# Exact captured packets for reference
CAPTURED_CONFIG = bytes.fromhex("080110351a0c080112080801100118012001")
CAPTURED_FINAL = bytes.fromhex(
    "080510173a1b0a1749206c6f76652044656e6f6e207265636569766572732e1001"
)


class Tracker:
    def __init__(self):
        self.r = []
    def h(self, label):
        def cb(_, data):
            st = ""
            svc = ""
            if len(data) >= 2:
                if data[1] == 0xC9: st = " **SUCCESS**"
                elif data[1] == 0xCB: st = " **ACK**"
            if len(data) >= 8 and data[0] == 0xAA:
                svc = f" svc=0x{data[6]:02X}-{data[7]:02X}"
            print(f"  <- [{label}] ({len(data)}b): {data.hex()[:60]}{svc}{st}")
            self.r.append((label, bytes(data)))
        return cb


async def main():
    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 glasses found!")
        return
    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Using: {device.name}\n")

    t = Tracker()
    async with BleakClient(device) as client:
        await client.start_notify(CHAR_NOTIFY, t.h("5402"))
        await client.start_notify(CHAR_DISPLAY_N, t.h("6402"))

        # Auth
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print(f"Auth done ({len(t.r)} responses)\n")

        seq = 0x08
        msg_id = 0x14

        # ====================================================================
        # Experiment 1: Exact captured config + transcription
        # ====================================================================
        print("=" * 60)
        print("EXP 1: Captured config + 'I love Denon receivers.'")
        print("=" * 60)
        before = len(t.r)

        pkt = build_aa(seq, 0x0B, 0x20, CAPTURED_CONFIG)
        print(f"  Config: {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(0.5)

        pkt = build_aa(seq, 0x0B, 0x20, CAPTURED_FINAL)
        print(f"  Text: {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 2: Config + progressive transcription
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 2: Config + progressive 'Hello from Python!'")
        print("=" * 60)
        before = len(t.r)

        # Start session
        config = build_conversate_config(msg_id)
        pkt = build_aa(seq, 0x0B, 0x20, config)
        print(f"  Config ({len(pkt)}b)")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.5)

        # Progressive transcription (simulating speech-to-text)
        progressive = ["H", "He", "Hell", "Hello", "Hello from",
                        "Hello from Py", "Hello from Python",
                        "Hello from Python!"]
        for i, text in enumerate(progressive):
            is_final = (i == len(progressive) - 1)
            trans = build_transcription(msg_id, text, is_final)
            pkt = build_aa(seq, 0x0B, 0x20, trans)
            print(f"  Trans: \"{text}\" {'[FINAL]' if is_final else ''}")
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            seq += 1; msg_id += 1
            await asyncio.sleep(0.3)

        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 3: Direct transcription without config
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 3: Direct transcription 'Test notification!'")
        print("=" * 60)
        before = len(t.r)

        trans = build_transcription(msg_id, "Test notification!", is_final=True)
        pkt = build_aa(seq, 0x0B, 0x20, trans)
        print(f"  Direct ({len(pkt)}b)")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 4: Exact captured sequence (config + empty + progressive)
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 4: Full captured sequence (config -> empty -> text)")
        print("=" * 60)
        before = len(t.r)

        # Config
        config = build_conversate_config(msg_id)
        pkt = build_aa(seq, 0x0B, 0x20, config)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        # Empty transcription (like capture's seq 0x08 - start of listening)
        trans = build_transcription(msg_id, "", is_final=False)
        pkt = build_aa(seq, 0x0B, 0x20, trans)
        print(f"  Empty start")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.5)

        # Progressive
        for text in ["G", "G2", "G2 not", "G2 notification",
                      "G2 notification test", "G2 notification test."]:
            is_final = text.endswith(".")
            trans = build_transcription(msg_id, text, is_final)
            pkt = build_aa(seq, 0x0B, 0x20, trans)
            print(f"  \"{text}\" {'[FINAL]' if is_final else ''}")
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            seq += 1; msg_id += 1
            await asyncio.sleep(0.4)

        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 5: Type=2 AI response (field 3 with text)
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 5: Type=2 AI response with text field")
        print("=" * 60)
        before = len(t.r)

        # Try type=2 with text in field 3 (AI result)
        ai_text = pb_string(1, "This is a test AI response displayed on G2 glasses.")
        payload = pb_varint(1, 2) + pb_varint(2, msg_id) + pb_bytes(3, ai_text)
        pkt = build_aa(seq, 0x0B, 0x20, payload)
        print(f"  AI response ({len(pkt)}b)")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 6: Type=2 AI response with screen_status fields
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 6: Type=2 AI response + screen fields")
        print("=" * 60)
        before = len(t.r)

        ai_text = pb_string(1, "Hello from Python!")
        payload = (pb_varint(1, 2) + pb_varint(2, msg_id) +
                   pb_bytes(3, ai_text) +
                   pb_varint(4, 1) +   # screen_status
                   pb_varint(5, 1))    # new_screen
        pkt = build_aa(seq, 0x0B, 0x20, payload)
        print(f"  AI+screen ({len(pkt)}b)")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # Final wait
        await asyncio.sleep(3.0)

        print(f"\n{'=' * 60}")
        print(f"RESULTS: {len(t.r)} total responses")
        for label, data in t.r:
            svc = ""
            if len(data) >= 8 and data[0] == 0xAA:
                svc = f" svc=0x{data[6]:02X}-{data[7]:02X}"
            print(f"  [{label}] {data.hex()[:60]}{svc}")
        print(f"\nCheck glasses for any text display!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
