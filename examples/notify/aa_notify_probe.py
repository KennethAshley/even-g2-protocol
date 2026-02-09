#!/usr/bin/env python3
"""
Wrap G1-style notification commands in AA-header packets for G2.

Hypothesis: G2 might process 0x4B notification JSON if wrapped in
the AA-header protocol frame, since it ignores raw UART entirely.
"""

import asyncio
import json
import time
from bleak import BleakClient, BleakScanner

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)
CHAR_DISPLAY_W = UUID_BASE.format(0x6401)
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


def v(fn, val):
    return bytes([(fn << 3) | 0]) + encode_varint(val)


def s(fn, text):
    data = text.encode('utf-8')
    return bytes([(fn << 3) | 2]) + encode_varint(len(data)) + data


def sub(fn, data):
    return bytes([(fn << 3) | 2]) + encode_varint(len(data)) + data


def b(fn, data):
    return bytes([(fn << 3) | 2]) + encode_varint(len(data)) + data


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


class T:
    def __init__(self):
        self.r = []
    def h(self, label):
        def cb(_, data):
            st = ""
            if len(data) >= 2 and data[1] == 0xC9: st = " **SUCCESS**"
            elif len(data) >= 2 and data[1] == 0xCB: st = " **ACK**"
            svc = f"svc=0x{data[6]:02X}{data[7]:02X}" if len(data) >= 8 and data[0] == 0xAA else ""
            print(f"  <- [{label}] ({len(data)}b): {data.hex()[:60]}{'...' if len(data.hex())>60 else ''} {svc}{st}")
            self.r.append((label, bytes(data)))
        return cb


async def main():
    print("Scanning...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2!"); return
    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Using: {device.name}\n")

    t = T()
    async with BleakClient(device) as client:
        await client.start_notify(CHAR_NOTIFY, t.h("5402"))
        await client.start_notify(CHAR_DISPLAY_N, t.h("6402"))
        try:
            await client.start_notify("6e400003-b5a3-f393-e0a9-e50e24dcca9e", t.h("UART"))
        except: pass

        # Auth
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print(f"Auth done ({len(t.r)} responses)\n")

        seq = 0x08
        msg_id = 0x14
        notification_json = json.dumps({
            "ncs_notification": {
                "msg_id": 1,
                "app_identifier": "com.even.test",
                "title": "Test",
                "subtitle": "",
                "message": "Hello from Python!",
                "time_s": int(time.time() * 1000),
                "display_name": "Test"
            }
        }, separators=(',', ':')).encode('utf-8')

        experiments = []

        # --- Experiment 1: 0x4B JSON wrapped in AA with notification service ---
        notif_cmd = bytes([0x4B, 0x01, 0x01, 0x00]) + notification_json
        experiments.append(("0x4B in AA[0x02-20]",
            build_aa(seq, 0x02, 0x20, notif_cmd)))
        seq += 1

        # --- Experiment 2: 0x4B JSON wrapped in AA with unknown service ---
        experiments.append(("0x4B in AA[0x4B-20]",
            build_aa(seq, 0x4B, 0x20, notif_cmd)))
        seq += 1

        # --- Experiment 3: JSON as protobuf string field in notification service ---
        payload = v(1, 1) + v(2, msg_id) + sub(3,
            v(1, 0x1A) + v(2, 1) + b(3, notification_json))
        experiments.append(("JSON in proto field[0x02-20]",
            build_aa(seq, 0x02, 0x20, payload)))
        seq += 1; msg_id += 1

        # --- Experiment 4: NCS notification as protobuf string ---
        payload = v(1, 1) + v(2, msg_id) + s(3, json.dumps({
            "ncs_notification": {
                "msg_id": 1,
                "title": "Test",
                "message": "Hello from Python!",
                "app_identifier": "com.even.test",
                "display_name": "Test",
                "type": "Add"
            }
        }, separators=(',', ':')))
        experiments.append(("NCS string in proto field 3",
            build_aa(seq, 0x02, 0x20, payload)))
        seq += 1; msg_id += 1

        # --- Experiment 5: Notification with ALL possible text fields ---
        notif_data = (
            v(1, 0x1A) + v(2, 1) +
            s(3, "Test") + s(4, "Hello from Python!") +
            s(5, "com.even.test") + s(6, "Test") +
            s(7, "") + v(8, int(time.time()))
        )
        payload = v(1, 1) + v(2, msg_id) + sub(3, notif_data)
        experiments.append(("Extended fields 3-8 [0x02-20]",
            build_aa(seq, 0x02, 0x20, payload)))
        seq += 1; msg_id += 1

        # --- Experiment 6: Type=2 notification (maybe type 2 = text notif) ---
        notif_data = v(1, 0x1A) + v(2, 1) + s(3, "Test") + s(4, "Hello from Python!")
        payload = v(1, 2) + v(2, msg_id) + sub(3, notif_data)
        experiments.append(("Type=2 notification",
            build_aa(seq, 0x02, 0x20, payload)))
        seq += 1; msg_id += 1

        # --- Experiment 7: 0x4B on display channel (0x6401) ---
        experiments.append(("0x4B on 0x6401",
            notif_cmd))  # Raw, not AA-wrapped
        seq += 1

        # --- Experiment 8: Conversate with type=2 (maybe AI response mode) ---
        payload = v(1, 2) + v(2, msg_id) + sub(7, s(1, "Test: Hello from Python!") + v(2, 1))
        experiments.append(("Conversate type=2",
            build_aa(seq, 0x0B, 0x20, payload)))
        seq += 1; msg_id += 1

        # --- Experiment 9: 0x4E (AI result) wrapped in AA ---
        ai_result = bytes([0x4E, 0x01, 0x01, 0x00]) + "Test: Hello from Python!".encode('utf-8')
        experiments.append(("AI result 0x4E in AA[0x0B-20]",
            build_aa(seq, 0x0B, 0x20, ai_result)))
        seq += 1

        # --- Experiment 10: AI result as raw protobuf with screen fields ---
        # From EvenDemoApp: sendResult includes screen_status and new_screen
        ai_payload = (
            v(1, 1) + v(2, msg_id) +
            sub(3, s(1, "Test: Hello from Python!")) +
            v(4, 1) +  # screen_status?
            v(5, 1)    # new_screen?
        )
        experiments.append(("AI result proto [0x0B-20]",
            build_aa(seq, 0x0B, 0x20, ai_payload)))
        seq += 1; msg_id += 1

        # Run all experiments
        print("=" * 60)
        print("RUNNING EXPERIMENTS")
        print("=" * 60)

        initial = len(t.r)
        for name, pkt in experiments:
            before = len(t.r)

            # Determine which char to write to
            if name == "0x4B on 0x6401":
                char = CHAR_DISPLAY_W
            else:
                char = CHAR_WRITE

            print(f"\n  [{name}] -> {char[-4:]} ({len(pkt)}b)")
            try:
                await client.write_gatt_char(char, pkt, response=False)
            except Exception as e:
                print(f"    Error: {e}")
                continue

            await asyncio.sleep(1.5)
            new = len(t.r) - before
            if new > 0:
                print(f"    ** {new} RESPONSE(S)! **")

        # Follow up with sync
        print(f"\n  [Sync trigger]")
        sync = bytes([0x08, 0x0E, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x00])
        await client.write_gatt_char(CHAR_WRITE, build_aa(seq, 0x80, 0x00, sync), response=False)
        await asyncio.sleep(2.0)

        print(f"\n{'=' * 60}")
        print(f"TOTAL: {len(t.r)} responses ({len(t.r) - initial} from experiments)")
        for label, data in t.r[initial:]:
            print(f"  [{label}] {data.hex()[:60]}")

        print("\n  Check glasses for any display!")
        await asyncio.sleep(2.0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
