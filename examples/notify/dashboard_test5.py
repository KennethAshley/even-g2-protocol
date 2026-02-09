#!/usr/bin/env python3
"""
Dashboard test v5 - Correct packet ORDER from capture analysis.

Key differences from v4:
  - NO Display Config at the start (capture shows it comes AFTER dashboard data)
  - Exact packet order: Enable -> Refresh -> Screen Mode -> Widget Config ->
    Widget setup -> Calendar entries -> Display Wake
  - Includes Widget #2 and #3 setup packets that v4 skipped
  - Display Config sent only at the END (matching capture)
  - msg_id counter matches capture gaps (20, 22, 23, 25-29, 31, 32)
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
    p.append(add_crc(bytes([0xAA,0x21,0x01,0x0C,0x01,0x01,0x80,0x00,
        0x08,0x04,0x10,0x0C,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x02,0x0A,0x01,0x01,0x80,0x20,
        0x08,0x05,0x10,0x0E,0x22,0x02,0x08,0x02])))
    pl = bytes([0x08,0x80,0x01,0x10,0x0F,0x82,0x08,0x11,0x08]) + ts + bytes([0x10]) + txid
    p.append(add_crc(bytes([0xAA,0x21,0x03,len(pl)+2,0x01,0x01,0x80,0x20]) + pl))
    p.append(add_crc(bytes([0xAA,0x21,0x04,0x0C,0x01,0x01,0x80,0x00,
        0x08,0x04,0x10,0x10,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x05,0x0C,0x01,0x01,0x80,0x00,
        0x08,0x04,0x10,0x11,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x06,0x0A,0x01,0x01,0x80,0x20,
        0x08,0x05,0x10,0x12,0x22,0x02,0x08,0x01])))
    pl = bytes([0x08,0x80,0x01,0x10,0x13,0x82,0x08,0x11,0x08]) + ts + bytes([0x10]) + txid
    p.append(add_crc(bytes([0xAA,0x21,0x07,len(pl)+2,0x01,0x01,0x80,0x20]) + pl))
    return p


def patch_msg_id(payload_hex, new_msg_id):
    """Replace msg_id (field 2) in a captured payload."""
    data = bytes.fromhex(payload_hex)
    idx = data.index(0x10, 1)  # Find field 2 tag after field 1
    old_start = idx + 1
    old_end = old_start
    while data[old_end] & 0x80:
        old_end += 1
    old_end += 1
    new_varint = encode_varint(new_msg_id)
    return data[:old_start] + new_varint + data[old_end:]


# EXACT captured payloads in CORRECT ORDER (from capture analysis)
# Order: Enable -> Refresh -> Screen Mode -> Widget Config -> Widget setup ->
#        Calendar entries -> Display Wake
#        (Display Config comes AFTER, not before!)
DASHBOARD_SEQUENCE = [
    # Step 1: Dashboard Enable
    (0x0A, 0x20, "08001014", "Dashboard Enable"),

    # Step 2: Dashboard Refresh (type=10)
    (0x07, 0x20, "080a10166a0408001020", "Dashboard Refresh"),

    # Step 3: Screen Mode (type=1, f3={f1:4})
    (0x10, 0x20, "080110171a020804", "Screen Mode"),

    # Step 4: Widget Config - declares 3 widgets (calendar=1, news=2, stocks=3)
    (0x01, 0x20,
     "0802101922131211080410031a0301020320042a0401030202",
     "Widget Config (3 widgets)"),

    # Step 5: Widget setup #2 - empty calendar init
    (0x01, 0x20,
     "0802101a220a1a081206120408001000",
     "Widget Setup (calendar init)"),

    # Step 6: Widget setup #3 - layout/color data
    (0x01, 0x20,
     "0802101b22161a140a120a100a1f1001180220330000007300000073",
     "Widget Setup (layout data)"),

    # Step 7: Calendar event 1 - [CALENDAR_EVENT]
    (0x01, 0x20,
     "0802101c22451a4312411a3f080310001a39120e5b43414c454e4441525f4556454e545d1a144e6f206c6f636174696f6e2070726f7669646564220b48483a4d4d2d48483a4d4d28060000",
     "Calendar: [CALENDAR_EVENT]"),

    # Step 8: Calendar event 2 - [MEETING]
    (0x01, 0x20,
     "0802101d223c1a3a12381a36080310011a30120e5b4d454554494e475d1a075b4c4f434154494f4e5d220f546d722048483a4d4d2d48483a4d4d2806cbae0000002f",
     "Calendar: [MEETING]"),

    # Step 9: Calendar event 3 - New Year's Day
    (0x01, 0x20,
     "0802101f22491a4712451a43080310021a3d120e4e657720596561722773204461791a144e6f206c6f636174696f6e2070726f7669646564220f546d722048483a4d4d2d48483a4d4d280600000008",
     "Calendar: New Year's Day"),

    # Step 10: Display Wake - triggers rendering
    (0x04, 0x20,
     "080110201a080801100118052801",
     "DISPLAY WAKE"),
]

# Display Config comes AFTER the dashboard (captured ~20 packets later)
DISPLAY_CONFIG = (0x0E, 0x20,
    "08021033226a080112130802104e1d001d4525000000002800300012130803100f1d006005452500000000280030001212080410001d0000422500000000280030001212080510001d0000422500000000280030001212080610001d00004225000000002800300018000000001c0000",
    "Display Config (post-dashboard)")


class Tracker:
    def __init__(self):
        self.responses = []
        self.display_count = 0

    def handler(self, label):
        def cb(_, data):
            if label == "6402":
                self.display_count += 1
                return
            svc = ""
            if len(data) >= 8 and data[0] == 0xAA:
                svc = f" svc=0x{data[6]:02X}-{data[7]:02X}"
            print(f"  <- [{label}] ({len(data)}b){svc}: {data.hex()[:60]}")
            self.responses.append((label, bytes(data)))
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
        await client.start_notify(CHAR_NOTIFY, t.handler("5402"))
        await client.start_notify(CHAR_DISPLAY_N, t.handler("6402"))

        # Auth
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        auth_responses = len(t.responses)
        print(f"Auth done ({auth_responses} responses)\n")

        seq = 0x08
        msg_id = 0x14

        print("=" * 60)
        print("DASHBOARD ACTIVATION (correct order from capture)")
        print("=" * 60)
        t.display_count = 0

        for svc_hi, svc_lo, payload_hex, label in DASHBOARD_SEQUENCE:
            payload = patch_msg_id(payload_hex, msg_id)
            pkt = build_aa(seq, svc_hi, svc_lo, payload)
            svc = f"0x{svc_hi:02X}-{svc_lo:02X}"
            print(f"  -> [{svc}] seq=0x{seq:02X} mid={msg_id} ({len(payload)}b) {label}")
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            seq += 1
            msg_id += 1
            await asyncio.sleep(0.15)

        new_responses = len(t.responses) - auth_responses
        print(f"\n  After dashboard: 5402={new_responses}, 6402={t.display_count}")

        # Wait and check for display
        print("\nWaiting 5s for display response...")
        for i in range(5):
            await asyncio.sleep(1.0)
            nr = len(t.responses) - auth_responses
            print(f"  [{i+1:2d}s] 5402={nr} 6402={t.display_count}")

        # Now send Display Config (comes AFTER dashboard in capture)
        print("\n" + "=" * 60)
        print("SENDING DISPLAY CONFIG (post-dashboard, matching capture)")
        print("=" * 60)
        svc_hi, svc_lo, payload_hex, label = DISPLAY_CONFIG
        payload = patch_msg_id(payload_hex, msg_id)
        pkt = build_aa(seq, svc_hi, svc_lo, payload)
        print(f"  -> [0x{svc_hi:02X}-{svc_lo:02X}] seq=0x{seq:02X} mid={msg_id} ({len(payload)}b) {label}")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        msg_id += 1

        # Wait again
        print("\nWaiting 10s...")
        for i in range(10):
            await asyncio.sleep(1.0)
            nr = len(t.responses) - auth_responses
            print(f"  [{i+1:2d}s] 5402={nr} 6402={t.display_count}")

        # Show responses
        for label, data in t.responses[auth_responses:]:
            print(f"\n  Response: {data.hex()}")

        print(f"\nCheck glasses for dashboard!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
