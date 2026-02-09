#!/usr/bin/env python3
"""
Dashboard widget test v2 - Full captured sequence.

Previous test was missing Display Config (0x0E-20), Display Wake (0x04-20),
and setup services (0x0A-20, 0x10-20). This test replicates the exact
sequence from the Samsung BLE capture.

Capture sequence:
  1. Display Config (0x0E-20) × 2
  2. Service 0x0A-20 (dashboard enable?)
  3. Dashboard Refresh (0x07-20)
  4. Service 0x10-20 (screen mode?)
  5. Widget Config (0x01-20)
  6. Calendar events (0x01-20)
  7. Display Wake (0x04-20)
  8. News content (0x01-20)
  9. Stock widget (0x01-20)
  10. Display Config again (0x0E-20)
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


# ============================================================================
# Exact captured payloads
# ============================================================================

# Display Config (0x0E-20) - 112 bytes, sets up display regions
DISPLAY_CONFIG = bytes.fromhex(
    "08021010226a080112130802104e1d001d45250000000028003000"
    "12130803100f1d006005452500000000280030001212080410001d"
    "0000422500000000280030001212080510001d0000422500000000"
    "280030001212080610001d000042250000000028003000180000"
    "0000001c0000"
)

# Service 0x0A-20 - dashboard enable? (4 bytes)
DASHBOARD_ENABLE = bytes.fromhex("08001014")

# Dashboard Refresh (0x07-20) - 10 bytes
DASHBOARD_REFRESH = bytes.fromhex("080a10166a0408001020")

# Service 0x10-20 - screen mode? (8 bytes)
SCREEN_MODE = bytes.fromhex("080110171a020804")

# Widget Config (0x01-20) - 25 bytes
WIDGET_CONFIG = bytes.fromhex(
    "0802101922131211080410031a0301020320042a0401030202"
)

# Calendar event (0x01-20) - 75 bytes
CALENDAR_EVENT = bytes.fromhex(
    "0802101a22451a4312411a3f080310001a39120e5b43414c454e4441525f"
    "454e545d1a144e6f206c6f636174696f6e2070726f7669646564220b48"
    "483a4d4d2d48483a4d4d2806"
)

# Index/position data (0x01-20) - 28 bytes
WIDGET_INDEX = bytes.fromhex(
    "0802101b22161a140a120a100a1001180220332c0000002f0000002f"
)

# Meeting event (0x01-20) - 66 bytes
MEETING_EVENT = bytes.fromhex(
    "0802101c223c1a3a12381a36080310011a30120e5b4d454554494e475d1a"
    "075b4c4f434154494f4e5d220f546d722048483a4d4d2d48483a4d4d28"
    "06cbae0000002f"
)

# New Year's Day (0x01-20) - 79 bytes
NEW_YEARS_EVENT = bytes.fromhex(
    "0802101d22491a4712451a43080310021a3d120e4e657720596561722773"
    "204461791a144e6f206c6f636174696f6e2070726f7669646564220f54"
    "6d722048483a4d4d2d48483a4d4d280600000008"
)

# Widget clear (0x01-20) - 16 bytes
WIDGET_CLEAR = bytes.fromhex("0802101e220a1a081206120408001000")

# Display Wake (0x04-20) - 14 bytes
DISPLAY_WAKE = bytes.fromhex("080110201a080801100118052801")


class Tracker:
    def __init__(self):
        self.r = []
        self.display_count = 0
    def h(self, label):
        def cb(_, data):
            if label == "6402":
                self.display_count += 1
                return
            svc = ""
            if len(data) >= 8 and data[0] == 0xAA:
                svc = f" svc=0x{data[6]:02X}-{data[7]:02X}"
            print(f"  <- [{label}] ({len(data)}b){svc}: {data.hex()[:60]}")
            self.r.append((label, bytes(data)))
        return cb


async def send(client, seq, svc_hi, svc_lo, payload, label=""):
    pkt = build_aa(seq, svc_hi, svc_lo, payload)
    svc = f"0x{svc_hi:02X}-{svc_lo:02X}"
    print(f"  -> [{svc}] seq=0x{seq:02X} ({len(payload)}b) {label}")
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)


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
        # Full dashboard sequence (matching capture order)
        # ====================================================================
        print("=" * 60)
        print("FULL DASHBOARD SEQUENCE")
        print("=" * 60)
        t.display_count = 0
        before = len(t.r)

        # Step 1: Display Config (0x0E-20) × 2
        await send(client, seq, 0x0E, 0x20, DISPLAY_CONFIG, "Display Config")
        seq += 1
        await asyncio.sleep(0.3)

        await send(client, seq, 0x0E, 0x20, DISPLAY_CONFIG, "Display Config (repeat)")
        seq += 1
        await asyncio.sleep(0.3)

        # Step 2: Dashboard Enable (0x0A-20)
        await send(client, seq, 0x0A, 0x20, DASHBOARD_ENABLE, "Dashboard Enable")
        seq += 1
        await asyncio.sleep(0.3)

        # Step 3: Dashboard Refresh (0x07-20)
        await send(client, seq, 0x07, 0x20, DASHBOARD_REFRESH, "Dashboard Refresh")
        seq += 1
        await asyncio.sleep(0.3)

        # Step 4: Screen Mode (0x10-20)
        await send(client, seq, 0x10, 0x20, SCREEN_MODE, "Screen Mode")
        seq += 1
        await asyncio.sleep(0.3)

        # Step 5: Widget Config (0x01-20)
        await send(client, seq, 0x01, 0x20, WIDGET_CONFIG, "Widget Config")
        seq += 1
        await asyncio.sleep(0.3)

        # Step 6: Calendar Event
        await send(client, seq, 0x01, 0x20, CALENDAR_EVENT, "[CALENDAR_EVENT]")
        seq += 1
        await asyncio.sleep(0.15)

        # Step 7: Widget Index
        await send(client, seq, 0x01, 0x20, WIDGET_INDEX, "Widget Index")
        seq += 1
        await asyncio.sleep(0.15)

        # Step 8: Meeting Event
        await send(client, seq, 0x01, 0x20, MEETING_EVENT, "[MEETING]")
        seq += 1
        await asyncio.sleep(0.15)

        # Step 9: New Year's Day
        await send(client, seq, 0x01, 0x20, NEW_YEARS_EVENT, "New Year's Day")
        seq += 1
        await asyncio.sleep(0.15)

        # Step 10: Widget Clear
        await send(client, seq, 0x01, 0x20, WIDGET_CLEAR, "Widget Clear")
        seq += 1
        await asyncio.sleep(0.3)

        # Step 11: Display Wake (0x04-20)
        await send(client, seq, 0x04, 0x20, DISPLAY_WAKE, "Display Wake!")
        seq += 1
        await asyncio.sleep(1.0)

        print(f"\n  5402 responses: {len(t.r) - before}")
        print(f"  6402 display packets: {t.display_count}")

        # Wait and check for display activity
        print("\nWaiting 5s for display activity...")
        for i in range(5):
            await asyncio.sleep(1.0)
            print(f"  [{i+1}s] 6402 packets: {t.display_count}")

        # ====================================================================
        # Try with custom calendar text
        # ====================================================================
        print(f"\n{'=' * 60}")
        print("CUSTOM CALENDAR EVENT")
        print("=" * 60)
        t.display_count = 0
        before_custom = len(t.r)

        # Build custom calendar event matching captured format
        cal_data = (
            pb_varint(1, 3) + pb_varint(2, 0) +
            pb_bytes(3,
                pb_string(2, "Team Standup") +
                pb_string(3, "Conference Room A") +
                pb_string(4, "09:00-09:30") +
                pb_varint(5, 6)
            )
        )
        event = pb_varint(1, 2) + pb_varint(2, msg_id) + pb_bytes(4, pb_bytes(3, pb_bytes(2, pb_bytes(3, cal_data))))
        msg_id += 1

        await send(client, seq, 0x0E, 0x20, DISPLAY_CONFIG, "Display Config")
        seq += 1
        await asyncio.sleep(0.3)

        await send(client, seq, 0x0A, 0x20, DASHBOARD_ENABLE, "Dashboard Enable")
        seq += 1
        await asyncio.sleep(0.3)

        await send(client, seq, 0x07, 0x20, DASHBOARD_REFRESH, "Dashboard Refresh")
        seq += 1
        await asyncio.sleep(0.3)

        await send(client, seq, 0x10, 0x20, SCREEN_MODE, "Screen Mode")
        seq += 1
        await asyncio.sleep(0.3)

        await send(client, seq, 0x01, 0x20, WIDGET_CONFIG, "Widget Config")
        seq += 1
        await asyncio.sleep(0.3)

        await send(client, seq, 0x01, 0x20, event, "Custom: Team Standup")
        seq += 1
        await asyncio.sleep(0.3)

        await send(client, seq, 0x04, 0x20, DISPLAY_WAKE, "Display Wake!")
        seq += 1
        await asyncio.sleep(1.0)

        print(f"\n  5402 responses: {len(t.r) - before_custom}")
        print(f"  6402 display packets: {t.display_count}")

        print("\nWaiting 5s...")
        for i in range(5):
            await asyncio.sleep(1.0)
            print(f"  [{i+1}s] 6402: {t.display_count}")

        await asyncio.sleep(2.0)

        print(f"\n{'=' * 60}")
        print(f"TOTAL: {len(t.r)} responses on 5402, {t.display_count} on 6402")
        print(f"\nCheck your glasses for calendar/dashboard display!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
