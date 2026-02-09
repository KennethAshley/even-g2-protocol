#!/usr/bin/env python3
"""
Dashboard widget test for G2 notification display.

Sends captured dashboard widget payloads (service 0x01-20) and dashboard
refresh commands (service 0x07-20) to test if text appears on glasses.

Key discovery: Service 0x01-20 carries calendar events, news, and stock
data as protobuf-encoded widgets. This is the most active service in the
Samsung capture (64 writes) and the most likely path for notification text.
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


# ============================================================================
# Protobuf helpers for building widget payloads
# ============================================================================

def pb_varint(field, value):
    """Encode a protobuf varint field."""
    return bytes([(field << 3) | 0]) + encode_varint(value)

def pb_bytes(field, data):
    """Encode a protobuf length-delimited field."""
    return bytes([(field << 3) | 2]) + encode_varint(len(data)) + data

def pb_string(field, text):
    """Encode a protobuf string field."""
    return pb_bytes(field, text.encode('utf-8'))


# ============================================================================
# Captured payloads from Samsung BLE traffic (exact bytes)
# ============================================================================

# Widget config: sets up which widgets to show (from capture seq 0x0a, 25 bytes)
WIDGET_CONFIG = bytes.fromhex(
    "0802101922131211080410031a0301020320042a0401030202"
)

# Calendar event: "[CALENDAR_EVENT]" at index 0 (from capture seq 0x10, 75 bytes)
CALENDAR_EVENT = bytes.fromhex(
    "0802101c22451a4312411a3f080310001a39120e5b43414c454e4441525f4556"
    "454e545d1a144e6f206c6f636174696f6e2070726f7669646564220b48483a"
    "4d4d2d48483a4d4d28060000"
)

# Meeting event: "[MEETING]" at index 1 (from capture seq 0x11, 66 bytes)
MEETING_EVENT = bytes.fromhex(
    "0802101d223c1a3a12381a36080310011a30120e5b4d454554494e475d1a07"
    "5b4c4f434154494f4e5d220f546d722048483a4d4d2d48483a4d4d2806cb"
    "ae0000002f"
)

# New Year's Day event at index 2 (from capture seq 0x13, 79 bytes)
NEW_YEARS_EVENT = bytes.fromhex(
    "0802101f22491a4712451a43080310021a3d120e4e657720596561722773"
    "204461791a144e6f206c6f636174696f6e2070726f7669646564220f546d"
    "722048483a4d4d2d48483a4d4d280600000008"
)

# Stock widget: BTCE.XAMS (from capture seq 0x24, 105 bytes)
STOCK_WIDGET = bytes.fromhex(
    "0802103022631a61125f125d080710021a570a09425443452e58414d5312"
    "0025000000002d000000003227425443657463202d20426974636f696e20"
    "45786368616e676520547261646564204372797074 6f4d00000000500059"
    "000000000000000065000000006800"
)

# Dashboard refresh command (from capture - service 0x07-20, 10 bytes)
DASHBOARD_REFRESH = bytes.fromhex("080a10166a0408001020")

# Widget clear/reset (from capture seq 0x0e, 16 bytes)
WIDGET_CLEAR = bytes.fromhex(
    "0802101a220a1a081206120408001000"
)


def build_custom_calendar(msg_id, title, location, time_range, index=0):
    """Build a calendar widget with custom text, matching captured format."""
    # Innermost: the calendar data
    cal_data = (
        pb_string(2, title) +
        pb_string(3, location) +
        pb_string(4, time_range) +
        pb_varint(5, 6)  # day_offset (6 = today?)
    )
    # Nest it: field 3 -> field 3 -> field 2 -> field 3 -> field 4
    inner = pb_varint(1, 3) + pb_varint(2, index) + pb_bytes(3, cal_data)
    level3 = pb_bytes(3, inner)
    level2 = pb_bytes(2, level3)
    level1 = pb_bytes(3, level2)
    container = pb_bytes(4, level1)
    return pb_varint(1, 2) + pb_varint(2, msg_id) + container


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
        # Experiment 1: Widget config (tells glasses which widgets to display)
        # ====================================================================
        print("=" * 60)
        print("EXP 1: Widget configuration (service 0x01-20)")
        print("=" * 60)
        before = len(t.r)
        pkt = build_aa(seq, 0x01, 0x20, WIDGET_CONFIG)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(1.5)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 2: Calendar event widget (exact captured bytes)
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 2: Calendar event [CALENDAR_EVENT] (service 0x01-20)")
        print("=" * 60)
        before = len(t.r)
        pkt = build_aa(seq, 0x01, 0x20, CALENDAR_EVENT)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(1.5)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 3: Meeting event widget (exact captured bytes)
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 3: Meeting event [MEETING] (service 0x01-20)")
        print("=" * 60)
        before = len(t.r)
        pkt = build_aa(seq, 0x01, 0x20, MEETING_EVENT)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(1.5)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 4: New Year's Day event (exact captured bytes)
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 4: New Year's Day event (service 0x01-20)")
        print("=" * 60)
        before = len(t.r)
        pkt = build_aa(seq, 0x01, 0x20, NEW_YEARS_EVENT)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(1.5)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 5: Dashboard refresh (service 0x07-20)
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 5: Dashboard refresh (service 0x07-20)")
        print("=" * 60)
        before = len(t.r)
        pkt = build_aa(seq, 0x07, 0x20, DASHBOARD_REFRESH)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 6: Stock widget (exact captured bytes)
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 6: Stock widget BTCE.XAMS (service 0x01-20)")
        print("=" * 60)
        before = len(t.r)
        pkt = build_aa(seq, 0x01, 0x20, STOCK_WIDGET)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(1.5)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 7: Dashboard refresh again
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 7: Dashboard refresh again (service 0x07-20)")
        print("=" * 60)
        before = len(t.r)
        pkt = build_aa(seq, 0x07, 0x20, DASHBOARD_REFRESH)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 8: Custom calendar with our text
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 8: Custom calendar 'Hello from Python!' (0x01-20)")
        print("=" * 60)
        before = len(t.r)
        custom_payload = build_custom_calendar(
            msg_id, "Hello from Python!", "Test Location", "12:00-13:00", index=0
        )
        msg_id += 1
        pkt = build_aa(seq, 0x01, 0x20, custom_payload)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(1.5)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 9: Dashboard refresh after custom event
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 9: Dashboard refresh (service 0x07-20)")
        print("=" * 60)
        before = len(t.r)
        refresh = pb_varint(1, 10) + pb_varint(2, msg_id) + pb_bytes(13, bytes([0x08, 0x00, 0x10, 0x20]))
        msg_id += 1
        pkt = build_aa(seq, 0x07, 0x20, refresh)
        print(f"  Sending ({len(pkt)}b): {pkt.hex()[:50]}...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(2.0)
        print(f"  Responses: {len(t.r) - before}")

        # ====================================================================
        # Experiment 10: Widget config + all 3 events + dashboard refresh
        # (full sequence as in capture)
        # ====================================================================
        print("\n" + "=" * 60)
        print("EXP 10: Full sequence (config + 3 events + refresh)")
        print("=" * 60)
        before = len(t.r)

        # Config
        pkt = build_aa(seq, 0x01, 0x20, WIDGET_CONFIG)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(0.3)

        # Calendar
        pkt = build_aa(seq, 0x01, 0x20, CALENDAR_EVENT)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(0.15)

        # Meeting
        pkt = build_aa(seq, 0x01, 0x20, MEETING_EVENT)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(0.15)

        # New Year's
        pkt = build_aa(seq, 0x01, 0x20, NEW_YEARS_EVENT)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(0.15)

        # Dashboard refresh
        refresh = pb_varint(1, 10) + pb_varint(2, msg_id) + pb_bytes(13, bytes([0x08, 0x00, 0x10, 0x20]))
        msg_id += 1
        pkt = build_aa(seq, 0x07, 0x20, refresh)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(3.0)
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
        print(f"\nCheck glasses for any display change!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
