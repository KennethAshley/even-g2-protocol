#!/usr/bin/env python3
"""
Dashboard widget test v3 - Rebuilt payloads with correct msg_ids.

The issue with v2: captured payloads had hardcoded msg_ids that didn't
match our running sequence counter. The glasses likely ignore packets
with out-of-sequence msg_ids.
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
def pb_fixed32(field, value):
    import struct
    return bytes([(field << 3) | 5]) + struct.pack('<f', value)

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
# Payload builders with dynamic msg_id
# ============================================================================

def build_display_config(msg_id):
    """Display Config (0x0E-20) - sets up display regions.
    Decoded from capture: type=2, msg_id, field 4 = display settings with 5 regions."""
    # Display settings with 5 regions (exact values from capture)
    regions = (
        pb_bytes(2, pb_varint(1, 2) + pb_varint(2, 0x4E) + pb_fixed32(3, 2628.0) + pb_fixed32(4, 0.0) + pb_varint(5, 0) + pb_varint(6, 0)) +
        pb_bytes(2, pb_varint(1, 3) + pb_varint(2, 0x0F) + pb_fixed32(3, 2832.0) + pb_fixed32(4, 0.0) + pb_varint(5, 0) + pb_varint(6, 0)) +
        pb_bytes(2, pb_varint(1, 4) + pb_varint(2, 0) + pb_fixed32(3, 2624.0) + pb_fixed32(4, 0.0) + pb_varint(5, 0) + pb_varint(6, 0)) +
        pb_bytes(2, pb_varint(1, 5) + pb_varint(2, 0) + pb_fixed32(3, 2624.0) + pb_fixed32(4, 0.0) + pb_varint(5, 0) + pb_varint(6, 0)) +
        pb_bytes(2, pb_varint(1, 6) + pb_varint(2, 0) + pb_fixed32(3, 2624.0) + pb_fixed32(4, 0.0) + pb_varint(5, 0) + pb_varint(6, 0))
    )
    settings = pb_varint(1, 1) + regions + pb_varint(3, 0)
    return pb_varint(1, 2) + pb_varint(2, msg_id) + pb_bytes(4, settings)


def build_dashboard_enable(msg_id):
    """Service 0x0A-20 - enable dashboard."""
    return pb_varint(1, 0) + pb_varint(2, msg_id)


def build_dashboard_refresh(msg_id):
    """Dashboard Refresh (0x07-20) - type=10."""
    return pb_varint(1, 10) + pb_varint(2, msg_id) + pb_bytes(13, pb_varint(1, 0) + pb_varint(2, 0x20))


def build_screen_mode(msg_id):
    """Service 0x10-20 - set screen mode. type=1, field 3 = {field 1 = 4}."""
    return pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, pb_varint(1, 4))


def build_widget_config(msg_id):
    """Widget Config (0x01-20) - type=2, configures which widgets to show."""
    # Inner config: field 1=4, field 2=3, field 3={1,2,3}, field 4=4, field 5={1,3,2,2}
    inner = (pb_varint(1, 4) + pb_varint(2, 3) +
             pb_bytes(3, bytes([0x01, 0x02, 0x03])) +
             pb_varint(4, 4) +
             pb_bytes(5, bytes([0x01, 0x03, 0x02, 0x02])))
    config = pb_bytes(2, pb_bytes(2, inner))
    return pb_varint(1, 2) + pb_varint(2, msg_id) + pb_bytes(4, config)


def build_calendar_event(msg_id, index, title, location, time_range, day_offset=6):
    """Calendar event widget (0x01-20)."""
    cal_data = (pb_varint(1, 3) + pb_varint(2, index) +
                pb_bytes(3, pb_string(2, title) +
                            pb_string(3, location) +
                            pb_string(4, time_range) +
                            pb_varint(5, day_offset)))
    wrapped = pb_bytes(3, pb_bytes(2, pb_bytes(3, cal_data)))
    return pb_varint(1, 2) + pb_varint(2, msg_id) + pb_bytes(4, wrapped)


def build_display_wake(msg_id):
    """Display Wake (0x04-20) - activates display."""
    settings = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 5) + pb_varint(5, 1)
    return pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, settings)


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
    print(f"  -> [{svc}] seq=0x{seq:02X} msg_id in payload ({len(payload)}b) {label}")
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
        print("=" * 60)
        print("FULL DASHBOARD SEQUENCE (dynamic msg_ids)")
        print("=" * 60)
        t.display_count = 0
        before = len(t.r)

        # 1. Display Config × 2
        payload = build_display_config(msg_id)
        await send(client, seq, 0x0E, 0x20, payload, "Display Config")
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        payload = build_display_config(msg_id)
        await send(client, seq, 0x0E, 0x20, payload, "Display Config (2)")
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        # 2. Dashboard Enable
        payload = build_dashboard_enable(msg_id)
        await send(client, seq, 0x0A, 0x20, payload, "Dashboard Enable")
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        # 3. Dashboard Refresh
        payload = build_dashboard_refresh(msg_id)
        await send(client, seq, 0x07, 0x20, payload, "Dashboard Refresh")
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        # 4. Screen Mode
        payload = build_screen_mode(msg_id)
        await send(client, seq, 0x10, 0x20, payload, "Screen Mode")
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        # 5. Widget Config
        payload = build_widget_config(msg_id)
        await send(client, seq, 0x01, 0x20, payload, "Widget Config")
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        # 6. Calendar Events
        for i, (title, loc, time_r) in enumerate([
            ("Team Standup", "Conference Room A", "09:00-09:30"),
            ("Lunch with Alex", "Downtown Cafe", "12:00-13:00"),
            ("Code Review", "Virtual", "15:00-15:30"),
        ]):
            payload = build_calendar_event(msg_id, i, title, loc, time_r)
            await send(client, seq, 0x01, 0x20, payload, f"Event: {title}")
            seq += 1; msg_id += 1
            await asyncio.sleep(0.15)

        # 7. Display Wake
        payload = build_display_wake(msg_id)
        await send(client, seq, 0x04, 0x20, payload, "DISPLAY WAKE!")
        seq += 1; msg_id += 1
        await asyncio.sleep(1.0)

        print(f"\n  5402 responses: {len(t.r) - before}")
        print(f"  6402 display packets: {t.display_count}")

        print("\nWaiting 8s for display activity...")
        for i in range(8):
            await asyncio.sleep(1.0)
            print(f"  [{i+1}s] 6402={t.display_count}, 5402={len(t.r) - 5}")

        await asyncio.sleep(2.0)
        print(f"\n{'=' * 60}")
        print("Check your glasses for calendar display!")
        print(f"Total: 5402={len(t.r)}, 6402={t.display_count}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
