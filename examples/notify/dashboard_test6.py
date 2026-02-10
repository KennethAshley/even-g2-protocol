#!/usr/bin/env python3
"""
Dashboard test v6 - Full app initialization sequence from capture analysis.

Key insight: The Even Connect app sends initialization packets for MULTIPLE
services (Transcribe, EvenAI, Onboarding, Notification, Settings, ModuleConfigure)
before/alongside Dashboard data. Previous tests only sent Dashboard packets.

This test replicates the EXACT captured initialization sequence:
  1. Auth handshake (7 packets)
  2. Transcribe init (service 0x0A) - {magicRandom: 20}
  3. EvenAI CONFIG (service 0x07) - {commandId:CONFIG, config{streamSpeed:32}}
  4. Onboarding FINISH (service 0x10) - {commandId:CONFIG, config{processId:FINISH}}
  5. Dashboard display settings (service 0x01) - DashboardReceiveFromApp
  6. Dashboard widget data (service 0x01) - calendar events
  7. Notification control (service 0x04) - enable notifications
  8. Settings request (service 0x09) - request basic settings
  9. Module Configure (service 0x20) - language + dashboard auto-close
"""

import asyncio
import sys
import time
import os

from bleak import BleakClient, BleakScanner

# Add protobuf path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "pbgenerated", "g2"))

from dashboard_pb2 import DashboardDataPackage
from transcribe_pb2 import TranscribeDataPackage
from even_ai_pb2 import EvenAIDataPackage
from onboarding_pb2 import OnboardingDataPackage
from notification_pb2 import NotificationDataPackage
from g2_setting_pb2 import G2SettingPackage
from module_configure_pb2 import module_configure_main_msg_ctx


UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)
CHAR_DISPLAY_N = UUID_BASE.format(0x6402)


# =============================================================================
# Transport layer
# =============================================================================

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


def build_aa(seq, service_id, status, payload):
    """Build an AA-header packet.

    Args:
        seq: Sequence number
        service_id: Single-byte service ID (e.g. 0x01 for dashboard)
        status: Status byte (0x20 = reserveFlag=True, 0x00 = plain)
        payload: Protobuf payload bytes
    """
    header = bytes([
        0xAA,           # Magic
        0x21,           # src=1, dst=2 (app→glasses)
        seq & 0xFF,     # Sequence
        len(payload) + 2,  # Payload length + CRC
        0x01,           # packetTotalNum
        0x01,           # packetSerialNum
        service_id,     # Service ID
        status,         # Status byte
    ])
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


# =============================================================================
# Protobuf message builders
# =============================================================================

class MagicCounter:
    """Track magicRandom values (matches capture behavior)."""
    def __init__(self, start=20):
        self.value = start

    def next(self):
        v = self.value
        self.value += 1
        return v


def pb_varint(field, value):
    tag = bytes([(field << 3) | 0])
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return tag + bytes(result)


def pb_bytes(field, data):
    tag = bytes([(field << 3) | 2])
    result = []
    ln = len(data)
    while ln > 0x7F:
        result.append((ln & 0x7F) | 0x80)
        ln >>= 7
    result.append(ln & 0x7F)
    return tag + bytes(result) + data


def build_transcribe_init(magic):
    """Transcribe service init - captured as first post-auth packet.
    Capture: 08 00 10 14 (explicitly includes commandId=0)
    """
    return pb_varint(1, 0) + pb_varint(2, magic)


def build_evenai_config(magic):
    """EvenAI CONFIG with streamSpeed=32.
    Capture: 08 0a 10 16 6a 04 08 00 10 20
    (config has explicit voiceSwitch=0)
    """
    config = pb_varint(1, 0) + pb_varint(2, 32)  # voiceSwitch=0, streamSpeed=32
    return pb_varint(1, 10) + pb_varint(2, magic) + pb_bytes(13, config)


def build_onboarding_finish(magic):
    """Onboarding FINISH - signals app initialization complete.
    Capture: 08 01 10 17 1a 02 08 04
    """
    msg = OnboardingDataPackage()
    msg.commandId = 1  # CONFIG
    msg.magicRandom = magic
    msg.config.processId = 4  # FINISH
    return msg.SerializeToString()


def build_dashboard_display_settings(magic):
    """Dashboard display settings - sets up widget layout."""
    msg = DashboardDataPackage()
    msg.commandId = 2  # Dashboard_Receive
    msg.magicRandom = magic
    dr = msg.dashboardReceive
    dr.packageId = 0  # Will be set later
    ds = dr.bashboardDisplaySetting
    ds.displayMode = 4
    ds.statusDisplayCount = 3
    ds.statusDisplayOrder.append(1)  # WEATHER
    ds.statusDisplayOrder.append(2)  # MESSAGE
    ds.statusDisplayOrder.append(3)  # Power
    ds.widgetDisplayCount = 4
    ds.widgetDisplayOrder.append(1)  # NEWS
    ds.widgetDisplayOrder.append(3)  # SCHEDULE
    ds.widgetDisplayOrder.append(2)  # STOCK
    ds.widgetDisplayOrder.append(2)  # STOCK
    return msg.SerializeToString()


def build_dashboard_schedule(magic, schedule_id, title, location, time_str):
    """Dashboard calendar event."""
    msg = DashboardDataPackage()
    msg.commandId = 2  # Dashboard_Receive
    msg.magicRandom = magic
    dr = msg.dashboardReceive
    wc = dr.bashboardConfig.widgetComponents
    sw = wc.schedule
    sw.scheduleTotal = 3
    sw.scheduleNum = schedule_id
    s = sw.schedule
    s.scheduleId = 3
    s.title = title
    s.location = location
    s.time = time_str
    s.endTimestamp = 0
    return msg.SerializeToString()


def build_dashboard_stock_init(magic):
    """Dashboard stock widget init (empty)."""
    msg = DashboardDataPackage()
    msg.commandId = 2  # Dashboard_Receive
    msg.magicRandom = magic
    dr = msg.dashboardReceive
    # Empty stock widget
    wc = dr.bashboardConfig.widgetComponents
    wc.stock.CopyFrom(DashboardDataPackage().dashboardReceive.bashboardConfig.widgetComponents.stock)
    return msg.SerializeToString()


def build_notification_ctrl(magic):
    """Notification control - enable notifications."""
    msg = NotificationDataPackage()
    msg.commandId = 1  # NOTIFICATION_CTRL
    msg.magicRandom = magic
    msg.ctrl.notifEnable = 1
    msg.ctrl.autoDispEnable = 1
    msg.ctrl.dispTime = 5
    msg.ctrl.avoidDisturbEnable = 1
    return msg.SerializeToString()


def build_settings_request(magic):
    """Request basic device settings."""
    msg = G2SettingPackage()
    msg.commandId = 2  # DeviceReceiveRequest
    msg.magicRandom = magic
    msg.deviceReceiveRequestFromApp.settingInfoType = 1  # APP_REQUIRE_BASIC_SETTING
    return msg.SerializeToString()


def build_module_configure_language(magic):
    """Module configure - system general settings (language=0).
    Capture: 08 00 10 26 1a 02 08 00
    (explicit cmd=0 and languageIndex=0)
    """
    inner = pb_varint(1, 0)  # languageIndex=0
    return pb_varint(1, 0) + pb_varint(2, magic) + pb_bytes(3, inner)


def build_module_configure_dashboard_autoclose(magic):
    """Module configure - inquire dashboard auto-close value.
    Capture: 08 01 10 27 22 00
    (empty DashboardGeneralSetting)
    """
    return pb_varint(1, 1) + pb_varint(2, magic) + pb_bytes(4, b'')


# =============================================================================
# Main
# =============================================================================

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
                svc_id = data[6]
                status = data[7]
                svc = f" svc=0x{svc_id:02X} st=0x{status:02X}"
            print(f"  <- [{label}] ({len(data)}b){svc}: {data.hex()[:80]}")
            self.responses.append((label, bytes(data)))
        return cb


async def send(client, seq, service_id, status, payload, label):
    """Send a packet and print debug info."""
    pkt = build_aa(seq, service_id, status, payload)
    print(f"  -> [0x{service_id:02X}] seq=0x{seq:02X} ({len(payload)}b) {label}")
    print(f"     payload: {payload.hex()[:80]}")
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    return seq + 1


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
        print("=" * 60)
        print("PHASE 1: Authentication")
        print("=" * 60)
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        auth_responses = len(t.responses)
        print(f"Auth done ({auth_responses} responses)\n")

        seq = 0x08
        magic = MagicCounter(20)

        # Phase 2: Service initialization (matches capture exactly)
        print("=" * 60)
        print("PHASE 2: Service initialization")
        print("=" * 60)

        # Transcribe init
        seq = await send(client, seq, 0x0A, 0x20,
                        build_transcribe_init(magic.next()),
                        "Transcribe init")
        await asyncio.sleep(0.15)

        # Skip magic 21 (gap in capture)
        magic.next()

        # EvenAI CONFIG
        seq = await send(client, seq, 0x07, 0x20,
                        build_evenai_config(magic.next()),
                        "EvenAI CONFIG (streamSpeed=32)")
        await asyncio.sleep(0.15)

        # Onboarding FINISH
        seq = await send(client, seq, 0x10, 0x20,
                        build_onboarding_finish(magic.next()),
                        "Onboarding FINISH")
        await asyncio.sleep(0.15)

        # Skip magic 24 (gap in capture)
        magic.next()

        init_responses = len(t.responses) - auth_responses
        print(f"\nInit done ({init_responses} new responses)\n")

        # Phase 3: Dashboard data
        print("=" * 60)
        print("PHASE 3: Dashboard data")
        print("=" * 60)

        # Display settings
        seq = await send(client, seq, 0x01, 0x20,
                        build_dashboard_display_settings(magic.next()),
                        "Dashboard display settings")
        await asyncio.sleep(0.15)

        # Stock init (empty)
        seq = await send(client, seq, 0x01, 0x20,
                        build_dashboard_stock_init(magic.next()),
                        "Stock widget init (empty)")
        await asyncio.sleep(0.15)

        # Calendar events
        events = [
            ("Team Standup", "Zoom", "10:00 AM - 10:30 AM"),
            ("Lunch", "Cafe", "12:30 PM - 1:30 PM"),
            ("Code Review", "GitHub", "3:00 PM - 4:00 PM"),
        ]
        for i, (title, loc, time_str) in enumerate(events):
            seq = await send(client, seq, 0x01, 0x20,
                            build_dashboard_schedule(magic.next(), i, title, loc, time_str),
                            f"Calendar: {title}")
            await asyncio.sleep(0.15)

        dash_responses = len(t.responses) - auth_responses - init_responses
        print(f"\nDashboard data done ({dash_responses} new responses)\n")

        # Phase 4: Post-dashboard services
        print("=" * 60)
        print("PHASE 4: Post-dashboard services")
        print("=" * 60)

        # Notification control
        seq = await send(client, seq, 0x04, 0x20,
                        build_notification_ctrl(magic.next()),
                        "Notification control (enable)")
        await asyncio.sleep(0.15)

        # Settings request
        seq = await send(client, seq, 0x09, 0x20,
                        build_settings_request(magic.next()),
                        "Settings request (basic)")
        await asyncio.sleep(0.15)

        # Module configure - language
        seq = await send(client, seq, 0x20, 0x20,
                        build_module_configure_language(magic.next()),
                        "ModuleConfigure: language=0")
        await asyncio.sleep(0.15)

        # Module configure - dashboard auto-close
        seq = await send(client, seq, 0x20, 0x20,
                        build_module_configure_dashboard_autoclose(magic.next()),
                        "ModuleConfigure: dashboard auto-close")
        await asyncio.sleep(0.15)

        post_responses = len(t.responses) - auth_responses - init_responses - dash_responses
        print(f"\nPost-dashboard done ({post_responses} new responses)\n")

        # Wait and monitor
        print("=" * 60)
        print("MONITORING for dashboard activity...")
        print("=" * 60)
        for i in range(15):
            await asyncio.sleep(1.0)
            total_new = len(t.responses) - auth_responses
            print(f"  [{i+1:2d}s] responses={total_new} display_pkts={t.display_count}")

        # Show all post-auth responses
        print(f"\n{'='*60}")
        print("ALL POST-AUTH RESPONSES:")
        print("=" * 60)
        for label, data in t.responses[auth_responses:]:
            svc_info = ""
            if len(data) >= 8 and data[0] == 0xAA:
                svc_id = data[6]
                status = data[7]
                result_code = (status >> 1) & 0x0F
                notify = status & 0x01
                svc_info = f" svc=0x{svc_id:02X} result={result_code} notify={notify}"
            print(f"  {label} ({len(data)}b){svc_info}: {data.hex()[:100]}")

        print(f"\nFinal: {len(t.responses) - auth_responses} responses, {t.display_count} display packets")
        print("Check glasses for dashboard!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
