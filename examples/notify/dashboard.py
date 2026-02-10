#!/usr/bin/env python3
"""
Even G2 Dashboard - Send live dashboard data to glasses.

Uses compiled protobuf definitions from PR#1 (aegray) for proper
message construction. Fetches live weather from wttr.in.

Protocol flow:
  1. Auth handshake (7 packets)
  2. Dashboard Enable (service 0x0A-20)
  3. Dashboard Refresh (service 0x07-20)
  4. Screen Mode (service 0x10-20)
  5. Display Settings via DashboardReceiveFromApp (service 0x01-20)
  6. Weather data via DashboardReceiveFromApp (service 0x01-20)
  7. Schedule events via DashboardReceiveFromApp (service 0x01-20)
  8. Display Wake (service 0x04-20)

Usage:
    python3 dashboard.py
    python3 dashboard.py --location "New York"
    python3 dashboard.py --no-weather --schedule "Team Standup|10:00 AM|Zoom"
"""

import argparse
import asyncio
import json
import os
import struct
import sys
import time
import urllib.request

from bleak import BleakClient, BleakScanner

# Add this dir to path for protobuf imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pbgen import dashboard_pb2


# =============================================================================
# BLE Constants
# =============================================================================

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)
CHAR_DISPLAY_N = UUID_BASE.format(0x6402)


# =============================================================================
# AA-Header Protocol
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


def build_aa_packet(seq, svc_hi, svc_lo, payload):
    """Build AA-header packet with CRC."""
    total_len = len(payload) + 2  # +2 for packet info (01 01)
    header = bytes([0xAA, 0x21, seq & 0xFF, total_len, 0x01, 0x01, svc_hi, svc_lo])
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
# Activation packets (raw payloads from BLE capture, non-dashboard services)
# =============================================================================

def build_dashboard_enable(seq, msg_id):
    """Service 0x0A-20: Enable dashboard mode."""
    payload = bytes([0x08, 0x00]) + bytes([0x10]) + encode_varint(msg_id)
    return build_aa_packet(seq, 0x0A, 0x20, payload)


def build_dashboard_refresh(seq, msg_id):
    """Service 0x07-20: Refresh dashboard (type=10)."""
    inner = bytes([0x08, 0x00, 0x10]) + encode_varint(msg_id)
    payload = (bytes([0x08, 0x0A]) +
               bytes([0x10]) + encode_varint(msg_id) +
               bytes([0x6A, len(inner)]) + inner)
    return build_aa_packet(seq, 0x07, 0x20, payload)


def build_screen_mode(seq, msg_id):
    """Service 0x10-20: Set screen mode (type=1, mode=4)."""
    payload = (bytes([0x08, 0x01]) +
               bytes([0x10]) + encode_varint(msg_id) +
               bytes([0x1A, 0x02, 0x08, 0x04]))
    return build_aa_packet(seq, 0x10, 0x20, payload)


def build_display_wake(seq, msg_id):
    """Service 0x04-20: Wake display to trigger rendering."""
    inner = bytes([0x08, 0x01, 0x10, 0x01, 0x18, 0x05, 0x28, 0x01])
    payload = (bytes([0x08, 0x01]) +
               bytes([0x10]) + encode_varint(msg_id) +
               bytes([0x1A, len(inner)]) + inner)
    return build_aa_packet(seq, 0x04, 0x20, payload)


def build_display_config(seq, msg_id):
    """Service 0x0E-20: Display config (captured, comes AFTER dashboard data)."""
    # Exact captured payload from scripted-session.log
    config_hex = (
        "080112130802104e1d001d4525000000002800300012130803100f1d006005"
        "452500000000280030001212080410001d000042250000000028003000"
        "1212080510001d0000422500000000280030001212080610001d0000"
        "4225000000002800300018000000001c0000"
    )
    config = bytes.fromhex(config_hex)
    payload = (bytes([0x08, 0x02]) +
               bytes([0x10]) + encode_varint(msg_id) +
               bytes([0x22, len(config)]) + config)
    return build_aa_packet(seq, 0x0E, 0x20, payload)


# =============================================================================
# Dashboard data messages (protobuf-based, service 0x01-20)
# =============================================================================

def build_display_settings_packet(seq, msg_id, widgets, statuses):
    """Build DashboardReceiveFromApp with display layout settings."""
    pkg = dashboard_pb2.DashboardDataPackage()
    pkg.commandId = dashboard_pb2.Dashboard_Receive
    pkg.magicRandom = msg_id

    recv = pkg.dashboardReceive
    recv.packageId = msg_id

    settings = recv.bashboardDisplaySetting
    settings.displayMode = 4

    # Status bar items
    settings.statusDisplayCount = len(statuses)
    for s in statuses:
        settings.statusDisplayOrder.append(s)

    # Widget tiles
    settings.widgetDisplayCount = len(widgets)
    for w in widgets:
        settings.widgetDisplayOrder.append(w)

    payload = pkg.SerializeToString()
    return build_aa_packet(seq, 0x01, 0x20, payload)


def build_weather_packet(seq, msg_id, temp_f, condition_code):
    """Build DashboardReceiveFromApp with weather status."""
    pkg = dashboard_pb2.DashboardDataPackage()
    pkg.commandId = dashboard_pb2.Dashboard_Receive
    pkg.magicRandom = msg_id

    recv = pkg.dashboardReceive
    recv.packageId = msg_id

    weather = recv.bashboardConfig.statusComponents.weather
    weather.temperature = temp_f
    weather.unit = dashboard_pb2.TEMP_UNIT_FAHRENHEIT
    weather.type = condition_code
    weather.updateTime = int(time.time())

    payload = pkg.SerializeToString()
    return build_aa_packet(seq, 0x01, 0x20, payload)


def build_schedule_packet(seq, msg_id, total, num, event):
    """Build DashboardReceiveFromApp with a single calendar event."""
    pkg = dashboard_pb2.DashboardDataPackage()
    pkg.commandId = dashboard_pb2.Dashboard_Receive
    pkg.magicRandom = msg_id

    recv = pkg.dashboardReceive
    recv.packageId = msg_id

    sched = recv.bashboardConfig.widgetComponents.schedule
    sched.scheduleTotal = total
    sched.scheduleNum = num
    s = sched.schedule
    s.scheduleId = event['id']
    s.title = event['title']
    s.location = event.get('location', '')
    s.time = event.get('time', '')
    s.endTimestamp = event.get('end_ts', 0)

    payload = pkg.SerializeToString()
    return build_aa_packet(seq, 0x01, 0x20, payload)


def build_app_respond_packet(seq, msg_id, package_id):
    """Build AppRespondToDashboard (ACK for glasses requests)."""
    pkg = dashboard_pb2.DashboardDataPackage()
    pkg.commandId = dashboard_pb2.APP_Respond
    pkg.magicRandom = msg_id

    respond = pkg.appRespond
    respond.packageId = package_id
    respond.flag = dashboard_pb2.APP_RECEIVED_SUCCESS

    payload = pkg.SerializeToString()
    return build_aa_packet(seq, 0x01, 0x20, payload)


# =============================================================================
# Weather fetching (wttr.in - free, no API key)
# =============================================================================

WEATHER_CODE_MAP = {
    'Clear': dashboard_pb2.WEATHER_SUNNY,
    'Sunny': dashboard_pb2.WEATHER_SUNNY,
    'Partly cloudy': dashboard_pb2.WEATHER_CLOUDS,
    'Cloudy': dashboard_pb2.WEATHER_CLOUDS,
    'Overcast': dashboard_pb2.WEATHER_CLOUDS,
    'Mist': dashboard_pb2.WEATHER_MIST,
    'Fog': dashboard_pb2.WEATHER_FOG,
    'Patchy rain possible': dashboard_pb2.WEATHER_DRIZZLE,
    'Light drizzle': dashboard_pb2.WEATHER_DRIZZLE,
    'Light rain': dashboard_pb2.WEATHER_RAIN,
    'Moderate rain': dashboard_pb2.WEATHER_RAIN,
    'Heavy rain': dashboard_pb2.WEATHER_HEAVY_RAIN,
    'Thundery outbreaks possible': dashboard_pb2.WEATHER_THUNDERSTORM,
    'Patchy snow possible': dashboard_pb2.WEATHER_SNOW,
    'Light snow': dashboard_pb2.WEATHER_SNOW,
    'Moderate snow': dashboard_pb2.WEATHER_SNOW,
    'Heavy snow': dashboard_pb2.WEATHER_SNOW,
}


def fetch_weather(location=""):
    """Fetch current weather from wttr.in."""
    loc = location.replace(" ", "+") if location else ""
    url = f"https://wttr.in/{loc}?format=j1"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "even-g2-dashboard"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        current = data["current_condition"][0]
        temp_f = float(current["temp_F"])
        desc = current["weatherDesc"][0]["value"]
        condition = WEATHER_CODE_MAP.get(desc, dashboard_pb2.WEATHER_CLOUDS)

        area = data.get("nearest_area", [{}])[0]
        city = area.get("areaName", [{}])[0].get("value", location or "Unknown")

        print(f"  Weather: {city} - {temp_f}F, {desc}")
        return temp_f, condition, city
    except Exception as e:
        print(f"  Weather fetch failed: {e}")
        print(f"  Using defaults: 72F, Sunny")
        return 72.0, dashboard_pb2.WEATHER_SUNNY, location or "Unknown"


# =============================================================================
# Response handler
# =============================================================================

class DashboardSession:
    def __init__(self):
        self.responses = []
        self.display_packets = 0
        self.glasses_requests = []
        self.seq = 0x08
        self.msg_id = 0x14
        self.sent_packets = []  # Track all sent packets for right lens mirroring

    def next(self):
        """Get next seq/msg_id pair and increment."""
        s, m = self.seq, self.msg_id
        self.seq += 1
        self.msg_id += 1
        return s, m

    def on_notify(self, sender, data):
        """Handle responses on 0x5402."""
        if len(data) >= 8 and data[0] == 0xAA:
            svc_hi, svc_lo = data[6], data[7]
            svc = f"0x{svc_hi:02X}-{svc_lo:02X}"
            proto_data = data[8:-2] if len(data) > 10 else data[8:]

            # Check if glasses are sending us a dashboard request
            if svc_hi == 0x01 and svc_lo == 0x20:
                try:
                    pkg = dashboard_pb2.DashboardDataPackage()
                    pkg.ParseFromString(proto_data)
                    if pkg.commandId == dashboard_pb2.APP_RECEIVE:
                        print(f"  <- GLASSES REQUEST: packageId={pkg.appReceive.packageId} reset={pkg.appReceive.reset}")
                        self.glasses_requests.append(pkg)
                    elif pkg.commandId == dashboard_pb2.Dashboard_Respond:
                        flag = "OK" if pkg.dashboardRespond.flag == 0 else "ERR"
                        print(f"  <- Dashboard ACK: packageId={pkg.dashboardRespond.packageId} flag={flag}")
                    else:
                        print(f"  <- [{svc}] cmd={pkg.commandId}: {data.hex()[:60]}")
                except Exception:
                    print(f"  <- [{svc}] ({len(data)}b): {data.hex()[:60]}")
            else:
                print(f"  <- [{svc}] ({len(data)}b): {data.hex()[:60]}")
        else:
            print(f"  <- raw ({len(data)}b): {data.hex()[:40]}")
        self.responses.append(bytes(data))

    def on_display(self, sender, data):
        """Handle display rendering data on 0x6402."""
        self.display_packets += 1


# =============================================================================
# Main
# =============================================================================

async def run(args):
    # Fetch weather data first
    print("Fetching live data...")
    if not args.no_weather:
        temp_f, weather_code, city = fetch_weather(args.location)
    else:
        temp_f, weather_code, city = 72.0, dashboard_pb2.WEATHER_SUNNY, "Default"

    # Parse schedule events
    events = []
    for i, s in enumerate(args.schedule or []):
        parts = s.split("|")
        events.append({
            'id': i + 1,
            'title': parts[0].strip(),
            'time': parts[1].strip() if len(parts) > 1 else "",
            'location': parts[2].strip() if len(parts) > 2 else "",
            'end_ts': 0,
        })
    if not events:
        # Default schedule entries
        events = [
            {'id': 1, 'title': 'Team Standup', 'time': '10:00 AM', 'location': 'Zoom', 'end_ts': 0},
            {'id': 2, 'title': 'Lunch', 'time': '12:30 PM', 'location': '', 'end_ts': 0},
            {'id': 3, 'title': 'Code Review', 'time': '3:00 PM', 'location': 'GitHub', 'end_ts': 0},
        ]

    print(f"  Schedule: {len(events)} events")
    for e in events:
        loc = f" @ {e['location']}" if e.get('location') else ""
        print(f"    - {e['title']} {e['time']}{loc}")

    # Connect
    print("\nScanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2_devices = [d for d in devices if d.name and "G2" in d.name]
    if not g2_devices:
        print("No G2 glasses found!")
        return

    left = next((d for d in g2_devices if "_L_" in d.name), None)
    right = next((d for d in g2_devices if "_R_" in d.name), None)
    device = left or g2_devices[0]
    print(f"Using: {device.name}")
    if right:
        print(f"Right lens: {right.name}")

    session = DashboardSession()

    async with BleakClient(device) as client:
        if not client.is_connected:
            print("Failed to connect!")
            return
        print("Connected!\n")

        await client.start_notify(CHAR_NOTIFY, session.on_notify)
        await client.start_notify(CHAR_DISPLAY_N, session.on_display)

        # Auth
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
        print(f"Auth complete ({len(session.responses)} responses)\n")

        async def send(pkt, label=""):
            if label:
                print(f"  -> {label} ({len(pkt)}b): {pkt.hex()[:80]}")
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            session.sent_packets.append(pkt)
            await asyncio.sleep(0.15)

        # =====================================================================
        # Phase 1: Activation sequence
        # =====================================================================
        print("=" * 55)
        print("PHASE 1: Dashboard Activation")
        print("=" * 55)

        seq, mid = session.next()
        await send(build_dashboard_enable(seq, mid), "Dashboard Enable (0x0A-20)")

        seq, mid = session.next()
        await send(build_dashboard_refresh(seq, mid), "Dashboard Refresh (0x07-20)")

        seq, mid = session.next()
        await send(build_screen_mode(seq, mid), "Screen Mode (0x10-20)")

        await asyncio.sleep(0.3)

        # =====================================================================
        # Phase 2: Display settings (what widgets to show)
        # =====================================================================
        print("\n" + "=" * 55)
        print("PHASE 2: Display Settings")
        print("=" * 55)

        statuses = [dashboard_pb2.STATUS_WEATHER]
        widgets = [dashboard_pb2.WIDGET_SCHEDULE]
        if not args.no_weather:
            statuses.append(dashboard_pb2.STATUS_Power)

        seq, mid = session.next()
        pkt = build_display_settings_packet(seq, mid, widgets, statuses)
        await send(pkt, f"Display Settings (statuses={len(statuses)}, widgets={len(widgets)})")

        await asyncio.sleep(0.3)

        # =====================================================================
        # Phase 3: Content data
        # =====================================================================
        print("\n" + "=" * 55)
        print("PHASE 3: Dashboard Content")
        print("=" * 55)

        # Weather
        if not args.no_weather:
            seq, mid = session.next()
            pkt = build_weather_packet(seq, mid, temp_f, weather_code)
            await send(pkt, f"Weather: {temp_f}F {city}")

        # Schedule events (one per packet)
        total_events = len(events)
        for i, event in enumerate(events):
            seq, mid = session.next()
            pkt = build_schedule_packet(seq, mid, total_events, i + 1, event)
            await send(pkt, f"Schedule {i+1}/{total_events}: {event['title']}")

        await asyncio.sleep(0.3)

        # =====================================================================
        # Phase 4: Display Wake
        # =====================================================================
        print("\n" + "=" * 55)
        print("PHASE 4: Display Wake + Display Config")
        print("=" * 55)

        seq, mid = session.next()
        await send(build_display_wake(seq, mid), "Display Wake (0x04-20)")

        await asyncio.sleep(0.5)

        # Display Config comes AFTER dashboard data (from capture analysis)
        seq, mid = session.next()
        await send(build_display_config(seq, mid), "Display Config (0x0E-20)")

        # =====================================================================
        # Mirror to right lens if available
        # =====================================================================
        if right:
            print("\n" + "=" * 55)
            print("MIRRORING TO RIGHT LENS")
            print("=" * 55)
            try:
                async with BleakClient(right) as rclient:
                    if rclient.is_connected:
                        print("  Right lens connected!")
                        # Replay all sent packets to right lens
                        for pkt in session.sent_packets:
                            await rclient.write_gatt_char(CHAR_WRITE, pkt, response=False)
                            await asyncio.sleep(0.1)
                        print(f"  Sent {len(session.sent_packets)} packets to right lens")
                    else:
                        print("  Right lens connection failed")
            except Exception as e:
                print(f"  Right lens error: {e}")

        # =====================================================================
        # Monitor for responses
        # =====================================================================
        pre_count = len(session.responses)
        print("\n" + "=" * 55)
        print("MONITORING (waiting for display...)")
        print("=" * 55)

        for i in range(20):
            await asyncio.sleep(1.0)

            # Handle any glasses requests
            while session.glasses_requests:
                req = session.glasses_requests.pop(0)
                print(f"  Responding to glasses request (packageId={req.appReceive.packageId})")
                seq, mid = session.next()
                pkt = build_app_respond_packet(seq, mid, req.appReceive.packageId)
                await client.write_gatt_char(CHAR_WRITE, pkt, response=False)

            new_resp = len(session.responses) - pre_count
            if (i + 1) % 5 == 0 or new_resp > 0:
                print(f"  [{i+1:2d}s] new_responses={new_resp} display={session.display_packets}")

        total_new = len(session.responses) - pre_count
        print(f"\nFinal: {total_new} new responses, {session.display_packets} display packets")
        if total_new == 0:
            print("No responses from dashboard commands.")
            print("Glasses may need post-auth init or be in wrong UI state.")
        print("Check your glasses!")


def main():
    parser = argparse.ArgumentParser(description="Send live dashboard to Even G2 glasses")
    parser.add_argument("--location", "-l", default="",
                        help="Weather location (default: auto-detect)")
    parser.add_argument("--no-weather", action="store_true",
                        help="Skip weather fetch")
    parser.add_argument("--schedule", "-s", action="append",
                        help="Schedule event as 'Title|Time|Location' (repeatable)")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
