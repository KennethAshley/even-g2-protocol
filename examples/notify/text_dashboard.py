#!/usr/bin/env python3
"""
Even G2 Text Dashboard - Display live info on glasses via Conversate service.

Uses the proven Conversate text display (service 0x0B) to show a formatted
dashboard with weather, schedule, and custom messages.

The native dashboard protocol (service 0x01) remains uncracked, but Conversate
reliably displays text on the glasses. This tool formats info nicely and
cycles through screens.

Usage:
    python3 text_dashboard.py
    python3 text_dashboard.py --location "New York"
    python3 text_dashboard.py -s "Standup|10:00 AM|Zoom" -s "Lunch|12:30 PM"
    python3 text_dashboard.py --loop 30   # Refresh every 30 seconds
"""

import argparse
import asyncio
import json
import time
import urllib.request
from datetime import datetime

from bleak import BleakClient, BleakScanner


# =============================================================================
# BLE Constants
# =============================================================================

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)


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
    header = bytes([0xAA, 0x21, seq & 0xFF, len(payload) + 2, 0x01, 0x01, svc_hi, svc_lo])
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
# Conversate text display
# =============================================================================

def build_conversate_start(seq, msg_id):
    inner_settings = pb_varint(1,1) + pb_varint(2,1) + pb_varint(3,1) + pb_varint(4,1)
    session = pb_varint(1,1) + pb_bytes(2, inner_settings)
    payload = pb_varint(1,1) + pb_varint(2, msg_id) + pb_bytes(3, session)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


def build_transcription(seq, msg_id, text, is_final=False):
    transcript = pb_string(1, text) + pb_varint(2, 1 if is_final else 0)
    payload = pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, transcript)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


def build_conversate_close(seq, msg_id):
    session = pb_varint(1, 2)  # CLOSE command
    payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


async def show_text(client, text, seq_start, msg_id_start):
    """Display text on glasses and return next seq/msg_id.

    Uses the exact same 3-step pattern as the proven notify.py:
    1. Start conversate session
    2. Empty transcription (non-final)
    3. Full text (final)
    """
    seq, mid = seq_start, msg_id_start

    # Step 1: Start session
    pkt = build_conversate_start(seq, mid)
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    seq += 1; mid += 1
    await asyncio.sleep(0.3)

    # Step 2: Empty start (matches captured protocol)
    pkt = build_transcription(seq, mid, "", is_final=False)
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    seq += 1; mid += 1
    await asyncio.sleep(0.3)

    # Step 3: Final text
    pkt = build_transcription(seq, mid, text, is_final=True)
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    seq += 1; mid += 1
    await asyncio.sleep(0.5)

    return seq, mid


# =============================================================================
# Weather
# =============================================================================

WEATHER_ICONS = {
    'Sunny': '*', 'Clear': '*', 'Partly cloudy': '~',
    'Cloudy': '=', 'Overcast': '=', 'Mist': '.', 'Fog': '.',
    'Light rain': '/', 'Moderate rain': '//', 'Heavy rain': '///',
    'Light drizzle': ',', 'Patchy rain possible': ',',
    'Light snow': 'S', 'Moderate snow': 'SS', 'Heavy snow': 'SSS',
    'Thundery outbreaks possible': '!',
}


def fetch_weather(location=""):
    loc = location.replace(" ", "+") if location else ""
    url = f"https://wttr.in/{loc}?format=j1"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "even-g2-dashboard"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        current = data["current_condition"][0]
        temp_f = int(float(current["temp_F"]))
        temp_c = int(float(current["temp_C"]))
        desc = current["weatherDesc"][0]["value"]
        humidity = current.get("humidity", "?")
        wind = current.get("windspeedMiles", "?")

        area = data.get("nearest_area", [{}])[0]
        city = area.get("areaName", [{}])[0].get("value", location or "")

        icon = WEATHER_ICONS.get(desc, '?')

        return {
            'city': city,
            'temp_f': temp_f,
            'temp_c': temp_c,
            'desc': desc,
            'icon': icon,
            'humidity': humidity,
            'wind': wind,
        }
    except Exception as e:
        print(f"  Weather fetch failed: {e}")
        return None


# =============================================================================
# Dashboard formatting
# =============================================================================

def format_dashboard(weather, events):
    """Format dashboard as single-line text for glasses display.

    Conversate transcription doesn't support newlines, so we use
    separators to fit everything on one display.
    """
    now = datetime.now()
    parts = []

    # Time
    time_str = now.strftime("%I:%M %p").lstrip("0")
    date_str = now.strftime("%a %b %d")
    parts.append(f"{time_str} {date_str}")

    # Weather
    if weather:
        parts.append(f"{weather['temp_f']}F {weather['desc']} - {weather['city']}")

    # Next event only (keep it short for readability)
    if events:
        e = events[0]
        time_part = f"{e['time']} " if e.get('time') else ""
        loc_part = f" @ {e['location']}" if e.get('location') else ""
        parts.append(f"Next: {time_part}{e['title']}{loc_part}")

    return " | ".join(parts)


# =============================================================================
# Main
# =============================================================================

async def run(args):
    # Parse schedule
    events = []
    for s in (args.schedule or []):
        parts = s.split("|")
        events.append({
            'title': parts[0].strip(),
            'time': parts[1].strip() if len(parts) > 1 else "",
            'location': parts[2].strip() if len(parts) > 2 else "",
        })
    if not events:
        events = [
            {'title': 'Team Standup', 'time': '10:00 AM', 'location': 'Zoom'},
            {'title': 'Lunch', 'time': '12:30 PM', 'location': ''},
            {'title': 'Code Review', 'time': '3:00 PM', 'location': 'GitHub'},
        ]

    # Connect
    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2_devices = [d for d in devices if d.name and "G2" in d.name]
    if not g2_devices:
        print("No G2 glasses found!")
        return

    device = next((d for d in g2_devices if "_L_" in d.name), g2_devices[0])
    print(f"Using: {device.name}")

    async with BleakClient(device) as client:
        if not client.is_connected:
            print("Failed to connect!")
            return
        print("Connected!")

        # Subscribe to notifications
        await client.start_notify(CHAR_NOTIFY, lambda s, d: None)

        # Auth
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
        print("Auth complete\n")

        seq, mid = 0x08, 0x14
        iteration = 0

        while True:
            iteration += 1
            # Fetch weather
            print(f"--- Dashboard update #{iteration} ---")
            weather = fetch_weather(args.location) if not args.no_weather else None
            if weather:
                print(f"  Weather: {weather['city']} {weather['temp_f']}F {weather['desc']}")

            # Build dashboard text
            text = format_dashboard(weather, events)
            print(f"  Displaying:\n    " + text.replace("\n", "\n    "))

            # Send to glasses
            seq, mid = await show_text(client, text, seq, mid)
            print("  Sent to glasses!")

            if not args.loop:
                # Keep display for a bit then exit
                await asyncio.sleep(10)
                break

            # Wait for next refresh
            print(f"  Next refresh in {args.loop}s (Ctrl+C to stop)\n")
            await asyncio.sleep(args.loop)


def main():
    parser = argparse.ArgumentParser(description="Text dashboard for Even G2 glasses")
    parser.add_argument("--location", "-l", default="",
                        help="Weather location (default: auto-detect)")
    parser.add_argument("--no-weather", action="store_true",
                        help="Skip weather fetch")
    parser.add_argument("--schedule", "-s", action="append",
                        help="Schedule event as 'Title|Time|Location' (repeatable)")
    parser.add_argument("--loop", type=int, default=0,
                        help="Refresh interval in seconds (0 = show once)")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped")
