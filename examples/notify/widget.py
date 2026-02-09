#!/usr/bin/env python3
"""
Even G2 Custom Widget - Persistent info display via Conversate.

Since we can't add new services to the glasses menu (firmware-defined),
we hijack the proven Conversate service (0x0B-20) to push periodic
text updates - acting as a custom widget.

The glasses display text when they're in Conversate mode. This script
keeps the connection alive and periodically pushes new content.

Usage:
    python3 widget.py                          # Clock widget
    python3 widget.py --widget clock           # Clock + date
    python3 widget.py --widget custom "Hello"  # Custom text
    python3 widget.py --widget ticker          # Cycle through messages
    python3 widget.py --interval 5             # Update every 5 seconds
"""

import argparse
import asyncio
import time
from datetime import datetime
from bleak import BleakClient, BleakScanner


# =============================================================================
# BLE Protocol (same as notify.py)
# =============================================================================

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
# Conversate Protocol
# =============================================================================

def build_session_start(seq, msg_id):
    inner = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)
    session = pb_varint(1, 1) + pb_bytes(2, inner)
    payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


def build_transcription(seq, msg_id, text, is_final=True):
    transcript = pb_string(1, text) + pb_varint(2, 1 if is_final else 0)
    payload = pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, transcript)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


def build_ai_response(seq, msg_id, text):
    """Type=2 AI response - also displays text."""
    payload = pb_varint(1, 2) + pb_varint(2, msg_id) + pb_string(3, text)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


# =============================================================================
# Widget Content Generators
# =============================================================================

def widget_clock():
    now = datetime.now()
    return now.strftime("%I:%M %p  %b %d")


def widget_custom(text):
    return text


def widget_ticker(messages, index):
    return messages[index % len(messages)]


# =============================================================================
# Main
# =============================================================================

async def connect_and_auth(device):
    client = BleakClient(device)
    await client.connect()
    await client.start_notify(CHAR_NOTIFY, lambda s, d: None)
    for pkt in build_auth_packets():
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        await asyncio.sleep(0.1)
    await asyncio.sleep(0.5)
    return client


async def send_widget_text(client, text, seq, msg_id):
    """Send text using Conversate session + transcription."""
    # Start session
    pkt = build_session_start(seq, msg_id)
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    seq += 1; msg_id += 1
    await asyncio.sleep(0.2)

    # Send text as final transcription
    pkt = build_transcription(seq, msg_id, text, is_final=True)
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    seq += 1; msg_id += 1
    await asyncio.sleep(0.2)

    return seq, msg_id


async def find_glasses():
    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 glasses found!")
        return None
    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Found: {device.name}")
    return device


async def run(args):
    device = await find_glasses()
    if not device:
        return

    ticker_messages = args.messages if args.messages else [
        "Hello from G2 Widget!",
        datetime.now().strftime("%I:%M %p  %b %d"),
        "Custom widget running...",
    ]
    ticker_index = 0

    print(f"Widget: {args.widget}")
    print(f"Interval: {args.interval}s")
    print(f"Press Ctrl+C to stop\n")

    while True:
        try:
            # Connect fresh each time (avoids BLE timeout issues)
            client = await connect_and_auth(device)
            print(f"  Connected")

            seq = 0x08
            msg_id = 0x14

            # Generate content
            if args.widget == "clock":
                text = widget_clock()
            elif args.widget == "custom":
                text = widget_custom(args.messages[0] if args.messages else "Hello!")
            elif args.widget == "ticker":
                text = widget_ticker(ticker_messages, ticker_index)
                ticker_index += 1
            else:
                text = widget_clock()

            # Send to glasses
            seq, msg_id = await send_widget_text(client, text, seq, msg_id)
            now = datetime.now().strftime("%H:%M:%S")
            print(f"  [{now}] -> \"{text}\"")

            await client.disconnect()

        except Exception as e:
            print(f"  Error: {e}")

        # Wait for next update
        await asyncio.sleep(args.interval)


def main():
    parser = argparse.ArgumentParser(description="Even G2 custom widget display")
    parser.add_argument("--widget", "-w", default="clock",
                        choices=["clock", "custom", "ticker"],
                        help="Widget type (default: clock)")
    parser.add_argument("--interval", "-i", type=float, default=30,
                        help="Update interval in seconds (default: 30)")
    parser.add_argument("messages", nargs="*",
                        help="Text for custom/ticker widget")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nWidget stopped")
