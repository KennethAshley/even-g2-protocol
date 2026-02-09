#!/usr/bin/env python3
"""
Even G2 Notification Sender

Send notifications to Even Realities G2 smart glasses via BLE.

Protocol (reverse-engineered from BLE capture + hardware testing):
  - Uses Conversate service (0x0B-20) with type=5 speech transcription
  - Sends text via AA-header protobuf on characteristic 0x5401
  - Auth handshake required first (7 packets on 0x5401)
  - Text appears as real-time transcription on the glasses display
  - Progressive updates supported (partial -> final with is_final=1)

Usage:
    python3 notify.py "Hello World"
    python3 notify.py "Meeting in 5 min" --title "Calendar"
    python3 notify.py "Hello" --method teleprompter   # alternative display
"""

import argparse
import asyncio
import time
from bleak import BleakClient, BleakScanner


# =============================================================================
# BLE Constants
# =============================================================================

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"

# Main protocol channel (AA-header packets)
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
    ts_varint = encode_varint(timestamp)
    txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])
    packets = []
    packets.append(add_crc(bytes([0xAA, 0x21, 0x01, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x0C, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x02, 0x0A, 0x01, 0x01, 0x80, 0x20,
        0x08, 0x05, 0x10, 0x0E, 0x22, 0x02, 0x08, 0x02])))
    payload = bytes([0x08, 0x80, 0x01, 0x10, 0x0F, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    packets.append(add_crc(bytes([0xAA, 0x21, 0x03, len(payload) + 2, 0x01, 0x01, 0x80, 0x20]) + payload))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x04, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x10, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x05, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x11, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])))
    packets.append(add_crc(bytes([0xAA, 0x21, 0x06, 0x0A, 0x01, 0x01, 0x80, 0x20,
        0x08, 0x05, 0x10, 0x12, 0x22, 0x02, 0x08, 0x01])))
    payload = bytes([0x08, 0x80, 0x01, 0x10, 0x13, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    packets.append(add_crc(bytes([0xAA, 0x21, 0x07, len(payload) + 2, 0x01, 0x01, 0x80, 0x20]) + payload))
    return packets


# =============================================================================
# Conversate Service (0x0B-20) - Native text display
# =============================================================================

def build_conversate_config(seq, msg_id):
    """Start a Conversate session (type=1)."""
    inner_settings = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)
    session = pb_varint(1, 1) + pb_bytes(2, inner_settings)
    payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


def build_transcription(seq, msg_id, text, is_final=False):
    """Build type=5 speech transcription packet for text display."""
    transcript = pb_string(1, text) + pb_varint(2, 1 if is_final else 0)
    payload = pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, transcript)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


async def send_text(client, text, seq_start=0x08, msg_id_start=0x14):
    """Display text on glasses via Conversate transcription."""
    seq = seq_start
    msg_id = msg_id_start

    # Start Conversate session
    pkt = build_conversate_config(seq, msg_id)
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    seq += 1; msg_id += 1
    await asyncio.sleep(0.3)

    # Send empty start (matches captured protocol)
    pkt = build_transcription(seq, msg_id, "", is_final=False)
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    seq += 1; msg_id += 1
    await asyncio.sleep(0.3)

    # Send final text
    pkt = build_transcription(seq, msg_id, text, is_final=True)
    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
    seq += 1; msg_id += 1
    await asyncio.sleep(0.5)

    return seq, msg_id


# =============================================================================
# Teleprompter Service (0x06-20) - Alternative display
# =============================================================================

def build_display_config(seq, msg_id):
    config = bytes.fromhex(
        "0801121308021090" "4E1D00E094442500" "000000280030001213"
        "0803100D0F1D0040" "8D44250000000028" "0030001212080410"
        "001D0000884225" "00000000280030" "001212080510001D"
        "00009242250000" "A242280030001212" "080610001D0000C6"
        "42250000C4422800" "30001800"
    )
    payload = bytes([0x08, 0x02, 0x10]) + encode_varint(msg_id) + bytes([0x22, 0x6A]) + config
    return build_aa_packet(seq, 0x0E, 0x20, payload)


def build_teleprompter_init(seq, msg_id, total_lines=10):
    content_height = max(1, (total_lines * 2665) // 140)
    display = (
        bytes([0x08, 0x01, 0x10, 0x00, 0x18, 0x00, 0x20, 0x8B, 0x02]) +
        bytes([0x28]) + encode_varint(content_height) +
        bytes([0x30, 0xE6, 0x01, 0x38, 0x8E, 0x0A, 0x40, 0x05, 0x48, 0x00])
    )
    settings = bytes([0x08, 0x01, 0x12, len(display)]) + display
    payload = bytes([0x08, 0x01, 0x10]) + encode_varint(msg_id) + bytes([0x1A, len(settings)]) + settings
    return build_aa_packet(seq, 0x06, 0x20, payload)


def build_content_page(seq, msg_id, page_num, text):
    text_bytes = ("\n" + text).encode('utf-8')
    inner = bytes([0x08]) + encode_varint(page_num) + bytes([0x10, 0x0A, 0x1A]) + encode_varint(len(text_bytes)) + text_bytes
    content = bytes([0x2A]) + encode_varint(len(inner)) + inner
    payload = bytes([0x08, 0x03, 0x10]) + encode_varint(msg_id) + content
    return build_aa_packet(seq, 0x06, 0x20, payload)


def build_marker(seq, msg_id):
    payload = bytes([0x08, 0xFF, 0x01, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x04, 0x08, 0x00, 0x10, 0x06])
    return build_aa_packet(seq, 0x06, 0x20, payload)


def build_sync(seq, msg_id):
    payload = bytes([0x08, 0x0E, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x00])
    return build_aa_packet(seq, 0x80, 0x00, payload)


def format_text_pages(title, message, chars_per_line=25, lines_per_page=10):
    lines = []
    if title:
        lines.append(title.upper())
        lines.append("-" * min(chars_per_line, 20))
    for paragraph in message.split("\n"):
        if not paragraph.strip():
            lines.append("")
            continue
        words = paragraph.split()
        current = ""
        for word in words:
            if len(current) + len(word) + 1 > chars_per_line:
                if current:
                    lines.append(current.strip())
                current = word + " "
            else:
                current += word + " "
        if current.strip():
            lines.append(current.strip())
    while len(lines) < lines_per_page:
        lines.append(" ")
    pages = []
    for i in range(0, len(lines), lines_per_page):
        page_lines = lines[i:i + lines_per_page]
        while len(page_lines) < lines_per_page:
            page_lines.append(" ")
        pages.append("\n".join(page_lines) + " \n")
    while len(pages) < 14:
        pages.append("\n".join([" "] * lines_per_page) + " \n")
    return pages


async def send_teleprompter(client, title, message):
    """Display text via teleprompter protocol."""
    print("  Sending as teleprompter text...")
    pages = format_text_pages(title, message)
    total_lines = sum(1 for p in pages for l in p.split("\n") if l.strip())
    seq, msg_id = 0x08, 0x14

    await client.write_gatt_char(CHAR_WRITE, build_display_config(seq, msg_id), response=False)
    seq += 1; msg_id += 1
    await asyncio.sleep(0.3)

    await client.write_gatt_char(CHAR_WRITE, build_teleprompter_init(seq, msg_id, total_lines), response=False)
    seq += 1; msg_id += 1
    await asyncio.sleep(0.5)

    for i in range(min(10, len(pages))):
        await client.write_gatt_char(CHAR_WRITE, build_content_page(seq, msg_id, i, pages[i]), response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.05)

    await client.write_gatt_char(CHAR_WRITE, build_marker(seq, msg_id), response=False)
    seq += 1; msg_id += 1
    await asyncio.sleep(0.05)

    for i in range(10, len(pages)):
        await client.write_gatt_char(CHAR_WRITE, build_content_page(seq, msg_id, i, pages[i]), response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.05)

    await client.write_gatt_char(CHAR_WRITE, build_sync(seq, msg_id), response=False)
    await asyncio.sleep(0.1)


# =============================================================================
# Main
# =============================================================================

async def run(args):
    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)

    g2_devices = [d for d in devices if d.name and "G2" in d.name]
    if not g2_devices:
        print("No G2 glasses found! Make sure they are powered on and nearby.")
        return

    for d in g2_devices:
        print(f"  Found: {d.name} ({d.address})")

    device = next((d for d in g2_devices if "_L_" in d.name), g2_devices[0])
    side = "right" if "_R_" in device.name else "left"
    print(f"Using {side} lens: {device.name}")

    async with BleakClient(device) as client:
        if not client.is_connected:
            print("Failed to connect!")
            return
        print("Connected!\n")

        # Subscribe to notify channel
        response_count = 0
        def on_response(sender, data):
            nonlocal response_count
            response_count += 1
        await client.start_notify(CHAR_NOTIFY, on_response)

        # Authenticate
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
        print(f"Auth complete ({response_count} responses)")

        title = args.title
        message = args.message
        display_text = f"{title}: {message}" if title else message

        if args.method == "teleprompter":
            await send_teleprompter(client, title or "", message)
        else:
            # Native display via Conversate service
            print(f"\nSending: \"{display_text}\"")
            await send_text(client, display_text)

        print("Done! Text should appear on glasses.")
        await asyncio.sleep(1.0)


def main():
    parser = argparse.ArgumentParser(description="Send notifications to Even G2 glasses")
    parser.add_argument("message", help="Notification message text")
    parser.add_argument("--title", "-t", help="Notification title (prepended to message)")
    parser.add_argument("--method", "-m", default="native",
                        choices=["native", "teleprompter"],
                        help="Display method (default: native)")

    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
