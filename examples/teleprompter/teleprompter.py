#!/usr/bin/env python3
"""
Even G2 Teleprompter - Display Custom Text

Usage:
    python teleprompter.py "Your text here"
    python teleprompter.py "Line one\nLine two\nLine three"
    python teleprompter.py "Use right eye" --right

Requirements:
    pip install bleak
"""

import asyncio
import sys
import time
from bleak import BleakClient, BleakScanner

# BLE UUIDs
UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)


# =============================================================================
# CRC-16/CCITT
# =============================================================================

def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    """CRC-16/CCITT with init=0xFFFF, polynomial=0x1021"""
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def add_crc(packet: bytes) -> bytes:
    """Add CRC to packet (calculated over payload, stored little-endian)"""
    crc = crc16_ccitt(packet[8:])  # Skip 8-byte header
    return packet + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


# =============================================================================
# Encoding Helpers
# =============================================================================

def encode_varint(value: int) -> bytes:
    """Encode integer as protobuf varint"""
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def build_packet(seq: int, service_hi: int, service_lo: int, payload: bytes) -> bytes:
    """Build a complete packet with header and CRC"""
    header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, service_hi, service_lo])
    return add_crc(header + payload)


# =============================================================================
# Authentication
# =============================================================================

def build_auth_packets() -> list:
    """Build the 7-packet authentication sequence"""
    timestamp = int(time.time())
    ts_varint = encode_varint(timestamp)
    txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])

    packets = []

    # Auth 1: Capability query
    packets.append(add_crc(bytes([
        0xAA, 0x21, 0x01, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x0C, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04
    ])))

    # Auth 2: Capability response request
    packets.append(add_crc(bytes([
        0xAA, 0x21, 0x02, 0x0A, 0x01, 0x01, 0x80, 0x20,
        0x08, 0x05, 0x10, 0x0E, 0x22, 0x02, 0x08, 0x02
    ])))

    # Auth 3: Time sync with transaction ID
    payload = bytes([0x08, 0x80, 0x01, 0x10, 0x0F, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    packets.append(add_crc(bytes([0xAA, 0x21, 0x03, len(payload) + 2, 0x01, 0x01, 0x80, 0x20]) + payload))

    # Auth 4-5: Additional capability exchanges
    packets.append(add_crc(bytes([
        0xAA, 0x21, 0x04, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x10, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04
    ])))
    packets.append(add_crc(bytes([
        0xAA, 0x21, 0x05, 0x0C, 0x01, 0x01, 0x80, 0x00,
        0x08, 0x04, 0x10, 0x11, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04
    ])))

    # Auth 6: Final capability
    packets.append(add_crc(bytes([
        0xAA, 0x21, 0x06, 0x0A, 0x01, 0x01, 0x80, 0x20,
        0x08, 0x05, 0x10, 0x12, 0x22, 0x02, 0x08, 0x01
    ])))

    # Auth 7: Final time sync
    payload = bytes([0x08, 0x80, 0x01, 0x10, 0x13, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    packets.append(add_crc(bytes([0xAA, 0x21, 0x07, len(payload) + 2, 0x01, 0x01, 0x80, 0x20]) + payload))

    return packets


# =============================================================================
# Teleprompter Protocol
# =============================================================================

def build_display_config(seq: int, msg_id: int) -> bytes:
    """Service 0x0E-20: Display configuration"""
    config = bytes.fromhex(
        "0801121308021090" "4E1D00E094442500" "000000280030001213"
        "0803100D0F1D0040" "8D44250000000028" "0030001212080410"
        "001D0000884225" "00000000280030" "001212080510001D"
        "00009242250000" "A242280030001212" "080610001D0000C6"
        "42250000C4422800" "30001800"
    )
    payload = bytes([0x08, 0x02, 0x10]) + encode_varint(msg_id) + bytes([0x22, 0x6A]) + config
    return build_packet(seq, 0x0E, 0x20, payload)


def build_teleprompter_init(seq: int, msg_id: int, total_lines: int = 10, manual_mode: bool = True) -> bytes:
    """Service 0x06-20 type=1: Initialize teleprompter"""
    mode = 0x00 if manual_mode else 0x01

    # Scale content height based on line count (Bee Movie: 140 lines = 2665)
    content_height = max(1, (total_lines * 2665) // 140)

    display = (
        bytes([0x08, 0x01, 0x10, 0x00, 0x18, 0x00, 0x20, 0x8B, 0x02]) +  # Fixed settings
        bytes([0x28]) + encode_varint(content_height) +  # Content height
        bytes([0x30, 0xE6, 0x01]) +  # Line height = 230
        bytes([0x38, 0x8E, 0x0A]) +  # Viewport = 1294
        bytes([0x40, 0x05, 0x48, mode])  # Font size + mode
    )

    settings = bytes([0x08, 0x01, 0x12, len(display)]) + display
    payload = bytes([0x08, 0x01, 0x10]) + encode_varint(msg_id) + bytes([0x1A, len(settings)]) + settings
    return build_packet(seq, 0x06, 0x20, payload)


def build_content_page(seq: int, msg_id: int, page_num: int, text: str) -> bytes:
    """Service 0x06-20 type=3: Content page"""
    text_bytes = ("\n" + text).encode('utf-8')

    inner = (
        bytes([0x08]) + encode_varint(page_num) +
        bytes([0x10, 0x0A]) +  # 10 lines
        bytes([0x1A]) + encode_varint(len(text_bytes)) + text_bytes
    )

    content = bytes([0x2A]) + encode_varint(len(inner)) + inner
    payload = bytes([0x08, 0x03, 0x10]) + encode_varint(msg_id) + content
    return build_packet(seq, 0x06, 0x20, payload)


def build_marker(seq: int, msg_id: int) -> bytes:
    """Service 0x06-20 type=255: Mid-stream marker"""
    payload = bytes([0x08, 0xFF, 0x01, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x04, 0x08, 0x00, 0x10, 0x06])
    return build_packet(seq, 0x06, 0x20, payload)


def build_sync(seq: int, msg_id: int) -> bytes:
    """Service 0x80-00 type=14: Sync/trigger"""
    payload = bytes([0x08, 0x0E, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x00])
    return build_packet(seq, 0x80, 0x00, payload)


# =============================================================================
# Text Formatting
# =============================================================================

def format_text(text: str, chars_per_line: int = 25, lines_per_page: int = 10) -> list:
    """Format text into pages of wrapped lines"""
    # Handle escaped newlines
    text = text.replace("\\n", "\n")

    # Split and wrap lines
    wrapped = []
    for line in text.split("\n"):
        if not line.strip():
            wrapped.append("")
            continue

        words = line.split()
        current = ""
        for word in words:
            if len(current) + len(word) + 1 > chars_per_line:
                if current:
                    wrapped.append(current.strip())
                current = word + " "
            else:
                current += word + " "
        if current.strip():
            wrapped.append(current.strip())

    if not wrapped:
        wrapped = [text]

    # Pad to at least 10 lines
    while len(wrapped) < lines_per_page:
        wrapped.append(" ")

    # Split into pages
    pages = []
    for i in range(0, len(wrapped), lines_per_page):
        page_lines = wrapped[i:i + lines_per_page]
        while len(page_lines) < lines_per_page:
            page_lines.append(" ")
        pages.append("\n".join(page_lines) + " \n")

    # Pad to minimum 14 pages
    while len(pages) < 14:
        pages.append("\n".join([" "] * lines_per_page) + " \n")

    return pages


# =============================================================================
# Main
# =============================================================================

async def send_text(device, text: str):
    """Send text to glasses"""
    print(f"Connecting to {device.name}...")

    async with BleakClient(device) as client:
        if not client.is_connected:
            print("Failed to connect!")
            return

        print("Connected!")

        # Enable notifications
        await client.start_notify(CHAR_NOTIFY, lambda s, d: None)

        # Send auth sequence
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)

        # Format text into pages
        pages = format_text(text)
        total_lines = len(text.replace("\\n", "\n").split("\n"))

        seq, msg_id = 0x08, 0x14

        # Display config
        print("Configuring display...")
        await client.write_gatt_char(CHAR_WRITE, build_display_config(seq, msg_id), response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        # Teleprompter init
        print("Initializing teleprompter...")
        await client.write_gatt_char(CHAR_WRITE, build_teleprompter_init(seq, msg_id, total_lines), response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.5)

        # Send content pages 0-9
        print(f"Sending {len(pages)} pages...")
        for i in range(min(10, len(pages))):
            await client.write_gatt_char(CHAR_WRITE, build_content_page(seq, msg_id, i, pages[i]), response=False)
            seq += 1; msg_id += 1
            await asyncio.sleep(0.1)

        # Mid-stream marker
        await client.write_gatt_char(CHAR_WRITE, build_marker(seq, msg_id), response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.1)

        # Pages 10-11
        for i in range(10, min(12, len(pages))):
            await client.write_gatt_char(CHAR_WRITE, build_content_page(seq, msg_id, i, pages[i]), response=False)
            seq += 1; msg_id += 1
            await asyncio.sleep(0.1)

        # Sync trigger
        await client.write_gatt_char(CHAR_WRITE, build_sync(seq, msg_id), response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.1)

        # Remaining pages
        for i in range(12, len(pages)):
            await client.write_gatt_char(CHAR_WRITE, build_content_page(seq, msg_id, i, pages[i]), response=False)
            seq += 1; msg_id += 1
            await asyncio.sleep(0.1)

        print("Done! Check your glasses.")
        await asyncio.sleep(5.0)


async def main():
    text = sys.argv[1] if len(sys.argv) > 1 else "Hello from Python!\nThis is a test."
    use_right = "--right" in sys.argv

    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)

    g2_devices = [d for d in devices if d.name and "G2" in d.name]
    if not g2_devices:
        print("No G2 glasses found!")
        return

    # Select left or right
    pattern = "_R_" if use_right else "_L_"
    device = next((d for d in g2_devices if pattern in d.name), g2_devices[0])
    print(f"Using: {device.name}")

    await send_text(device, text)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
