#!/usr/bin/env python3
"""
Even AI Display - Send Custom Q&A to G2 Glasses

Displays custom questions and answers on the Even AI card.
No Even app or cloud service required.

Usage:
    python even_ai.py "What is 2+2?" "The answer is 4!"
    python even_ai.py --question "Hello" --answer "Hi there!"

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


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT for packet framing."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def encode_varint(value: int) -> bytes:
    """Encode integer as protobuf varint."""
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def build_packet(seq: int, svc_hi: int, svc_lo: int, payload: bytes) -> bytes:
    """Build G2 packet with header and CRC."""
    header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, svc_hi, svc_lo])
    full = header + payload
    crc = crc16_ccitt(payload)
    return full + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def build_auth_packets() -> list:
    """Build 7-packet authentication sequence."""
    timestamp = int(time.time())
    ts_varint = encode_varint(timestamp)
    txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])

    packets = []

    # Auth 1-2: Capability exchange
    p1 = bytes([0xAA, 0x21, 0x01, 0x0C, 0x01, 0x01, 0x80, 0x00,
                0x08, 0x04, 0x10, 0x0C, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])
    packets.append(p1 + bytes([crc16_ccitt(p1[8:]) & 0xFF, (crc16_ccitt(p1[8:]) >> 8) & 0xFF]))

    p2 = bytes([0xAA, 0x21, 0x02, 0x0A, 0x01, 0x01, 0x80, 0x20,
                0x08, 0x05, 0x10, 0x0E, 0x22, 0x02, 0x08, 0x02])
    packets.append(p2 + bytes([crc16_ccitt(p2[8:]) & 0xFF, (crc16_ccitt(p2[8:]) >> 8) & 0xFF]))

    # Auth 3: Time sync
    payload3 = bytes([0x08, 0x80, 0x01, 0x10, 0x0F, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    p3 = bytes([0xAA, 0x21, 0x03, len(payload3) + 2, 0x01, 0x01, 0x80, 0x20]) + payload3
    packets.append(p3 + bytes([crc16_ccitt(payload3) & 0xFF, (crc16_ccitt(payload3) >> 8) & 0xFF]))

    # Auth 4-6: Additional exchanges
    p4 = bytes([0xAA, 0x21, 0x04, 0x0C, 0x01, 0x01, 0x80, 0x00,
                0x08, 0x04, 0x10, 0x10, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])
    packets.append(p4 + bytes([crc16_ccitt(p4[8:]) & 0xFF, (crc16_ccitt(p4[8:]) >> 8) & 0xFF]))

    p5 = bytes([0xAA, 0x21, 0x05, 0x0C, 0x01, 0x01, 0x80, 0x00,
                0x08, 0x04, 0x10, 0x11, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04])
    packets.append(p5 + bytes([crc16_ccitt(p5[8:]) & 0xFF, (crc16_ccitt(p5[8:]) >> 8) & 0xFF]))

    p6 = bytes([0xAA, 0x21, 0x06, 0x0A, 0x01, 0x01, 0x80, 0x20,
                0x08, 0x05, 0x10, 0x12, 0x22, 0x02, 0x08, 0x01])
    packets.append(p6 + bytes([crc16_ccitt(p6[8:]) & 0xFF, (crc16_ccitt(p6[8:]) >> 8) & 0xFF]))

    # Auth 7: Final time sync
    payload7 = bytes([0x08, 0x80, 0x01, 0x10, 0x13, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
    p7 = bytes([0xAA, 0x21, 0x07, len(payload7) + 2, 0x01, 0x01, 0x80, 0x20]) + payload7
    packets.append(p7 + bytes([crc16_ccitt(payload7) & 0xFF, (crc16_ccitt(payload7) >> 8) & 0xFF]))

    return packets


# ============================================================
# Even AI Protocol
# ============================================================

def build_ctrl_enter(seq: int, magic: int) -> bytes:
    """
    CTRL(ENTER) - Enter Even AI mode.
    REQUIRED before ASK/REPLY will display!
    """
    payload = bytes([
        0x08, 0x01,           # commandId = 1 (CTRL)
        0x10, magic,          # magicRandom
        0x1a, 0x02,           # ctrl field (field 3)
        0x08, 0x02            # status = 2 (EVEN_AI_ENTER)
    ])
    return build_packet(seq, 0x07, 0x20, payload)


def build_ctrl_exit(seq: int, magic: int) -> bytes:
    """CTRL(EXIT) - Exit Even AI mode."""
    payload = bytes([
        0x08, 0x01,           # commandId = 1 (CTRL)
        0x10, magic,          # magicRandom
        0x1a, 0x02,           # ctrl field
        0x08, 0x03            # status = 3 (EVEN_AI_EXIT)
    ])
    return build_packet(seq, 0x07, 0x20, payload)


def build_ask(seq: int, magic: int, text: str) -> bytes:
    """ASK - Display question text on glasses."""
    text_bytes = text.encode('utf-8')

    askinfo = bytes([
        0x08, 0x00,           # cmdCnt = 0
        0x10, 0x00,           # streamEnable = 0
        0x18, 0x00,           # textMode = 0
        0x22,                 # text field (field 4)
    ]) + encode_varint(len(text_bytes)) + text_bytes

    payload = bytes([
        0x08, 0x03,           # commandId = 3 (ASK)
        0x10, magic,          # magicRandom
        0x2a,                 # askInfo field (field 5)
    ]) + encode_varint(len(askinfo)) + askinfo

    return build_packet(seq, 0x07, 0x20, payload)


def build_reply(seq: int, magic: int, text: str) -> bytes:
    """REPLY - Display answer text on glasses."""
    text_bytes = text.encode('utf-8')

    replyinfo = bytes([
        0x08, 0x00,           # cmdCnt = 0
        0x10, 0x00,           # streamEnable = 0
        0x18, 0x00,           # textMode = 0
        0x22,                 # text field (field 4)
    ]) + encode_varint(len(text_bytes)) + text_bytes

    payload = bytes([
        0x08, 0x05,           # commandId = 5 (REPLY)
        0x10, magic,          # magicRandom
        0x3a,                 # replyInfo field (field 7)
    ]) + encode_varint(len(replyinfo)) + replyinfo

    return build_packet(seq, 0x07, 0x20, payload)


# ============================================================
# Main
# ============================================================

async def display_qa(client, question: str, answer: str):
    """Display a question and answer on the Even AI card."""
    seq = 0x08
    magic = 100

    # 1. Enter AI mode (REQUIRED!)
    print(f"  Entering AI mode...")
    await client.write_gatt_char(CHAR_WRITE, build_ctrl_enter(seq, magic), response=False)
    seq += 1
    magic += 1
    await asyncio.sleep(0.3)

    # 2. Display question
    print(f"  Displaying question: {question}")
    await client.write_gatt_char(CHAR_WRITE, build_ask(seq, magic, question), response=False)
    seq += 1
    magic += 1
    await asyncio.sleep(1.0)

    # 3. Display answer
    print(f"  Displaying answer: {answer}")
    await client.write_gatt_char(CHAR_WRITE, build_reply(seq, magic, answer), response=False)


async def main():
    import argparse
    parser = argparse.ArgumentParser(description='Display custom Q&A on G2 Even AI card')
    parser.add_argument('question', nargs='?', help='Question to display')
    parser.add_argument('answer', nargs='?', help='Answer to display')
    parser.add_argument('-q', '--question', dest='q', help='Question (alternative syntax)')
    parser.add_argument('-a', '--answer', dest='a', help='Answer (alternative syntax)')
    parser.add_argument('--left', action='store_true', help='Use left eye instead of right')

    args = parser.parse_args()

    # Handle both positional and named args
    question = args.question or args.q or "What is 2 + 2?"
    answer = args.answer or args.a or "The answer is 4!"

    print("Even G2 - Custom AI Display")
    print("=" * 50)

    print(f"\nScanning for G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)

    pattern = "_L_" if args.left else "_R_"
    device = next((d for d in devices if d.name and "G2" in d.name and pattern in d.name), None)

    if not device:
        print(f"ERROR: No G2 glasses found")
        for d in devices:
            if d.name and "G2" in d.name:
                print(f"  Found: {d.name}")
        return

    print(f"  Using: {device.name}")

    async with BleakClient(device) as client:
        print("  Connected!")

        await client.start_notify(CHAR_NOTIFY, lambda s, d: None)

        # Authenticate
        print("\nAuthenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
        print("  Authenticated!")

        # Display Q&A
        print(f"\nDisplaying Q&A...")
        await display_qa(client, question, answer)

        print("\n" + "=" * 50)
        print("Done! Check your glasses.")
        print("=" * 50)

        # Keep alive for viewing
        await asyncio.sleep(5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
