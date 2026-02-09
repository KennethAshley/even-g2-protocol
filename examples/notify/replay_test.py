#!/usr/bin/env python3
"""
Replay captured G2 notification protocol packets.

Sends the EXACT byte sequences captured from the official Even app
BLE traffic, testing each writable characteristic to find the correct one.

Protocol sequence discovered from capture analysis:
  1. File reference: 103-byte packet pointing to "user/notify_whitelist.json"
  2. Metadata: 11-byte transfer header
  3. JSON data: notification payload with 4-byte chunk header
"""

import asyncio
import json
import time
from datetime import datetime
from bleak import BleakClient, BleakScanner

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)
CHAR_DISPLAY_W = UUID_BASE.format(0x6401)
CHAR_DISPLAY_N = UUID_BASE.format(0x6402)
CHAR_EXTRA_W = UUID_BASE.format(0x7401)
CHAR_EXTRA_N = UUID_BASE.format(0x7402)
CHAR_FIRST_W = UUID_BASE.format(0x0001)
CHAR_FIRST_N = UUID_BASE.format(0x0002)
UART_SVC = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
UART_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
UART_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"


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


def build_file_reference(counter):
    """Build the file reference packet (103 bytes) - exact format from capture."""
    # Header: [counter] 01 01 00
    # Payload: 00 00 00 00 00 02 00 00 37 + "user/notify_whitelist.json" + null padding
    path = b"user/notify_whitelist.json"
    header = bytes([counter, 0x01, 0x01, 0x00])
    metadata = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x37])
    payload = header + metadata + path
    # Pad to 103 bytes total (matching captured packet)
    payload += bytes(103 - len(payload))
    # Add the last 6 bytes from capture: 32 1e 00 00 00 23 00 00 00 23
    # Actually just pad with zeros for now
    return payload


def build_metadata(counter, is_notification=False):
    """Build the 11-byte metadata/transfer header packet."""
    # Format from capture:
    # Whitelist: [counter] 03 01 01 00 01 00 00 01 00 00
    # Notification: [counter] 03 01 01 00 01 00 00 00 00 00
    header = bytes([counter, 0x03, 0x01, 0x01])
    if is_notification:
        data = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
    else:
        data = bytes([0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00])
    return header + data


def build_notification_packets(counter, msg_id, title, message, app_id, display_name):
    """Build notification JSON with correct chunk format."""
    now = datetime.now()
    notification = {
        "android_notification": {
            "msg_id": msg_id,
            "action": 0,
            "app_identifier": app_id,
            "title": title,
            "subtitle": "",
            "message": message,
            "time_s": int(time.time() * 1000),
            "date": now.strftime("%Y%m%dT%H%M%S"),
            "display_name": display_name,
        }
    }
    payload = json.dumps(notification, separators=(',', ':')).encode('utf-8')

    # Single chunk notification: [counter] 01 01 00 [json]
    # (from capture: notifications fit in one chunk)
    header = bytes([counter, 0x01, 0x01, 0x00])
    return [header + payload]


def build_whitelist_packets(counter):
    """Build full whitelist JSON matching captured format."""
    whitelist = {
        "calendar_enable": True,
        "call_enable": True,
        "msg_enable": True,
        "ios_mail_enable": True,
        "app": {
            "enable": True,
            "list": [
                {"id": "com.android.even_phone", "name": "Phone"},
                {"id": "com.android.even_sms", "name": "Messages"},
                {"id": "com.android.deskclock", "name": "Clock"},
                {"id": "com.discord", "name": "Discord"},
                {"id": "com.facebook.katana", "name": "Facebook"},
                {"id": "com.google.android.gm", "name": "Gmail"},
                {"id": "com.instagram.android", "name": "Instagram"},
                {"id": "com.microsoft.office.outlook", "name": "Outlook"},
                {"id": "com.Slack", "name": "Slack"},
                {"id": "com.snapchat.android", "name": "Snapchat"},
                {"id": "com.microsoft.teams", "name": "Teams"},
                {"id": "com.waze", "name": "Waze"},
            ]
        }
    }
    payload = json.dumps(whitelist, separators=(',', ':')).encode('utf-8')

    # Chunk into ~245 byte packets (matching captured chunk sizes)
    chunk_size = 245
    total = max(1, (len(payload) + chunk_size - 1) // chunk_size)
    packets = []
    for i in range(total):
        start = i * chunk_size
        end = min(start + chunk_size, len(payload))
        chunk = payload[start:end]
        header = bytes([counter, total, i + 1, 0x00])
        packets.append(header + chunk)
    return packets


class ResponseTracker:
    def __init__(self):
        self.responses = []

    def handler(self, label):
        def cb(sender, data):
            status = ""
            if len(data) >= 2:
                if data[1] == 0xC9: status = " [SUCCESS]"
                elif data[1] == 0xCB: status = " [ACK]"
            print(f"  <- [{label}] ({len(data)}b): {data.hex()[:60]}{status}")
            self.responses.append((label, bytes(data)))
        return cb


async def try_notification_on_char(client, tracker, char_uuid, char_name, counter_start):
    """Send the complete notification protocol sequence to a characteristic."""
    counter = counter_start

    print(f"\n{'='*50}")
    print(f"TESTING: {char_name}")
    print(f"{'='*50}")
    before = len(tracker.responses)

    try:
        # Step 1: File reference
        file_ref = build_file_reference(counter)
        print(f"  1. File ref ({len(file_ref)}b): {file_ref[:15].hex()}...")
        await client.write_gatt_char(char_uuid, file_ref, response=False)
        await asyncio.sleep(0.3)
        counter += 1

        # Step 2: Whitelist metadata
        wl_meta = build_metadata(counter, is_notification=False)
        print(f"  2. WL meta ({len(wl_meta)}b): {wl_meta.hex()}")
        await client.write_gatt_char(char_uuid, wl_meta, response=False)
        await asyncio.sleep(0.15)

        # Step 3: Whitelist data chunks
        wl_packets = build_whitelist_packets(counter)
        for i, pkt in enumerate(wl_packets):
            print(f"  3.{i+1} WL data ({len(pkt)}b): {pkt[:10].hex()}...")
            await client.write_gatt_char(char_uuid, pkt, response=False)
            await asyncio.sleep(0.15)
        counter += 1

        await asyncio.sleep(0.5)

        # Step 4: File reference again (before notification)
        file_ref2 = build_file_reference(counter)
        print(f"  4. File ref ({len(file_ref2)}b): {file_ref2[:15].hex()}...")
        await client.write_gatt_char(char_uuid, file_ref2, response=False)
        await asyncio.sleep(0.3)
        counter += 1

        # Step 5: Notification metadata
        notif_meta = build_metadata(counter, is_notification=True)
        print(f"  5. Notif meta ({len(notif_meta)}b): {notif_meta.hex()}")
        await client.write_gatt_char(char_uuid, notif_meta, response=False)
        await asyncio.sleep(0.15)

        # Step 6: Notification data
        notif_packets = build_notification_packets(
            counter, 1, "Test", "Hello from Python!",
            "com.google.android.gm", "Gmail"
        )
        for i, pkt in enumerate(notif_packets):
            print(f"  6.{i+1} Notif data ({len(pkt)}b): {pkt[:15].hex()}...")
            await client.write_gatt_char(char_uuid, pkt, response=False)
            await asyncio.sleep(0.15)

        await asyncio.sleep(1.5)
        new = len(tracker.responses) - before
        if new > 0:
            print(f"  ** {new} RESPONSE(S)! **")
        else:
            print(f"  (no responses)")
        return counter + 1

    except Exception as e:
        print(f"  ERROR: {e}")
        return counter + 1


async def main():
    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 glasses found!")
        return

    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Using: {device.name}\n")

    tracker = ResponseTracker()

    async with BleakClient(device) as client:
        # Subscribe to ALL notify channels
        for uuid, label in [
            (CHAR_NOTIFY, "5402"), (CHAR_DISPLAY_N, "6402"),
            (CHAR_EXTRA_N, "7402"), (CHAR_FIRST_N, "0002"),
        ]:
            try:
                await client.start_notify(uuid, tracker.handler(label))
            except Exception:
                pass
        try:
            await client.start_notify(UART_RX, tracker.handler("UART"))
        except Exception:
            pass

        # Auth on 0x5401
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print(f"Auth done ({len(tracker.responses)} responses)\n")

        # Test each writable characteristic with FULL protocol sequence
        counter = 0x40
        channels = [
            (CHAR_FIRST_W, "0x0001"),
            (CHAR_WRITE, "0x5401"),
            (CHAR_DISPLAY_W, "0x6401"),
            (CHAR_EXTRA_W, "0x7401"),
            (UART_TX, "UART TX"),
        ]

        for char_uuid, name in channels:
            counter = await try_notification_on_char(
                client, tracker, char_uuid, name, counter
            )

        # Also try UART with write-with-response (might trigger pairing)
        print(f"\n{'='*50}")
        print("TESTING: UART TX (write-with-response)")
        print(f"{'='*50}")
        try:
            counter2 = 0x70
            file_ref = build_file_reference(counter2)
            print(f"  1. File ref with response...")
            await client.write_gatt_char(UART_TX, file_ref, response=True)
            await asyncio.sleep(0.3)
            counter2 += 1
            notif_meta = build_metadata(counter2, is_notification=True)
            await client.write_gatt_char(UART_TX, notif_meta, response=True)
            await asyncio.sleep(0.15)
            notif_packets = build_notification_packets(
                counter2, 2, "Test", "Hello from Python!",
                "com.google.android.gm", "Gmail"
            )
            for pkt in notif_packets:
                await client.write_gatt_char(UART_TX, pkt, response=True)
                await asyncio.sleep(0.15)
            print("  Write-with-response succeeded!")
        except Exception as e:
            print(f"  ERROR: {e}")

        await asyncio.sleep(3.0)

        print(f"\n{'='*50}")
        print(f"RESULTS: {len(tracker.responses)} total responses")
        for label, data in tracker.responses:
            print(f"  [{label}] {data.hex()[:60]}")
        print(f"\nCheck glasses for any notification display!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
