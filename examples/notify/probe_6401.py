#!/usr/bin/env python3
"""
Probe characteristic 0x6401 - the undocumented display rendering channel.

Discovery: 0x6401 accepts RAW protobuf (no AA header) and echoes responses
on 0x6402. This is different from the main protocol channel (0x5401/0x5402).

This script systematically tests different protobuf payloads on 0x6401
to discover the notification display format.
"""

import asyncio
import time
from bleak import BleakClient, BleakScanner


UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)      # Main protocol (AA-header)
CHAR_NOTIFY = UUID_BASE.format(0x5402)     # Main protocol responses
CHAR_DISPLAY_W = UUID_BASE.format(0x6401)  # Display channel write (raw protobuf!)
CHAR_DISPLAY_N = UUID_BASE.format(0x6402)  # Display channel notify
CHAR_EXTRA_W = UUID_BASE.format(0x7401)    # Third channel write
CHAR_EXTRA_N = UUID_BASE.format(0x7402)    # Third channel notify
CHAR_FIRST_W = UUID_BASE.format(0x0001)    # First channel write
CHAR_FIRST_N = UUID_BASE.format(0x0002)    # First channel notify


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


def v(fn, val):
    """Encode varint field"""
    return bytes([(fn << 3) | 0]) + encode_varint(val)


def s(fn, text):
    """Encode string field"""
    data = text.encode('utf-8')
    return bytes([(fn << 3) | 2]) + encode_varint(len(data)) + data


def sub(fn, data):
    """Encode submessage field"""
    return bytes([(fn << 3) | 2]) + encode_varint(len(data)) + data


def build_aa_packet(seq, svc_hi, svc_lo, payload):
    header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, svc_hi, svc_lo])
    return add_crc(header + payload)


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


class Probe:
    def __init__(self):
        self.responses = {}  # char_uuid -> list of (data,)

    def make_handler(self, label):
        def handler(sender, data):
            hex_str = data.hex()
            print(f"    <- [{label}] ({len(data)}b): {hex_str[:80]}{'...' if len(hex_str) > 80 else ''}")
            self.responses.setdefault(label, []).append(bytes(data))
        return handler


async def main():
    print("Scanning for G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 found!")
        return

    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Using: {device.name}\n")

    probe = Probe()

    async with BleakClient(device) as client:
        # Subscribe to ALL notify channels
        await client.start_notify(CHAR_NOTIFY, probe.make_handler("5402"))
        await client.start_notify(CHAR_DISPLAY_N, probe.make_handler("6402"))
        await client.start_notify(CHAR_EXTRA_N, probe.make_handler("7402"))
        await client.start_notify(CHAR_FIRST_N, probe.make_handler("0002"))
        # UART RX
        try:
            await client.start_notify("6e400003-b5a3-f393-e0a9-e50e24dcca9e", probe.make_handler("UART"))
        except Exception:
            pass

        # Authenticate via main channel
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print("Auth complete.\n")

        # =================================================================
        # Test various payloads on 0x6401
        # =================================================================
        print("=" * 60)
        print("PROBING 0x6401 (Display Rendering Channel)")
        print("=" * 60)

        msg_id = 1
        experiments = [
            # -- Simple text payloads --
            ("Plain text string", s(1, "Hello World")),
            ("Title + body strings", s(1, "Test") + s(2, "Hello World")),

            # -- Notification-like structures --
            ("Notif: type=1, submsg with title+body",
                v(1, 1) + v(2, msg_id) + sub(3, s(1, "Test") + s(2, "Hello World"))),

            ("Notif: type=2, app_id + title + body",
                v(1, 2) + v(2, msg_id + 1) + sub(3,
                    v(1, 0x1A) + v(2, 1) + s(3, "Test") + s(4, "Hello World"))),

            # -- NCS notification JSON (G1 style but raw) --
            ("NCS JSON notification",
                s(1, '{"ncs_notification":{"msg_id":1,"title":"Test","message":"Hello World","app_identifier":"com.test","display_name":"Test","type":"Add"}}')),

            # -- Conversate-style (field 7 transcript) --
            ("Conversate transcript",
                v(1, 1) + v(2, msg_id + 2) + sub(7, s(1, "Test: Hello World") + v(2, 1))),

            # -- Dashboard widget style --
            ("Dashboard with text widget",
                v(1, 1) + v(2, msg_id + 3) + sub(3, v(1, 1) + s(2, "Test\nHello World"))),

            # -- Try mimicking teleprompter content on display channel --
            ("Teleprompter content page format",
                v(1, 3) + v(2, msg_id + 4) + sub(5,
                    v(1, 0) + v(2, 10) + s(3, "\nTest\nHello World\n \n \n \n \n \n \n \n"))),

            # -- Simple key-value pairs at different field positions --
            ("Fields 1-5 all strings",
                s(1, "Test") + s(2, "Hello World") + s(3, "notification") +
                s(4, "com.test") + s(5, "1")),

            # -- Try with AA header on display channel --
            ("AA-header notification on 0x6401", None),  # Special case

            # -- Notification with type bytes like 0x4B --
            ("0x4B command prefix + JSON",
                bytes([0x4B]) + '{"ncs_notification":{"msg_id":1,"title":"Test","message":"Hello World"}}'.encode('utf-8')),

            # -- Just raw UTF-8 text --
            ("Raw UTF-8 text", "Test: Hello World".encode('utf-8')),

            # -- Try wrapping in even-specific envelope --
            ("Even envelope: svc 0x02 + notif data",
                bytes([0x02, 0x20]) + v(1, 1) + v(2, msg_id + 5) + sub(3,
                    v(1, 0x1A) + v(2, 1) + s(3, "Test") + s(4, "Hello World"))),
        ]

        seq = 0x20
        for name, payload in experiments:
            print(f"\n  Experiment: {name}")

            if payload is None:
                # AA-header version on display channel
                inner = v(1, 1) + v(2, msg_id + 10) + sub(3,
                    v(1, 0x1A) + v(2, 1) + s(3, "Test") + s(4, "Hello World"))
                payload = build_aa_packet(seq, 0x02, 0x20, inner)
                # Write to display channel instead of main
                print(f"    -> Writing AA packet to 0x6401 ({len(payload)}b)")
                try:
                    await client.write_gatt_char(CHAR_DISPLAY_W, payload, response=False)
                except Exception as e:
                    print(f"    Write failed: {e}")
                seq += 1
                await asyncio.sleep(1.5)
                continue

            print(f"    -> Writing raw payload to 0x6401 ({len(payload)}b): {payload.hex()[:60]}...")
            try:
                await client.write_gatt_char(CHAR_DISPLAY_W, payload, response=False)
            except Exception as e:
                print(f"    Write failed: {e}")

            await asyncio.sleep(1.5)

        # =================================================================
        # Also test 0x0001 and 0x7401
        # =================================================================
        print(f"\n{'=' * 60}")
        print("PROBING 0x0001 and 0x7401")
        print("=" * 60)

        for char_name, char_uuid in [("0x0001", CHAR_FIRST_W), ("0x7401", CHAR_EXTRA_W)]:
            test_payload = v(1, 1) + v(2, msg_id + 20) + sub(3, s(1, "Test") + s(2, "Hello World"))
            print(f"\n  {char_name}: sending notification payload...")
            try:
                await client.write_gatt_char(char_uuid, test_payload, response=False)
            except Exception as e:
                print(f"    Write failed: {e}")
            await asyncio.sleep(1.5)

        # =================================================================
        # Try: notif metadata on main channel THEN text on display channel
        # =================================================================
        print(f"\n{'=' * 60}")
        print("COMBO: Notif metadata (0x5401) + Text (0x6401)")
        print("=" * 60)

        # Send notification metadata via main protocol
        notif_meta = v(1, 1) + v(2, msg_id + 30) + sub(3, v(1, 0x1A) + v(2, 1))
        pkt = build_aa_packet(seq, 0x02, 0x20, notif_meta)
        print("  Step 1: Notification metadata via 0x5401...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(0.5)

        # Then send text via display channel
        text_payload = s(1, "Test") + s(2, "Hello World from Python!")
        print("  Step 2: Text content via 0x6401...")
        await client.write_gatt_char(CHAR_DISPLAY_W, text_payload, response=False)
        await asyncio.sleep(0.5)

        # Sync trigger
        sync = bytes([0x08, 0x0E, 0x10]) + encode_varint(msg_id + 31) + bytes([0x6A, 0x00])
        pkt = build_aa_packet(seq, 0x80, 0x00, sync)
        print("  Step 3: Sync trigger...")
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1
        await asyncio.sleep(2.0)

        # =================================================================
        # Summary
        # =================================================================
        print(f"\n{'=' * 60}")
        print("SUMMARY")
        print("=" * 60)
        for label, resps in probe.responses.items():
            print(f"\n  Channel {label}: {len(resps)} response(s)")
            for i, data in enumerate(resps):
                print(f"    [{i}] {data.hex()[:80]}{'...' if len(data.hex()) > 80 else ''}")

        print(f"\n  ** Check your glasses! Did ANYTHING appear? **")
        await asyncio.sleep(3.0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
