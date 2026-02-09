#!/usr/bin/env python3
"""
G2 Deep Service Probe

Enumerates all BLE services/characteristics on the glasses, then
systematically sends notification-like payloads to every writable
characteristic to discover which service handles notifications.

Also tries:
- Notification metadata (0x02-20) followed by text on different services
- Multi-step sequences (wake -> config -> notify -> sync)
- Undocumented services (0x1001, 0x6450, 0x7450)
- Various protobuf type values for each service
"""

import asyncio
import time
from bleak import BleakClient, BleakScanner


# =============================================================================
# Protocol Primitives (from teleprompter.py)
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


def encode_varint_field(fn, val):
    return bytes([(fn << 3) | 0]) + encode_varint(val)


def encode_string_field(fn, text):
    data = text.encode('utf-8')
    return bytes([(fn << 3) | 2]) + encode_varint(len(data)) + data


def encode_submessage(fn, data):
    return bytes([(fn << 3) | 2]) + encode_varint(len(data)) + data


def build_packet(seq, svc_hi, svc_lo, payload):
    header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, svc_hi, svc_lo])
    return add_crc(header + payload)


UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)


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
# Main Probe
# =============================================================================

class Probe:
    def __init__(self):
        self.responses = []
        self.response_event = asyncio.Event()

    def handle_response(self, sender, data):
        hex_str = data.hex()
        svc = f"0x{data[6]:02X}{data[7]:02X}" if len(data) >= 8 else "?"
        print(f"    <- RESPONSE [{svc}] ({len(data)}b): {hex_str[:60]}{'...' if len(hex_str) > 60 else ''}")
        self.responses.append((svc, bytes(data)))
        self.response_event.set()

    async def wait_response(self, timeout=1.5):
        self.response_event.clear()
        try:
            await asyncio.wait_for(self.response_event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False


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
        print("Connected! Enumerating services...\n")

        # =====================================================================
        # Phase 1: Service enumeration
        # =====================================================================
        print("=" * 60)
        print("PHASE 1: BLE Service Enumeration")
        print("=" * 60)

        writable_chars = []
        notify_chars = []

        for service in client.services:
            print(f"\nService: {service.uuid}")
            print(f"  Description: {service.description or 'Unknown'}")
            for char in service.characteristics:
                props = ",".join(char.properties)
                print(f"  Char: {char.uuid} [{props}]")
                if "write-without-response" in char.properties or "write" in char.properties:
                    writable_chars.append(char.uuid)
                if "notify" in char.properties:
                    notify_chars.append(char.uuid)

        print(f"\nWritable characteristics: {len(writable_chars)}")
        print(f"Notify characteristics: {len(notify_chars)}")

        # =====================================================================
        # Phase 2: Auth + subscribe to all notify chars
        # =====================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 2: Authentication")
        print("=" * 60)

        # Subscribe to all notify characteristics
        for nc in notify_chars:
            try:
                await client.start_notify(nc, probe.handle_response)
                print(f"  Subscribed to {nc}")
            except Exception as e:
                print(f"  Failed to subscribe to {nc}: {e}")

        # Authenticate
        print("\n  Sending auth sequence...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print(f"  Auth complete ({len(probe.responses)} responses)")

        seq = 0x08
        msg_id = 0x14

        # =====================================================================
        # Phase 3: Test notification payloads on every known service
        # =====================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 3: Systematic Service Probing")
        print("=" * 60)

        # Services to test with notification-like payloads
        test_services = [
            (0x02, 0x20, "Notification"),
            (0x02, 0x00, "Notification Control"),
            (0x04, 0x20, "Display Wake"),
            (0x07, 0x20, "Dashboard"),
            (0x09, 0x00, "Device Info"),
            (0x09, 0x20, "Device Info Data"),
            (0x0B, 0x20, "Conversate"),
            (0x0C, 0x20, "Tasks"),
            (0x0D, 0x00, "Configuration"),
            (0x0D, 0x20, "Configuration Data"),
            (0x0E, 0x20, "Display Config"),
            (0x10, 0x20, "Service 0x10"),
            (0x11, 0x20, "Conversate Alt"),
            (0x20, 0x20, "Commit"),
        ]

        # Notification text payload - try text in fields 3, 4, 5, 7
        text = "Hello World"
        title = "Test"

        for svc_hi, svc_lo, name in test_services:
            initial = len(probe.responses)

            # Build a generic payload with text at multiple field positions
            payload = (
                encode_varint_field(1, 1) +         # type = 1
                encode_varint_field(2, msg_id) +     # msg_id
                encode_submessage(3,                  # field 3: submessage with text
                    encode_varint_field(1, 0x1A) +   # app_id (Gmail)
                    encode_varint_field(2, 1) +       # count
                    encode_string_field(3, title) +   # title
                    encode_string_field(4, text) +    # body
                    encode_string_field(5, "com.test") # app identifier
                )
            )

            pkt = build_packet(seq, svc_hi, svc_lo, payload)
            print(f"\n  [{svc_hi:02X}-{svc_lo:02X}] {name}: sending notification payload...")

            try:
                await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            except Exception as e:
                print(f"    Write failed: {e}")
                seq += 1; msg_id += 1
                continue

            seq += 1; msg_id += 1
            got = await probe.wait_response(timeout=1.0)

            new = len(probe.responses) - initial
            if new > 0:
                print(f"    ** GOT {new} RESPONSE(S)! **")
            else:
                print(f"    No response")

        # =====================================================================
        # Phase 4: Test undocumented characteristics directly
        # =====================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 4: Undocumented Characteristic Probing")
        print("=" * 60)

        # Try writing notification payload to each writable characteristic
        notification_payload = (
            encode_varint_field(1, 1) +
            encode_varint_field(2, msg_id) +
            encode_submessage(3,
                encode_string_field(1, title) +
                encode_string_field(2, text)
            )
        )

        # Build as raw AA packet (for protocol chars) and raw protobuf (for others)
        for wc in writable_chars:
            if wc == CHAR_WRITE:
                continue  # Already tested via service probing

            initial = len(probe.responses)
            print(f"\n  Char {wc}: raw protobuf write...")

            try:
                # Try raw protobuf (no AA header)
                await client.write_gatt_char(wc, notification_payload, response=False)
                seq += 1; msg_id += 1
                got = await probe.wait_response(timeout=1.0)
                new = len(probe.responses) - initial
                if new > 0:
                    print(f"    ** GOT {new} RESPONSE(S)! **")
                else:
                    print(f"    No response")
            except Exception as e:
                print(f"    Write failed: {e}")

        # =====================================================================
        # Phase 5: Try notification metadata + sync sequence
        # =====================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 5: Multi-step Notification Sequences")
        print("=" * 60)

        sequences = [
            ("Wake -> NotifMeta -> Sync", [
                ("wake", 0x04, 0x20,
                    encode_varint_field(1, 1) + encode_varint_field(2, msg_id) +
                    encode_submessage(3,
                        encode_varint_field(1, 1) + encode_varint_field(2, 1) +
                        encode_varint_field(3, 5) + encode_varint_field(5, 1)
                    )),
                ("notif_meta", 0x02, 0x20,
                    encode_varint_field(1, 1) + encode_varint_field(2, msg_id + 1) +
                    encode_submessage(3,
                        encode_varint_field(1, 0x1A) + encode_varint_field(2, 1)
                    )),
                ("notif_text", 0x02, 0x20,
                    encode_varint_field(1, 2) + encode_varint_field(2, msg_id + 2) +
                    encode_submessage(3,
                        encode_varint_field(1, 0x1A) + encode_varint_field(2, 1) +
                        encode_string_field(3, title) + encode_string_field(4, text)
                    )),
                ("sync", 0x80, 0x00,
                    bytes([0x08, 0x0E, 0x10]) + encode_varint(msg_id + 3) + bytes([0x6A, 0x00])),
            ]),
            ("Config -> Wake -> Conversate(type=3)", [
                ("config", 0x0E, 0x20, None),  # Will use display config
                ("wake", 0x04, 0x20,
                    encode_varint_field(1, 1) + encode_varint_field(2, msg_id + 5) +
                    encode_submessage(3,
                        encode_varint_field(1, 1) + encode_varint_field(2, 1) +
                        encode_varint_field(3, 5) + encode_varint_field(5, 1)
                    )),
                ("conversate_t3", 0x0B, 0x20,
                    encode_varint_field(1, 3) + encode_varint_field(2, msg_id + 6) +
                    encode_submessage(7,
                        encode_string_field(1, f"{title}: {text}") +
                        encode_varint_field(2, 1)
                    )),
                ("sync", 0x80, 0x00,
                    bytes([0x08, 0x0E, 0x10]) + encode_varint(msg_id + 7) + bytes([0x6A, 0x00])),
            ]),
        ]

        for seq_name, steps in sequences:
            initial = len(probe.responses)
            print(f"\n  Sequence: {seq_name}")

            for step_name, svc_hi, svc_lo, payload in steps:
                if payload is None:
                    # Use display config
                    config = bytes.fromhex(
                        "0801121308021090" "4E1D00E094442500" "000000280030001213"
                        "0803100D0F1D0040" "8D44250000000028" "0030001212080410"
                        "001D0000884225" "00000000280030" "001212080510001D"
                        "00009242250000" "A242280030001212" "080610001D0000C6"
                        "42250000C4422800" "30001800"
                    )
                    payload = bytes([0x08, 0x02, 0x10]) + encode_varint(msg_id) + bytes([0x22, 0x6A]) + config

                pkt = build_packet(seq, svc_hi, svc_lo, payload)
                print(f"    Step [{step_name}]: {svc_hi:02X}-{svc_lo:02X}")
                try:
                    await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
                except Exception as e:
                    print(f"      Write failed: {e}")
                seq += 1; msg_id += 1
                await asyncio.sleep(0.3)

            await asyncio.sleep(2.0)
            new = len(probe.responses) - initial
            print(f"    Sequence result: {new} response(s)")

        # =====================================================================
        # Summary
        # =====================================================================
        print(f"\n{'=' * 60}")
        print("SUMMARY")
        print("=" * 60)
        print(f"Total responses received: {len(probe.responses)}")
        print(f"\nAll responses by service:")
        svc_counts = {}
        for svc, data in probe.responses:
            svc_counts[svc] = svc_counts.get(svc, 0) + 1
        for svc, count in sorted(svc_counts.items()):
            print(f"  {svc}: {count} response(s)")

        print(f"\nCheck your glasses - did anything appear on the display?")
        print(f"If so, note the timestamp to correlate with the probe above.")

        await asyncio.sleep(3.0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
