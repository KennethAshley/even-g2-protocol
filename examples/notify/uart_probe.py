#!/usr/bin/env python3
"""
UART Protocol Probe for G2 Glasses

The EvenDemoApp uses Nordic UART for ALL commands including notifications.
But the G2 might need init commands before accepting UART traffic.

This script tests:
1. Init commands (0x4D for iOS, 0xF4 for Android)
2. Heartbeat (0x25) to establish session
3. Whitelist (0x04) then notification (0x4B)
4. Both write modes (with/without response)
"""

import asyncio
import json
import time
from bleak import BleakClient, BleakScanner

UART_TX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
UART_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

# Also subscribe to all Even protocol notify chars
UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
NOTIFY_CHARS = {
    "0002": UUID_BASE.format(0x0002),
    "5402": UUID_BASE.format(0x5402),
    "6402": UUID_BASE.format(0x6402),
    "7402": UUID_BASE.format(0x7402),
}


class Tracker:
    def __init__(self):
        self.responses = []
        self.event = asyncio.Event()

    def handler(self, label):
        def cb(sender, data):
            hex_str = data.hex()
            status = ""
            if len(data) >= 2:
                if data[1] == 0xC9:
                    status = " ** SUCCESS **"
                elif data[1] == 0xCB:
                    status = " ** ACK **"
            cmd = f"cmd=0x{data[0]:02X}" if len(data) >= 1 else ""
            print(f"  <- [{label}] ({len(data)}b) {cmd}: {hex_str[:60]}{'...' if len(hex_str) > 60 else ''}{status}")
            self.responses.append((label, bytes(data)))
            self.event.set()
        return cb

    async def wait(self, timeout=1.5):
        self.event.clear()
        try:
            await asyncio.wait_for(self.event.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False


async def try_write(client, tracker, char, data, label, use_response=False):
    """Write and wait for response"""
    mode = "w/resp" if use_response else "w/o resp"
    print(f"\n  [{label}] ({mode}) Writing {len(data)}b: {data[:12].hex()}{'...' if len(data) > 12 else ''}")
    try:
        await client.write_gatt_char(char, data, response=use_response)
        got = await tracker.wait(timeout=1.5)
        if not got:
            print(f"    No response")
        return True
    except Exception as e:
        print(f"    Write error: {e}")
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

    tracker = Tracker()

    async with BleakClient(device) as client:
        print("Connected!")

        # Subscribe to ALL notify characteristics
        await client.start_notify(UART_RX, tracker.handler("UART"))
        for label, uuid in NOTIFY_CHARS.items():
            try:
                await client.start_notify(uuid, tracker.handler(label))
            except Exception:
                pass

        await asyncio.sleep(0.3)

        # =================================================================
        # Phase 1: Init commands
        # =================================================================
        print("=" * 60)
        print("PHASE 1: Init Commands")
        print("=" * 60)

        # iOS init: 0x4D
        await try_write(client, tracker, UART_TX,
            bytes([0x4D, 0x01]), "iOS init (0x4D)")

        # Android init: 0xF4 with device info
        android_init = bytes([0xF4, 0x01, 0x00, 0x00])
        await try_write(client, tracker, UART_TX,
            android_init, "Android init (0xF4)")

        # Try with response=True
        await try_write(client, tracker, UART_TX,
            bytes([0x4D, 0x01]), "iOS init (0x4D) w/resp", use_response=True)

        # =================================================================
        # Phase 2: Heartbeat
        # =================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 2: Heartbeat")
        print("=" * 60)

        # Heartbeat from proto.dart: [0x25, seq_lo, seq_hi]
        heartbeat = bytes([0x25, 0x01, 0x00])
        await try_write(client, tracker, UART_TX,
            heartbeat, "Heartbeat (0x25)")

        await try_write(client, tracker, UART_TX,
            heartbeat, "Heartbeat w/resp", use_response=True)

        # =================================================================
        # Phase 3: Exit all first, then init fresh
        # =================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 3: Exit All + Fresh Init")
        print("=" * 60)

        # Exit all functions: 0x18
        await try_write(client, tracker, UART_TX,
            bytes([0x18]), "Exit all (0x18)")

        await asyncio.sleep(0.5)

        # Re-init
        await try_write(client, tracker, UART_TX,
            bytes([0x4D, 0x01]), "Re-init (0x4D)")

        # =================================================================
        # Phase 4: Whitelist + Notification
        # =================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 4: Whitelist + Notification")
        print("=" * 60)

        # Whitelist
        whitelist = json.dumps({
            "calendar_enable": False,
            "call_enable": False,
            "msg_enable": False,
            "ios_mail_enable": False,
            "app": {
                "list": [{"id": "com.even.test", "name": "Test"}],
                "enable": True
            }
        }, separators=(',', ':')).encode('utf-8')

        wl_pkt = bytes([0x04, 0x01, 0x00]) + whitelist
        await try_write(client, tracker, UART_TX,
            wl_pkt, "Whitelist (0x04)")

        await asyncio.sleep(0.5)

        # Notification
        notification = json.dumps({
            "ncs_notification": {
                "msg_id": 1,
                "app_identifier": "com.even.test",
                "title": "Test",
                "subtitle": "",
                "message": "Hello from Python!",
                "time_s": int(time.time() * 1000),
                "display_name": "Test"
            }
        }, separators=(',', ':')).encode('utf-8')

        # Single packet (fits in 176 bytes)
        notif_pkt = bytes([0x4B, 0x01, 0x01, 0x00]) + notification
        await try_write(client, tracker, UART_TX,
            notif_pkt, "Notification (0x4B)")

        # Also try with response=True
        await try_write(client, tracker, UART_TX,
            notif_pkt, "Notification w/resp", use_response=True)

        # =================================================================
        # Phase 5: Try writing UART commands to the Even protocol channel
        # =================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 5: UART Commands on Even Protocol Channel (0x5401)")
        print("=" * 60)

        even_write = UUID_BASE.format(0x5401)

        # Maybe the G2 routes UART-style commands through the main channel?
        await try_write(client, tracker, even_write,
            bytes([0x4D, 0x01]), "Init on 0x5401")

        await try_write(client, tracker, even_write,
            wl_pkt, "Whitelist on 0x5401")

        await try_write(client, tracker, even_write,
            notif_pkt, "Notification on 0x5401")

        # =================================================================
        # Phase 6: Try 0x0001 characteristic (undocumented first channel)
        # =================================================================
        print(f"\n{'=' * 60}")
        print("PHASE 6: Commands on 0x0001 (First Channel)")
        print("=" * 60)

        first_write = UUID_BASE.format(0x0001)

        await try_write(client, tracker, first_write,
            bytes([0x4D, 0x01]), "Init on 0x0001")

        await try_write(client, tracker, first_write,
            notif_pkt, "Notification on 0x0001")

        # =================================================================
        # Summary
        # =================================================================
        print(f"\n{'=' * 60}")
        print("SUMMARY")
        print("=" * 60)
        print(f"Total responses: {len(tracker.responses)}")
        for label, data in tracker.responses:
            cmd = f"0x{data[0]:02X}" if data else "?"
            print(f"  [{label}] cmd={cmd} data={data.hex()[:60]}")

        if not tracker.responses:
            print("\n  NO RESPONSES on any channel.")
            print("  The G2 may require AA-header protocol for ALL commands,")
            print("  wrapping the 0x4B notification in an AA packet.")

        print("\n  Check your glasses - did anything appear?")
        await asyncio.sleep(3.0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
