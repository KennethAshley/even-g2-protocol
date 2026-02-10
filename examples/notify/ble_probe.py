#!/usr/bin/env python3
"""
BLE Probe - Listen on ALL Even G2 notification channels.

Subscribes to every notify characteristic to see if the glasses
send initialization data that we need to respond to before
dashboard commands are accepted.
"""

import asyncio
import time
from bleak import BleakClient, BleakScanner

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"

# All known characteristics
CHANNELS = {
    "0002": UUID_BASE.format(0x0002),  # Unknown service notify
    "5402": UUID_BASE.format(0x5402),  # Main protocol notify
    "6402": UUID_BASE.format(0x6402),  # Display notify
    "7402": UUID_BASE.format(0x7402),  # Unknown service notify
}

WRITE_CHANNELS = {
    "0001": UUID_BASE.format(0x0001),  # Unknown service write
    "5401": UUID_BASE.format(0x5401),  # Main protocol write
    "6401": UUID_BASE.format(0x6401),  # Display/echo write
    "7401": UUID_BASE.format(0x7401),  # Unknown service write
}

# NUS (Nordic UART)
NUS_RX = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  # write
NUS_TX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  # notify


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


async def main():
    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 glasses found!")
        return
    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Using: {device.name}\n")

    traffic = {ch: [] for ch in CHANNELS}
    traffic["NUS"] = []

    def make_handler(label):
        def cb(_, data):
            ts = time.time()
            traffic[label].append((ts, bytes(data)))
            svc_info = ""
            if len(data) >= 8 and data[0] == 0xAA:
                svc_id = data[6]
                status = data[7]
                result_code = (status >> 1) & 0x0F
                notify_flag = status & 0x01
                svc_info = f" svc=0x{svc_id:02X} result={result_code} notify={notify_flag}"
            print(f"  <- [{label}] ({len(data):3d}b){svc_info}: {data.hex()[:80]}")
        return cb

    async with BleakClient(device) as client:
        print("Connected!\n")

        # Subscribe to ALL notification channels
        print("Subscribing to all notify channels...")
        for label, uuid in CHANNELS.items():
            try:
                await client.start_notify(uuid, make_handler(label))
                print(f"  Subscribed: {label}")
            except Exception as e:
                print(f"  Failed {label}: {e}")

        # NUS
        try:
            await client.start_notify(NUS_TX, make_handler("NUS"))
            print(f"  Subscribed: NUS TX")
        except Exception as e:
            print(f"  Failed NUS: {e}")

        print()

        # Wait before auth to see if glasses send anything unsolicited
        print("Waiting 3s before auth for unsolicited traffic...")
        await asyncio.sleep(3.0)
        pre_auth = sum(len(v) for v in traffic.values())
        print(f"  Pre-auth traffic: {pre_auth} packets\n")

        # Auth
        print("Authenticating on 0x5401...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(WRITE_CHANNELS["5401"], pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        post_auth = sum(len(v) for v in traffic.values())
        print(f"  Post-auth traffic: {post_auth} packets\n")

        # Try writing auth to OTHER channels too
        print("Trying auth on 0x0001...")
        try:
            for pkt in build_auth_packets():
                await client.write_gatt_char(WRITE_CHANNELS["0001"], pkt, response=False)
                await asyncio.sleep(0.1)
            await asyncio.sleep(1.0)
        except Exception as e:
            print(f"  Error: {e}")
        post_0001 = sum(len(v) for v in traffic.values())
        print(f"  After 0x0001 auth: {post_0001} packets\n")

        # Try writing to NUS
        print("Trying hello on NUS...")
        try:
            await client.write_gatt_char(NUS_RX, b"EVEN\x00", response=False)
            await asyncio.sleep(1.0)
        except Exception as e:
            print(f"  Error: {e}")

        # Now try a simple dashboard command after all this
        print("\nSending dashboard command on 0x5401...")
        payload = bytes.fromhex("0802101922131211080410031a0301020320042a0401030202")
        header = bytes([0xAA, 0x21, 0x20, len(payload) + 2, 0x01, 0x01, 0x01, 0x20])
        pkt = add_crc(header + payload)
        await client.write_gatt_char(WRITE_CHANNELS["5401"], pkt, response=False)
        await asyncio.sleep(0.5)

        # Also try dashboard on other write channels
        for ch_label in ["0001", "7401"]:
            print(f"  Trying dashboard on {ch_label}...")
            try:
                await client.write_gatt_char(WRITE_CHANNELS[ch_label], pkt, response=False)
                await asyncio.sleep(0.5)
            except Exception as e:
                print(f"    Error: {e}")

        # Monitor
        print("\nMonitoring all channels for 10s...")
        for i in range(10):
            await asyncio.sleep(1.0)
            counts = {k: len(v) for k, v in traffic.items()}
            active = {k: v for k, v in counts.items() if v > 0}
            print(f"  [{i+1:2d}s] {active}")

        # Summary
        print(f"\n{'='*60}")
        print("TRAFFIC SUMMARY")
        print(f"{'='*60}")
        for label, packets in traffic.items():
            if packets:
                print(f"\n  {label}: {len(packets)} packets")
                for ts, data in packets[:10]:
                    svc_info = ""
                    if len(data) >= 8 and data[0] == 0xAA:
                        svc_id = data[6]
                        status = data[7]
                        svc_info = f" svc=0x{svc_id:02X} st=0x{status:02X}"
                    print(f"    ({len(data):3d}b){svc_info}: {data.hex()[:80]}")
                if len(packets) > 10:
                    print(f"    ... and {len(packets) - 10} more")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
