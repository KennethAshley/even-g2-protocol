#!/usr/bin/env python3
"""
Cycle through glasses app pages via G2Setting.DeviceReceive_APP_PAGE.

G2SettingPackage:
  commandId = 1 (DeviceReceiveInfo)
  magicRandom = msg_id
  field 3 = DeviceReceiveInfoFromAPP {
    field 7 = DeviceReceive_APP_PAGE { appPage = N }
  }

SID mapping from service_id_def.proto:
  0: Default        6: Teleprompter   11: Conversate
  1: Dashboard       7: Even AI        12: Quicklist
  3: Menu            8: Navigation
  4: Notification    9: Settings
  5: Translate      10: Transcribe
"""
import asyncio
import time
from bleak import BleakClient, BleakScanner

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

def build_auth():
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


def build_app_page(seq, msg_id, page, svc_hi):
    """
    G2SettingPackage {
      commandId = 1 (DeviceReceiveInfo)
      magicRandom = msg_id
      deviceReceiveInfoFromApp (f3) = {
        deviceReceiveAppPage (f7) = { appPage (f1) = page }
      }
    }
    """
    app_page = pb_varint(1, page)                    # DeviceReceive_APP_PAGE.appPage
    info_from_app = pb_bytes(7, app_page)             # DeviceReceiveInfoFromAPP.deviceReceiveAppPage
    payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, info_from_app)
    return build_aa_packet(seq, svc_hi, 0x20, payload)


PAGE_NAMES = {
    0: "Default",
    1: "Dashboard",
    3: "Menu",
    4: "Notification",
    5: "Translate",
    6: "Teleprompter",
    7: "Even AI",
    8: "Navigation",
    9: "Settings",
    10: "Transcribe",
    11: "Conversate",
    12: "Quicklist",
}


async def main():
    print("Scanning for G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 found!")
        return

    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Connecting to {device.name}...\n")

    async with BleakClient(device) as client:
        def on_notify(sender, data):
            svc_hi = data[6] if len(data) > 7 else 0
            svc_lo = data[7] if len(data) > 7 else 0
            print(f"  <- [0x{svc_hi:02x}-{svc_lo:02x}] {data.hex()}")

        await client.start_notify(CHAR_NOTIFY, on_notify)

        print("Authenticating...")
        for pkt in build_auth():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        print("Auth done.\n")

        seq = 0x08
        msg_id = 0x14

        # Try both service 0x09 (UI_SETTING_APP_ID) and 0x80 (UX_DEVICE_SETTINGS_APP_ID)
        for svc_hi, svc_name in [(0x80, "0x80-20"), (0x09, "0x09-20")]:
            print(f"\n{'='*50}")
            print(f"Trying app page switching on {svc_name}")
            print(f"{'='*50}")

            for page_id in [1, 11, 6, 8, 0]:
                name = PAGE_NAMES.get(page_id, f"unknown_{page_id}")
                print(f"\n--- Page {page_id}: {name} ---")
                pkt = build_app_page(seq, msg_id, page_id, svc_hi)
                print(f"  -> {pkt.hex()}")
                await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
                seq += 1; msg_id += 1
                await asyncio.sleep(3.0)

        print("\nDone.")


asyncio.run(main())
