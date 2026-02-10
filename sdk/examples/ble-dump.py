#!/usr/bin/env python3
"""Dump all readable BLE characteristics from G2 glasses."""
import asyncio
from bleak import BleakClient, BleakScanner

KNOWN_UUIDS = {
    "00002a00": "Device Name",
    "00002a01": "Appearance",
    "00002a04": "Peripheral Preferred Connection Parameters",
    "00002a05": "Service Changed",
    "00002a24": "Model Number String",
    "00002a25": "Serial Number String",
    "00002a26": "Firmware Revision String",
    "00002a27": "Hardware Revision String",
    "00002a28": "Software Revision String",
    "00002a29": "Manufacturer Name String",
    "00002a19": "Battery Level",
    "00002a23": "System ID",
    "00002a50": "PnP ID",
}

async def main():
    print("Scanning for G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 found!")
        return

    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Connecting to {device.name} ({device.address})...\n")

    async with BleakClient(device) as client:
        print(f"Connected: {client.is_connected}\n")

        for service in client.services:
            print(f"Service: {service.uuid}")
            print(f"  Description: {service.description or '(unknown)'}")

            for char in service.characteristics:
                short_uuid = char.uuid[:8]
                name = KNOWN_UUIDS.get(short_uuid, char.description or "")
                props = ", ".join(char.properties)
                print(f"  Char: {char.uuid}  [{props}]  {name}")

                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        # Try as string
                        try:
                            text = value.decode("utf-8")
                            if all(32 <= ord(c) < 127 for c in text):
                                print(f"    Value: \"{text}\"")
                            else:
                                print(f"    Value: {value.hex()} (bytes)")
                        except:
                            print(f"    Value: {value.hex()} (bytes)")
                    except Exception as e:
                        print(f"    Read error: {e}")

                for desc in char.descriptors:
                    print(f"    Desc: {desc.uuid} = {desc.description}")
            print()

asyncio.run(main())
