/**
 * Dump device info from Even G2 glasses.
 *
 * Tries GET_DEVICE_INFO on multiple service IDs to find the right one.
 *
 * 1. Start the bridge:  python bridge/server.py
 * 2. Run this script:   npx tsx sdk/examples/device-info.ts
 */

import { G2 } from "../src/index.js";

function encodeVarint(value: number): number[] {
  const result: number[] = [];
  while (value > 0x7f) {
    result.push((value & 0x7f) | 0x80);
    value >>= 7;
  }
  result.push(value & 0x7f);
  return result;
}

function pbVarint(field: number, value: number): number[] {
  return [(field << 3) | 0, ...encodeVarint(value)];
}

function pbBytes(field: number, data: number[]): number[] {
  return [(field << 3) | 2, ...encodeVarint(data.length), ...data];
}

function toHex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function parseProtobuf(hex: string): Record<string, unknown>[] {
  const bytes = Buffer.from(hex, "hex");
  const fields: Record<string, unknown>[] = [];
  let pos = 0;
  while (pos < bytes.length) {
    if (pos >= bytes.length) break;
    const tag = bytes[pos++];
    const fieldNum = tag >> 3;
    const wireType = tag & 0x07;
    if (wireType === 0) {
      let value = 0, shift = 0;
      while (pos < bytes.length) {
        const b = bytes[pos++];
        value |= (b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
      }
      fields.push({ field: fieldNum, type: "varint", value });
    } else if (wireType === 2) {
      let len = 0, shift = 0;
      while (pos < bytes.length) {
        const b = bytes[pos++];
        len |= (b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
      }
      const data = bytes.subarray(pos, pos + len);
      pos += len;
      let str: string | null = null;
      try {
        const s = data.toString("utf-8");
        if (s.length > 0 && /^[\x20-\x7e\r\n\t]+$/.test(s)) str = s;
      } catch {}
      fields.push({ field: fieldNum, type: "bytes", hex: data.toString("hex"), string: str, length: len });
    } else if (wireType === 5) {
      const value = bytes.readUInt32LE(pos);
      pos += 4;
      fields.push({ field: fieldNum, type: "fixed32", value });
    } else if (wireType === 1) {
      const value = bytes.readBigUInt64LE(pos);
      pos += 8;
      fields.push({ field: fieldNum, type: "fixed64", value: value.toString() });
    } else {
      break;
    }
  }
  return fields;
}

function sendRaw(g: G2, svcHi: number, svcLo: number, payload: string, wait: number): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const ws = (g as any).ws as WebSocket;
    const id = String(Date.now()) + Math.random();
    const msg = JSON.stringify({ id, method: "sendRaw", params: { svcHi, svcLo, payload, wait } });
    const handler = (e: MessageEvent) => {
      try {
        const data = JSON.parse(String(e.data));
        if (data.id === id) {
          ws.removeEventListener("message", handler);
          if (data.error) reject(new Error(data.error.message));
          else resolve(data.result?.responses ?? []);
        }
      } catch {}
    };
    ws.addEventListener("message", handler);
    ws.send(msg);
  });
}

function printResponse(raw: string) {
  if (raw.length <= 20) {
    console.log("    Short:", raw);
    return;
  }
  const svcHi = parseInt(raw.slice(12, 14), 16);
  const svcLo = parseInt(raw.slice(14, 16), 16);
  const payloadHex = raw.slice(16, raw.length - 4);
  console.log(`    Service: 0x${svcHi.toString(16).padStart(2, "0")}-${svcLo.toString(16).padStart(2, "0")}  Payload: ${payloadHex}`);
  if (payloadHex) {
    const fields = parseProtobuf(payloadHex);
    for (const f of fields) {
      if (f.type === "bytes") {
        console.log(`      f${f.field}: [${f.length}B] ${f.hex}${f.string ? ` = "${f.string}"` : ""}`);
        const nested = parseProtobuf(f.hex as string);
        if (nested.length > 0) {
          for (const n of nested) {
            if (n.type === "bytes") {
              console.log(`        f${n.field}: [${n.length}B] ${n.hex}${n.string ? ` = "${n.string}"` : ""}`);
            } else {
              console.log(`        f${n.field}: ${n.value} (${n.type})`);
            }
          }
        }
      } else {
        console.log(`      f${f.field}: ${f.value} (${f.type})`);
      }
    }
  }
}

async function main() {
  const g = new G2();
  console.log("Connecting to G2 glasses...");
  await g.connect();
  console.log("Connected!\n");

  // GET_DEVICE_INFO payload: commandId=12, magicRandom=1, field 11 = DeviceInfo{infoValue:[{cfgInfoItem:ALL_INFO}]}
  const deviceInfoValue = pbVarint(1, 0); // cfgInfoItem = ALL_INFO
  const deviceInfo = pbBytes(1, deviceInfoValue); // repeated DeviceInfoValue
  const payload = toHex([
    ...pbVarint(1, 12),       // commandId = GET_DEVICE_INFO
    ...pbVarint(2, 1),        // magicRandom
    ...pbBytes(11, deviceInfo), // getDeviceInfo (field 11)
  ]);

  // Try multiple service IDs
  const services = [
    [0x80, 0x20, "DevConfig (0x80-20)"],
    [0x80, 0x00, "DevConfig (0x80-00)"],
    [0x09, 0x20, "DevInfo (0x09-20)"],
    [0x09, 0x00, "DevInfo (0x09-00)"],
  ] as const;

  for (const [hi, lo, name] of services) {
    console.log(`\n--- Trying ${name} ---`);
    console.log(`  Payload: ${payload}`);
    const resps = await sendRaw(g, hi, lo, payload, 1.5);
    console.log(`  Got ${resps.length} response(s)`);
    for (const r of resps) {
      printResponse(r);
    }
  }

  // Also try just querying individual items on whichever service worked
  // Try GLASSES_SN (6) and BLE_MAC (8) on 0x80-20
  for (const [itemId, name] of [[6, "GLASSES_SN"], [7, "DEVICE_SN"], [8, "BLE_MAC"]] as const) {
    const div = pbVarint(1, itemId);
    const di = pbBytes(1, div);
    const p = toHex([...pbVarint(1, 12), ...pbVarint(2, 1), ...pbBytes(11, di)]);
    console.log(`\n--- ${name} on 0x80-20 ---`);
    const resps = await sendRaw(g, 0x80, 0x20, p, 1.0);
    console.log(`  Got ${resps.length} response(s)`);
    for (const r of resps) printResponse(r);
  }

  await g.close();
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
