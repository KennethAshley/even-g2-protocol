/**
 * Send a raw command and watch all responses for 5 seconds.
 */
import { G2 } from "../src/index.js";

function sendRaw(g: G2, svcHi: number, svcLo: number, payload: string, wait: number): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const ws = (g as any).ws as WebSocket;
    const id = String(Date.now());
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

async function main() {
  const g = new G2();

  g.on("response", (data) => {
    console.log("[event] response:", data.raw);
  });
  g.on("disconnected", (data) => {
    console.log("[event] disconnected:", data.reason);
  });

  console.log("Connecting...");
  await g.connect();
  console.log("Connected. Waiting 1s for dust to settle...\n");
  await new Promise((r) => setTimeout(r, 1000));

  // GET_DEVICE_INFO on 0x80-20
  // commandId=12, magicRandom=1, field 11 (getDeviceInfo) = { field 1 (infoValue) = { field 1 (cfgInfoItem) = 0 (ALL_INFO) } }
  console.log("--- Sending GET_DEVICE_INFO on 0x80-20 ---");
  const r1 = await sendRaw(g, 0x80, 0x20, "080c10015a040a020800", 3.0);
  console.log("sendRaw returned:", r1.length, "responses");
  for (const r of r1) console.log("  ", r);

  console.log("\n--- Sending GET_DEVICE_INFO on 0x80-00 ---");
  const r2 = await sendRaw(g, 0x80, 0x00, "080c10015a040a020800", 3.0);
  console.log("sendRaw returned:", r2.length, "responses");
  for (const r of r2) console.log("  ", r);

  await g.close();
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
