/**
 * Example: Send text to Even G2 glasses
 *
 * 1. Start the bridge:  python bridge/server.py
 * 2. Run this script:   npx tsx sdk/examples/hello.ts
 */

import { G2 } from "../src/index.js";

const glasses = new G2();

glasses.on("connected", (data) => {
  console.log("Glasses connected:", data.device);
});

glasses.on("disconnected", (data) => {
  console.log("Glasses disconnected:", data.reason);
});

glasses.on("response", (data) => {
  console.log("Glasses response:", data.raw);
});

async function main() {
  console.log("Connecting to G2 glasses...");
  await glasses.connect();

  console.log("Sending text...");
  await glasses.setText("It works!");

  console.log("Done! Text should appear on glasses.");

  // Keep alive for a bit to receive events
  await new Promise((r) => setTimeout(r, 3000));

  await glasses.close();
  console.log("Disconnected.");
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
