/**
 * Cycle through navigation direction icons on G2 glasses.
 *
 * 1. Start the bridge:  python bridge/server.py
 * 2. Run this script:   npx tsx sdk/examples/nav-directions.ts
 */
import { G2 } from "../src/index.js";

const DIRECTIONS: Record<number, string> = {
  0: "none/straight?",
  1: "straight",
  2: "slight right",
  3: "right",
  4: "sharp right",
  5: "u-turn right",
  6: "slight left",
  7: "left",
  8: "sharp left",
  9: "u-turn left",
  10: "arrive",
  11: "roundabout",
  12: "merge",
  13: "fork",
  14: "highway",
  15: "unknown",
};

async function main() {
  const g = new G2();
  console.log("Connecting...");
  await g.connect();

  console.log("Starting navigation HUD...");
  await g.startNavigation();
  await new Promise((r) => setTimeout(r, 1000));

  for (let i = 0; i <= 15; i++) {
    const label = DIRECTIONS[i] ?? `icon ${i}`;
    console.log(`Direction ${i}: ${label}`);
    await g.setNavigation({
      direction: i,
      distance: `icon #${i}`,
      road: label,
      eta: "8:00 PM",
      speed: "30 mph",
      remainDistance: "2.0 mi",
    });
    await new Promise((r) => setTimeout(r, 2500));
  }

  console.log("Stopping navigation...");
  await g.stopNavigation();
  await g.close();
  console.log("Done.");
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
