import { G2 } from "../src/index.js";

const g = new G2();
await g.connect();
console.log("Connected, sending teleprompter...");
await g.setTeleprompter("SDK Test", "This text is displayed via the Teleprompter service, not Conversate. It supports multi-page scrolling and formatted layout.");
console.log("Done!");
await new Promise((r) => setTimeout(r, 2000));
await g.close();
