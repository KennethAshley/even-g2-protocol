/**
 * Even G2 TypeScript SDK
 *
 * Control Even Realities G2 smart glasses via a Python BLE bridge.
 *
 * @example
 * ```ts
 * import { G2 } from "@anthropic/even-g2-sdk"
 *
 * const glasses = new G2()
 * await glasses.connect()
 * await glasses.setText("Meeting in 5 min — Room 302")
 * glasses.on("response", (data) => console.log("Glasses said:", data))
 * ```
 */

// --- Types ---

export interface G2Status {
  connected: boolean;
  device: string | null;
}

export interface G2NavigationData {
  /** Direction icon index (0-15). */
  direction?: number;
  /** Distance to next turn, e.g. "0.3 mi" */
  distance?: string;
  /** Road/instruction text, e.g. "Turn right on 5th Ave" */
  road?: string;
  /** Time spent so far, e.g. "2 min" */
  spendTime?: string;
  /** Remaining distance, e.g. "1.2 mi" */
  remainDistance?: string;
  /** ETA, e.g. "7:35 PM" */
  eta?: string;
  /** Current speed, e.g. "25 mph" */
  speed?: string;
}

export interface G2Options {
  /** WebSocket URL of the Python BLE bridge. Default: ws://localhost:8765 */
  url?: string;
  /** Auto-reconnect to bridge on disconnect. Default: true */
  autoReconnect?: boolean;
  /** Reconnect delay in ms. Default: 2000 */
  reconnectDelay?: number;
}

export type G2Event = "connected" | "disconnected" | "response";

type EventHandler = (data: Record<string, unknown>) => void;

interface PendingRequest {
  resolve: (value: Record<string, unknown>) => void;
  reject: (error: Error) => void;
}

// --- G2 Client ---

export class G2 {
  private url: string;
  private autoReconnect: boolean;
  private reconnectDelay: number;

  private ws: WebSocket | null = null;
  private pending = new Map<string, PendingRequest>();
  private listeners = new Map<G2Event, Set<EventHandler>>();
  private idCounter = 0;
  private closed = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options?: G2Options | string) {
    if (typeof options === "string") {
      this.url = options;
      this.autoReconnect = true;
      this.reconnectDelay = 2000;
    } else {
      this.url = options?.url ?? "ws://localhost:8765";
      this.autoReconnect = options?.autoReconnect ?? true;
      this.reconnectDelay = options?.reconnectDelay ?? 2000;
    }
  }

  // --- WebSocket lifecycle ---

  /** Connect to the BLE bridge WebSocket server. */
  connectBridge(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      this.closed = false;
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => resolve();

      this.ws.onerror = (e) => {
        if (this.ws?.readyState !== WebSocket.OPEN) {
          reject(new Error(`Bridge connection failed: ${this.url}`));
        }
      };

      this.ws.onclose = () => {
        // Reject all pending requests
        for (const [id, req] of this.pending) {
          req.reject(new Error("Bridge connection lost"));
        }
        this.pending.clear();

        if (this.autoReconnect && !this.closed) {
          this.scheduleReconnect();
        }
      };

      this.ws.onmessage = (e) => {
        this.handleMessage(String(e.data));
      };
    });
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      if (this.closed) return;
      try {
        await this.connectBridge();
      } catch {
        this.scheduleReconnect();
      }
    }, this.reconnectDelay);
  }

  private handleMessage(raw: string) {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    // Event (no id)
    if ("event" in msg) {
      const event = msg.event as G2Event;
      const data = (msg.data ?? {}) as Record<string, unknown>;
      this.emit(event, data);
      return;
    }

    // Response (has id)
    const id = msg.id as string;
    const req = this.pending.get(id);
    if (!req) return;
    this.pending.delete(id);

    if ("error" in msg) {
      const err = msg.error as { code: string; message: string };
      req.reject(new Error(`[${err.code}] ${err.message}`));
    } else {
      req.resolve((msg.result ?? {}) as Record<string, unknown>);
    }
  }

  /** Send a command to the bridge and wait for a response. */
  private send(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error("Not connected to bridge"));
        return;
      }

      const id = String(++this.idCounter);
      const msg: Record<string, unknown> = { id, method };
      if (params) msg.params = params;

      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(msg));
    });
  }

  /** Close the bridge WebSocket connection. */
  closeBridge() {
    this.closed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  // --- Events ---

  on(event: G2Event, handler: EventHandler): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(handler);
  }

  off(event: G2Event, handler: EventHandler): void {
    this.listeners.get(event)?.delete(handler);
  }

  private emit(event: G2Event, data: Record<string, unknown>) {
    for (const handler of this.listeners.get(event) ?? []) {
      try {
        handler(data);
      } catch {
        // Don't let handler errors propagate
      }
    }
  }

  // --- Glasses Commands ---

  /** Scan for and connect to G2 glasses via BLE. Also connects to bridge if needed. */
  async connect(): Promise<void> {
    await this.connectBridge();
    await this.send("connect");
  }

  /** Disconnect from the G2 glasses (keeps bridge connection open). */
  async disconnect(): Promise<void> {
    await this.send("disconnect");
  }

  /** Display text on the glasses using the Conversate service. */
  async setText(text: string): Promise<void> {
    await this.send("setText", { text });
  }

  /** Display text using the Teleprompter service (scrollable multi-page). */
  async setTeleprompter(title: string, body: string): Promise<void> {
    await this.send("setTeleprompter", { title, body });
  }

  /** Activate the navigation HUD on the glasses. */
  async startNavigation(): Promise<void> {
    await this.send("startNavigation");
  }

  /** Update the navigation HUD with new data. */
  async setNavigation(data: G2NavigationData): Promise<void> {
    await this.send("setNavigation", data as Record<string, unknown>);
  }

  /** Close the navigation HUD. */
  async stopNavigation(): Promise<void> {
    await this.send("stopNavigation");
  }

  /** Get the current connection status. */
  async getStatus(): Promise<G2Status> {
    const result = await this.send("getStatus");
    return result as unknown as G2Status;
  }

  /** Disconnect from glasses and close bridge connection. */
  async close(): Promise<void> {
    try {
      if (this.ws?.readyState === WebSocket.OPEN) {
        await this.send("disconnect");
      }
    } catch {
      // Already disconnected
    }
    this.closeBridge();
  }
}

export default G2;
