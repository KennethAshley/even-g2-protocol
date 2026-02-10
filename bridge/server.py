#!/usr/bin/env python3
"""
Even G2 BLE Bridge — WebSocket server for controlling G2 smart glasses.

Wraps BLE communication (Bleak) in a WebSocket server so TypeScript/JS
apps can send commands to the glasses without touching BLE directly.

Usage:
    python bridge/server.py                    # default port 8765
    python bridge/server.py --port 9000        # custom port

Protocol:
    Client → Bridge:  {"id": "abc", "method": "connect"}
    Bridge → Client:  {"id": "abc", "result": {"ok": true}}
    Bridge → Client:  {"event": "connected", "data": {"device": "G2_1234_L_"}}
"""

import argparse
import asyncio
import json
import logging
import time
from typing import Optional

import websockets
from bleak import BleakClient, BleakScanner

log = logging.getLogger("g2-bridge")


# =============================================================================
# BLE Constants
# =============================================================================

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)


# =============================================================================
# Packet Building (from notify.py)
# =============================================================================

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


def pb_string(field, text):
    return pb_bytes(field, text.encode("utf-8"))


# =============================================================================
# Auth
# =============================================================================

def build_auth_packets():
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


# =============================================================================
# Conversate Service (0x0B-20)
# =============================================================================

def build_conversate_config(seq, msg_id):
    inner_settings = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)
    session = pb_varint(1, 1) + pb_bytes(2, inner_settings)
    payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


def build_transcription(seq, msg_id, text, is_final=False):
    transcript = pb_string(1, text) + pb_varint(2, 1 if is_final else 0)
    payload = pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, transcript)
    return build_aa_packet(seq, 0x0B, 0x20, payload)


# =============================================================================
# Teleprompter Service (0x06-20)
# =============================================================================

def build_display_config(seq, msg_id):
    config = bytes.fromhex(
        "0801121308021090" "4E1D00E094442500" "000000280030001213"
        "0803100D0F1D0040" "8D44250000000028" "0030001212080410"
        "001D0000884225" "00000000280030" "001212080510001D"
        "00009242250000" "A242280030001212" "080610001D0000C6"
        "42250000C4422800" "30001800"
    )
    payload = bytes([0x08, 0x02, 0x10]) + encode_varint(msg_id) + bytes([0x22, 0x6A]) + config
    return build_aa_packet(seq, 0x0E, 0x20, payload)


def build_teleprompter_init(seq, msg_id, total_lines=10):
    content_height = max(1, (total_lines * 2665) // 140)
    display = (
        bytes([0x08, 0x01, 0x10, 0x00, 0x18, 0x00, 0x20, 0x8B, 0x02])
        + bytes([0x28]) + encode_varint(content_height)
        + bytes([0x30, 0xE6, 0x01, 0x38, 0x8E, 0x0A, 0x40, 0x05, 0x48, 0x00])
    )
    settings = bytes([0x08, 0x01, 0x12, len(display)]) + display
    payload = bytes([0x08, 0x01, 0x10]) + encode_varint(msg_id) + bytes([0x1A, len(settings)]) + settings
    return build_aa_packet(seq, 0x06, 0x20, payload)


def build_content_page(seq, msg_id, page_num, text):
    text_bytes = ("\n" + text).encode("utf-8")
    inner = bytes([0x08]) + encode_varint(page_num) + bytes([0x10, 0x0A, 0x1A]) + encode_varint(len(text_bytes)) + text_bytes
    content = bytes([0x2A]) + encode_varint(len(inner)) + inner
    payload = bytes([0x08, 0x03, 0x10]) + encode_varint(msg_id) + content
    return build_aa_packet(seq, 0x06, 0x20, payload)


def build_marker(seq, msg_id):
    payload = bytes([0x08, 0xFF, 0x01, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x04, 0x08, 0x00, 0x10, 0x06])
    return build_aa_packet(seq, 0x06, 0x20, payload)


def build_sync(seq, msg_id):
    payload = bytes([0x08, 0x0E, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x00])
    return build_aa_packet(seq, 0x80, 0x00, payload)


def format_text_pages(title, message, chars_per_line=25, lines_per_page=10):
    lines = []
    if title:
        lines.append(title.upper())
        lines.append("-" * min(chars_per_line, 20))
    for paragraph in message.split("\n"):
        if not paragraph.strip():
            lines.append("")
            continue
        words = paragraph.split()
        current = ""
        for word in words:
            if len(current) + len(word) + 1 > chars_per_line:
                if current:
                    lines.append(current.strip())
                current = word + " "
            else:
                current += word + " "
        if current.strip():
            lines.append(current.strip())
    while len(lines) < lines_per_page:
        lines.append(" ")
    pages = []
    for i in range(0, len(lines), lines_per_page):
        page_lines = lines[i : i + lines_per_page]
        while len(page_lines) < lines_per_page:
            page_lines.append(" ")
        pages.append("\n".join(page_lines) + " \n")
    while len(pages) < 14:
        pages.append("\n".join([" "] * lines_per_page) + " \n")
    return pages


# =============================================================================
# Navigation Service (0x08-20)
# =============================================================================

def build_nav_startup(seq, msg_id):
    """APP_REQUEST_START_UP (cmd=5) — activate navigation mode."""
    payload = pb_varint(1, 5) + pb_varint(2, msg_id)
    return build_aa_packet(seq, 0x08, 0x20, payload)


def build_nav_basic_info(seq, msg_id, direction_idx=0, distance="",
                          road="", spend_time="", remain_dist="",
                          eta="", speed="", work_method=0):
    """APP_SEND_BASIC_INFO (cmd=7) — push HUD data."""
    info = pb_varint(1, direction_idx)
    if distance: info += pb_string(2, distance)
    if road: info += pb_string(3, road)
    if spend_time: info += pb_string(4, spend_time)
    if remain_dist: info += pb_string(5, remain_dist)
    if eta: info += pb_string(6, eta)
    if speed: info += pb_string(7, speed)
    info += pb_varint(8, work_method)
    payload = pb_varint(1, 7) + pb_varint(2, msg_id) + pb_bytes(5, info)
    return build_aa_packet(seq, 0x08, 0x20, payload)


def build_nav_exit(seq, msg_id):
    """APP_REQUEST_EXIT (cmd=12) — close navigation mode."""
    payload = pb_varint(1, 12) + pb_varint(2, msg_id)
    return build_aa_packet(seq, 0x08, 0x20, payload)


# =============================================================================
# GlassesManager — BLE lifecycle
# =============================================================================

class GlassesManager:
    def __init__(self):
        self.client: Optional[BleakClient] = None
        self.device_name: Optional[str] = None
        self.seq = 0x08
        self.msg_id = 0x14
        self._event_callback = None
        self._lock = asyncio.Lock()
        self._response_queues: list[asyncio.Queue] = []

    @property
    def connected(self) -> bool:
        return self.client is not None and self.client.is_connected

    def on_event(self, callback):
        self._event_callback = callback

    def _emit(self, event: str, data: dict):
        if self._event_callback:
            asyncio.get_event_loop().call_soon(
                lambda: asyncio.ensure_future(self._event_callback(event, data))
            )

    def _on_notify(self, sender, data: bytearray):
        log.debug("BLE notify: %s (%d queues)", data.hex(), len(self._response_queues))
        self._emit("response", {"raw": data.hex()})
        # Collect for pending waiters
        for q in self._response_queues:
            q.put_nowait(data)

    def _on_disconnect(self, client):
        log.info("BLE disconnected: %s", self.device_name)
        self.client = None
        name = self.device_name
        self.device_name = None
        self.seq = 0x08
        self.msg_id = 0x14
        self._emit("disconnected", {"device": name, "reason": "ble_disconnect"})

    async def connect(self) -> str:
        async with self._lock:
            if self.connected:
                return self.device_name

            log.info("Scanning for G2 glasses...")
            devices = await BleakScanner.discover(timeout=10.0)
            g2 = [d for d in devices if d.name and "G2" in d.name]
            if not g2:
                raise RuntimeError("No G2 glasses found")

            device = next((d for d in g2 if "_L_" in d.name), g2[0])
            self.device_name = device.name
            log.info("Connecting to %s (%s)", device.name, device.address)

            self.client = BleakClient(device, disconnected_callback=self._on_disconnect)
            await self.client.connect()
            if not self.client.is_connected:
                raise RuntimeError("BLE connection failed")

            await self.client.start_notify(CHAR_NOTIFY, self._on_notify)

            # Auth handshake
            log.info("Authenticating...")
            for pkt in build_auth_packets():
                await self.client.write_gatt_char(CHAR_WRITE, pkt, response=False)
                await asyncio.sleep(0.1)
            await asyncio.sleep(0.5)
            log.info("Auth complete")

            self.seq = 0x08
            self.msg_id = 0x14
            self._emit("connected", {"device": self.device_name})
            return self.device_name

    async def disconnect(self):
        async with self._lock:
            if self.client and self.client.is_connected:
                await self.client.disconnect()
            self.client = None
            self.device_name = None

    async def _write(self, packet):
        if not self.connected:
            raise RuntimeError("Not connected")
        await self.client.write_gatt_char(CHAR_WRITE, packet, response=False)

    def _next(self):
        seq, msg_id = self.seq, self.msg_id
        self.seq += 1
        self.msg_id += 1
        return seq, msg_id

    async def set_text(self, text: str):
        async with self._lock:
            # Start conversate session
            seq, msg_id = self._next()
            await self._write(build_conversate_config(seq, msg_id))
            await asyncio.sleep(0.3)

            # Empty start
            seq, msg_id = self._next()
            await self._write(build_transcription(seq, msg_id, "", is_final=False))
            await asyncio.sleep(0.3)

            # Final text
            seq, msg_id = self._next()
            await self._write(build_transcription(seq, msg_id, text, is_final=True))
            await asyncio.sleep(0.5)

    async def set_teleprompter(self, title: str, body: str):
        async with self._lock:
            pages = format_text_pages(title, body)
            total_lines = sum(1 for p in pages for ln in p.split("\n") if ln.strip())

            seq, msg_id = self._next()
            await self._write(build_display_config(seq, msg_id))
            await asyncio.sleep(0.3)

            seq, msg_id = self._next()
            await self._write(build_teleprompter_init(seq, msg_id, total_lines))
            await asyncio.sleep(0.5)

            for i in range(min(10, len(pages))):
                seq, msg_id = self._next()
                await self._write(build_content_page(seq, msg_id, i, pages[i]))
                await asyncio.sleep(0.05)

            seq, msg_id = self._next()
            await self._write(build_marker(seq, msg_id))
            await asyncio.sleep(0.05)

            for i in range(10, len(pages)):
                seq, msg_id = self._next()
                await self._write(build_content_page(seq, msg_id, i, pages[i]))
                await asyncio.sleep(0.05)

            seq, msg_id = self._next()
            await self._write(build_sync(seq, msg_id))
            await asyncio.sleep(0.1)

    async def start_navigation(self):
        """Activate navigation mode on the glasses."""
        async with self._lock:
            seq, msg_id = self._next()
            await self._write(build_nav_startup(seq, msg_id))
            await asyncio.sleep(0.5)

    async def set_navigation(self, direction: int = 0, distance: str = "",
                              road: str = "", eta: str = "", speed: str = "",
                              remain_dist: str = "", spend_time: str = ""):
        """Update navigation HUD data."""
        async with self._lock:
            seq, msg_id = self._next()
            await self._write(build_nav_basic_info(
                seq, msg_id, direction_idx=direction, distance=distance,
                road=road, spend_time=spend_time, remain_dist=remain_dist,
                eta=eta, speed=speed,
            ))
            await asyncio.sleep(0.1)

    async def stop_navigation(self):
        """Exit navigation mode."""
        async with self._lock:
            seq, msg_id = self._next()
            await self._write(build_nav_exit(seq, msg_id))
            await asyncio.sleep(0.3)

    async def send_raw(self, svc_hi: int, svc_lo: int, payload_hex: str, wait: float = 1.0) -> list[str]:
        """Send a raw protobuf payload on any service and collect responses."""
        async with self._lock:
            payload = bytes.fromhex(payload_hex)
            seq, msg_id = self._next()
            pkt = build_aa_packet(seq, svc_hi, svc_lo, payload)
            log.info("sendRaw 0x%02X-0x%02X seq=%d pkt=%s", svc_hi, svc_lo, seq, pkt.hex())

            q: asyncio.Queue = asyncio.Queue()
            self._response_queues.append(q)
            try:
                await self._write(pkt)
                await asyncio.sleep(wait)
                responses = []
                while not q.empty():
                    responses.append(q.get_nowait().hex())
                log.info("sendRaw collected %d responses", len(responses))
                return responses
            finally:
                self._response_queues.remove(q)

    def status(self) -> dict:
        return {
            "connected": self.connected,
            "device": self.device_name,
        }


# =============================================================================
# WebSocket Server
# =============================================================================

class BridgeServer:
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.glasses = GlassesManager()
        self.clients: set = set()

    async def _broadcast(self, event: str, data: dict):
        msg = json.dumps({"event": event, "data": data})
        dead = set()
        for ws in self.clients:
            try:
                await ws.send(msg)
            except websockets.ConnectionClosed:
                dead.add(ws)
        self.clients -= dead

    async def _handle_command(self, msg: dict) -> dict:
        cmd_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})

        try:
            if method == "connect":
                device = await self.glasses.connect()
                return {"id": cmd_id, "result": {"ok": True, "device": device}}

            elif method == "disconnect":
                await self.glasses.disconnect()
                return {"id": cmd_id, "result": {"ok": True}}

            elif method == "setText":
                text = params.get("text", "")
                if not text:
                    return {"id": cmd_id, "error": {"code": "INVALID_PARAMS", "message": "text is required"}}
                await self.glasses.set_text(text)
                return {"id": cmd_id, "result": {"ok": True}}

            elif method == "setTeleprompter":
                title = params.get("title", "")
                body = params.get("body", "")
                if not body:
                    return {"id": cmd_id, "error": {"code": "INVALID_PARAMS", "message": "body is required"}}
                await self.glasses.set_teleprompter(title, body)
                return {"id": cmd_id, "result": {"ok": True}}

            elif method == "startNavigation":
                await self.glasses.start_navigation()
                return {"id": cmd_id, "result": {"ok": True}}

            elif method == "setNavigation":
                await self.glasses.set_navigation(
                    direction=params.get("direction", 0),
                    distance=params.get("distance", ""),
                    road=params.get("road", ""),
                    eta=params.get("eta", ""),
                    speed=params.get("speed", ""),
                    remain_dist=params.get("remainDistance", ""),
                    spend_time=params.get("spendTime", ""),
                )
                return {"id": cmd_id, "result": {"ok": True}}

            elif method == "stopNavigation":
                await self.glasses.stop_navigation()
                return {"id": cmd_id, "result": {"ok": True}}

            elif method == "sendRaw":
                svc_hi = params.get("svcHi")
                svc_lo = params.get("svcLo")
                payload = params.get("payload", "")
                wait = params.get("wait", 1.0)
                if svc_hi is None or svc_lo is None:
                    return {"id": cmd_id, "error": {"code": "INVALID_PARAMS", "message": "svcHi and svcLo required"}}
                responses = await self.glasses.send_raw(svc_hi, svc_lo, payload, wait)
                return {"id": cmd_id, "result": {"ok": True, "responses": responses}}

            elif method == "getStatus":
                return {"id": cmd_id, "result": self.glasses.status()}

            else:
                return {"id": cmd_id, "error": {"code": "UNKNOWN_METHOD", "message": f"Unknown method: {method}"}}

        except RuntimeError as e:
            code = "NOT_CONNECTED" if "Not connected" in str(e) else "BLE_ERROR"
            return {"id": cmd_id, "error": {"code": code, "message": str(e)}}
        except Exception as e:
            log.exception("Command error")
            return {"id": cmd_id, "error": {"code": "INTERNAL", "message": str(e)}}

    async def _handler(self, ws):
        self.clients.add(ws)
        log.info("Client connected (%d total)", len(self.clients))
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    await ws.send(json.dumps({"error": {"code": "PARSE_ERROR", "message": "Invalid JSON"}}))
                    continue
                resp = await self._handle_command(msg)
                await ws.send(json.dumps(resp))
        except websockets.ConnectionClosed:
            pass
        finally:
            self.clients.discard(ws)
            log.info("Client disconnected (%d remaining)", len(self.clients))

    async def run(self):
        self.glasses.on_event(self._broadcast)
        log.info("G2 Bridge starting on ws://%s:%d", self.host, self.port)
        async with websockets.serve(self._handler, self.host, self.port):
            await asyncio.Future()  # run forever


def main():
    parser = argparse.ArgumentParser(description="Even G2 BLE Bridge")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    server = BridgeServer(host=args.host, port=args.port)
    asyncio.run(server.run())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutting down")
