#!/usr/bin/env python3
"""
G2 Microphone Capture

Starts a Conversate session on the G2 glasses and captures all binary
data flowing back, looking for microphone audio data.

When a Conversate session is active, the glasses blast 205-byte binary
packets on 0x6402. This script captures those packets, saves them to
a file, and analyzes whether they contain audio.

Usage:
    python mic_capture.py                    # Record for 10 seconds
    python mic_capture.py --duration 30      # Record for 30 seconds
    python mic_capture.py --analyze only     # Analyze existing capture
"""

import argparse
import asyncio
import struct
import time
import wave
from collections import defaultdict
from pathlib import Path
from bleak import BleakClient, BleakScanner

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"
CHAR_WRITE = UUID_BASE.format(0x5401)
CHAR_NOTIFY = UUID_BASE.format(0x5402)
CHAR_DISPLAY_N = UUID_BASE.format(0x6402)
CHAR_EXTRA_N = UUID_BASE.format(0x7402)
CHAR_FIRST_N = UUID_BASE.format(0x0002)
UART_RX = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

OUTPUT_DIR = Path(__file__).parent / "captures"


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


def build_aa(seq, svc_hi, svc_lo, payload):
    header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, svc_hi, svc_lo])
    return add_crc(header + payload)


def pb_varint(field, value):
    return bytes([(field << 3) | 0]) + encode_varint(value)

def pb_bytes(field, data):
    return bytes([(field << 3) | 2]) + encode_varint(len(data)) + data

def pb_string(field, text):
    return pb_bytes(field, text.encode('utf-8'))


def build_auth_packets():
    timestamp = int(time.time())
    ts = encode_varint(timestamp)
    txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])
    p = []
    p.append(add_crc(bytes([0xAA,0x21,0x01,0x0C,0x01,0x01,0x80,0x00,0x08,0x04,0x10,0x0C,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x02,0x0A,0x01,0x01,0x80,0x20,0x08,0x05,0x10,0x0E,0x22,0x02,0x08,0x02])))
    pl = bytes([0x08,0x80,0x01,0x10,0x0F,0x82,0x08,0x11,0x08]) + ts + bytes([0x10]) + txid
    p.append(add_crc(bytes([0xAA,0x21,0x03,len(pl)+2,0x01,0x01,0x80,0x20]) + pl))
    p.append(add_crc(bytes([0xAA,0x21,0x04,0x0C,0x01,0x01,0x80,0x00,0x08,0x04,0x10,0x10,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x05,0x0C,0x01,0x01,0x80,0x00,0x08,0x04,0x10,0x11,0x1A,0x04,0x08,0x01,0x10,0x04])))
    p.append(add_crc(bytes([0xAA,0x21,0x06,0x0A,0x01,0x01,0x80,0x20,0x08,0x05,0x10,0x12,0x22,0x02,0x08,0x01])))
    pl = bytes([0x08,0x80,0x01,0x10,0x13,0x82,0x08,0x11,0x08]) + ts + bytes([0x10]) + txid
    p.append(add_crc(bytes([0xAA,0x21,0x07,len(pl)+2,0x01,0x01,0x80,0x20]) + pl))
    return p


def build_conversate_config(seq, msg_id):
    """Start Conversate session (type=1)."""
    inner = pb_varint(1, 1) + pb_varint(2, 1) + pb_varint(3, 1) + pb_varint(4, 1)
    session = pb_varint(1, 1) + pb_bytes(2, inner)
    payload = pb_varint(1, 1) + pb_varint(2, msg_id) + pb_bytes(3, session)
    return build_aa(seq, 0x0B, 0x20, payload)


def build_empty_transcription(seq, msg_id):
    """Empty transcription (signals 'listening' state)."""
    transcript = pb_string(1, "") + pb_varint(2, 0)
    payload = pb_varint(1, 5) + pb_varint(2, msg_id) + pb_bytes(7, transcript)
    return build_aa(seq, 0x0B, 0x20, payload)


class PacketRecorder:
    def __init__(self):
        self.channels = defaultdict(list)  # channel -> [(timestamp, data)]
        self.start_time = None
        self.packet_count = 0

    def make_handler(self, channel):
        def handler(sender, data):
            if self.start_time is None:
                self.start_time = time.time()
            ts = time.time() - self.start_time
            self.channels[channel].append((ts, bytes(data)))
            self.packet_count += 1
        return handler

    def summary(self):
        print(f"\n{'='*60}")
        print(f"CAPTURE SUMMARY")
        print(f"{'='*60}")
        print(f"Total packets: {self.packet_count}")
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"Duration: {duration:.1f}s")
            print(f"Rate: {self.packet_count / duration:.1f} packets/sec")
        print()
        for ch in sorted(self.channels.keys()):
            packets = self.channels[ch]
            sizes = [len(d) for _, d in packets]
            unique_sizes = sorted(set(sizes))
            total_bytes = sum(sizes)
            print(f"  [{ch}]: {len(packets)} packets, {total_bytes:,} bytes")
            print(f"    Sizes: {unique_sizes}")
            if packets:
                duration = packets[-1][0] - packets[0][0] if len(packets) > 1 else 0
                if duration > 0:
                    print(f"    Rate: {len(packets)/duration:.1f} pkt/s, {total_bytes/duration:,.0f} bytes/s")
        print()


def analyze_data(raw_data, channel_name):
    """Analyze binary data for audio patterns."""
    print(f"\n{'='*60}")
    print(f"ANALYZING {channel_name}: {len(raw_data):,} bytes")
    print(f"{'='*60}")

    # Basic stats
    byte_freq = defaultdict(int)
    for b in raw_data:
        byte_freq[b] += 1

    # Entropy calculation
    import math
    entropy = 0
    for count in byte_freq.values():
        p = count / len(raw_data)
        entropy -= p * math.log2(p)
    print(f"  Shannon entropy: {entropy:.2f} bits/byte (8.0 = random, ~4 = audio)")

    # Check for patterns
    # PCM audio tends to have values clustered around midpoint (128 for unsigned, 0 for signed)
    mean = sum(raw_data) / len(raw_data)
    print(f"  Mean byte value: {mean:.1f} (128 = unsigned center, audio-like)")

    # Check if values cluster around center (audio) or edges (binary/compressed)
    center_count = sum(1 for b in raw_data if 96 <= b <= 160)
    center_pct = center_count / len(raw_data) * 100
    print(f"  Bytes near center (96-160): {center_pct:.1f}%")

    # Look for repeating headers/structure
    print(f"\n  First 32 bytes of each packet size:")
    packets_by_size = defaultdict(list)
    # This function gets called with concatenated data, so show raw start
    print(f"    Raw start: {raw_data[:32].hex()}")
    print(f"    Raw end:   {raw_data[-32:].hex()}")

    # Check for common audio codec magic bytes
    checks = [
        (b"OggS", "Ogg/Opus"),
        (b"RIFF", "WAV/RIFF"),
        (b"fLaC", "FLAC"),
        (b"\xff\xfb", "MP3"),
        (b"\xff\xf1", "AAC"),
        (b"\x00\x00\x00", "Possible raw PCM"),
    ]
    for magic, name in checks:
        if magic in raw_data[:100]:
            print(f"  ** Found {name} signature! **")

    # Try saving as different PCM formats
    return entropy, mean


def save_as_wav(raw_data, filename, sample_rate, sample_width, channels=1):
    """Save raw data as WAV file."""
    with wave.open(str(filename), 'wb') as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(sample_width)
        wf.setframerate(sample_rate)
        wf.writeframes(raw_data)
    print(f"  Saved: {filename} ({sample_rate}Hz, {sample_width*8}-bit)")


async def capture(duration):
    print("Scanning for Even G2 glasses...")
    devices = await BleakScanner.discover(timeout=10.0)
    g2 = [d for d in devices if d.name and "G2" in d.name]
    if not g2:
        print("No G2 glasses found!")
        return None
    device = next((d for d in g2 if "_L_" in d.name), g2[0])
    print(f"Using: {device.name}\n")

    recorder = PacketRecorder()

    async with BleakClient(device) as client:
        # Subscribe to ALL notify channels
        notify_channels = [
            (CHAR_NOTIFY, "5402"),
            (CHAR_DISPLAY_N, "6402"),
            (CHAR_EXTRA_N, "7402"),
            (CHAR_FIRST_N, "0002"),
        ]
        for uuid, label in notify_channels:
            try:
                await client.start_notify(uuid, recorder.make_handler(label))
            except Exception:
                pass
        try:
            await client.start_notify(UART_RX, recorder.make_handler("UART"))
        except Exception:
            pass

        # Auth
        print("Authenticating...")
        for pkt in build_auth_packets():
            await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
            await asyncio.sleep(0.1)
        await asyncio.sleep(1.0)
        auth_count = recorder.packet_count
        print(f"Auth done ({auth_count} responses)\n")

        # Clear auth packets from recording
        recorder.channels.clear()
        recorder.packet_count = 0
        recorder.start_time = None

        seq = 0x08
        msg_id = 0x14

        # Start Conversate session
        print("Starting Conversate session (activating mic)...")
        pkt = build_conversate_config(seq, msg_id)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.5)

        # Send empty transcription to signal "listening"
        pkt = build_empty_transcription(seq, msg_id)
        await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
        seq += 1; msg_id += 1
        await asyncio.sleep(0.3)

        # Record!
        print(f"\n*** RECORDING for {duration} seconds ***")
        print(f"*** Speak into your glasses! ***\n")

        start = time.time()
        last_report = start
        while time.time() - start < duration:
            await asyncio.sleep(0.1)
            now = time.time()
            if now - last_report >= 2.0:
                elapsed = now - start
                print(f"  [{elapsed:.0f}s] {recorder.packet_count} packets captured")
                last_report = now

                # Send periodic empty transcription to keep session alive
                pkt = build_empty_transcription(seq, msg_id)
                await client.write_gatt_char(CHAR_WRITE, pkt, response=False)
                seq += 1; msg_id += 1

        print(f"\n*** Recording complete ***")

    recorder.summary()
    return recorder


def save_and_analyze(recorder):
    """Save captured data and analyze for audio."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    for channel, packets in recorder.channels.items():
        if not packets:
            continue

        # Save raw packets (with timestamps)
        raw_file = OUTPUT_DIR / f"mic_{timestamp}_{channel}_packets.bin"
        with open(raw_file, 'wb') as f:
            for ts, data in packets:
                # Write: [4-byte float timestamp] [2-byte length] [data]
                f.write(struct.pack('<fH', ts, len(data)))
                f.write(data)
        print(f"Saved packets: {raw_file}")

        # Save concatenated raw data
        raw_data = b''.join(data for _, data in packets)
        concat_file = OUTPUT_DIR / f"mic_{timestamp}_{channel}_raw.bin"
        with open(concat_file, 'wb') as f:
            f.write(raw_data)
        print(f"Saved raw: {concat_file} ({len(raw_data):,} bytes)")

        # Analyze
        entropy, mean = analyze_data(raw_data, channel)

        # Try saving as various WAV formats (we'll listen to find the right one)
        wav_dir = OUTPUT_DIR / f"mic_{timestamp}_{channel}_wav"
        wav_dir.mkdir(exist_ok=True)

        # Common BLE audio formats to try
        formats = [
            (8000, 1, "8khz_8bit"),    # 8kHz 8-bit (telephone quality)
            (8000, 2, "8khz_16bit"),   # 8kHz 16-bit
            (16000, 1, "16khz_8bit"),  # 16kHz 8-bit (wideband)
            (16000, 2, "16khz_16bit"), # 16kHz 16-bit (wideband)
            (44100, 2, "44khz_16bit"), # CD quality (unlikely over BLE)
        ]

        print(f"\n  Saving as WAV files to try different decodings:")
        for rate, width, name in formats:
            wav_file = wav_dir / f"{name}.wav"
            try:
                save_as_wav(raw_data, wav_file, rate, width)
            except Exception as e:
                print(f"  Error saving {name}: {e}")

        # Also try with packet headers stripped (first N bytes of each packet)
        for skip in [1, 2, 4, 8]:
            stripped = b''.join(data[skip:] for _, data in packets if len(data) > skip)
            if stripped:
                for rate, width, name in [(8000, 1, "8k8"), (16000, 2, "16k16")]:
                    wav_file = wav_dir / f"skip{skip}_{name}.wav"
                    try:
                        save_as_wav(stripped, wav_file, rate, width)
                    except Exception:
                        pass

    print(f"\n{'='*60}")
    print(f"FILES SAVED TO: {OUTPUT_DIR}")
    print(f"{'='*60}")
    print(f"\nNext steps:")
    print(f"  1. Open the WAV files and listen for recognizable audio")
    print(f"  2. If one sounds right, that tells us the sample rate + format")
    print(f"  3. Check the raw .bin file in a hex editor for patterns")
    print(f"  4. The _packets.bin has timestamps to analyze packet timing")


async def main():
    parser = argparse.ArgumentParser(description="Capture G2 microphone audio")
    parser.add_argument("--duration", "-d", type=int, default=10,
                        help="Recording duration in seconds (default: 10)")
    parser.add_argument("--analyze", "-a", type=str, default=None,
                        help="Analyze existing .bin file instead of capturing")
    args = parser.parse_args()

    if args.analyze:
        raw_data = Path(args.analyze).read_bytes()
        analyze_data(raw_data, Path(args.analyze).stem)
        return

    recorder = await capture(args.duration)
    if recorder and recorder.packet_count > 0:
        save_and_analyze(recorder)
    else:
        print("No data captured!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
