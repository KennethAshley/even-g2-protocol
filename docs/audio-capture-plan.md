# G2 Audio Capture: Mimicking the Official App

## Status (Feb 9, 2026)

We can display text, navigation HUD, and teleprompter content on the G2 glasses via BLE. But we **cannot capture microphone audio** — the glasses don't stream raw audio over BLE.

## What We Tested (All Failed for Audio)

| Method | Service | Result |
|--------|---------|--------|
| AudControl OPEN | 0x80-20 cmd=129 | Silently ignored |
| Transcribe OPEN | 0x0A-20 cmd=1 | Silently ignored |
| Conversate useAudio=1 | 0x0B-20 | Triggered display rendering (0x6402), not audio |

All 5 BLE notify channels were monitored (0x0002, 0x5402, 0x6402, 0x7402, NUS_TX). Only 0x5402 (protocol responses) and 0x6402 (display rendering) had traffic. No raw audio appeared on any channel.

## Hypothesis: Audio Goes Over Classic Bluetooth

BLE has ~1 Mbit/s bandwidth — too tight for real-time audio. The glasses likely use **Classic Bluetooth audio profiles** (HFP/SCO/A2DP) for mic streaming. The official Even Realities app probably:

1. Pairs via Classic BT for audio + BLE for data/commands
2. Receives mic audio over Classic BT SCO channel
3. Sends audio to Even's cloud for speech-to-text
4. Receives transcription results
5. Pushes transcription text back to glasses via BLE

## Plan to Mimic the App

### Step 1: Discover Classic BT Profiles

Check what Bluetooth profiles the G2 glasses advertise beyond BLE.

```python
# Using sdptool (Linux) or IOBluetooth (macOS) to query SDP records
# This tells us if HFP, A2DP, or other audio profiles are available

# Linux:
# sdptool browse <MAC_ADDRESS>

# macOS Python approach:
import subprocess
# system_profiler SPBluetoothDataType shows paired devices and profiles

# Or use PyBluez:
# pip install pybluez2
import bluetooth
services = bluetooth.find_service(address="<G2_MAC>")
for s in services:
    print(f"  {s['name']}: {s['protocol']} port={s['port']}")
```

**Key question**: Do the glasses expose HFP (Hands-Free Profile) or SCO audio?

### Step 2: Connect to Classic BT Audio

If HFP/SCO is available:

```python
# Option A: PyBluez SCO socket
import bluetooth
sock = bluetooth.BluetoothSocket(bluetooth.SCO)
sock.connect(("<G2_MAC>", 1))
# Read raw audio frames from sock

# Option B: PulseAudio/ALSA on Linux
# Pair glasses as audio device, capture from audio source

# Option C: macOS CoreBluetooth + AVFoundation
# Use system Bluetooth to pair, then capture audio input
```

### Step 3: Local Speech-to-Text

Replace Even's cloud STT with local processing:

```python
# Using OpenAI Whisper locally
import whisper
model = whisper.load_model("base")
result = model.transcribe("audio_buffer.wav")
print(result["text"])

# Or use faster-whisper for real-time:
from faster_whisper import WhisperModel
model = WhisperModel("base", device="cpu")
segments, info = model.transcribe("audio_buffer.wav")
```

### Step 4: Push Results Back to Glasses

We already have this working — use our existing SDK:

```typescript
import { G2 } from "../src/index.js";
const g = new G2();
await g.connect();
// Push transcription from our local STT
await g.setText(transcriptionResult);
```

### Step 5: Full Loop Integration

```
G2 Mic → Classic BT SCO → Python Bridge → Whisper STT → BLE → G2 Display
```

Add to bridge/server.py:
- Classic BT audio capture thread
- Whisper transcription pipeline
- Auto-push transcription via existing BLE connection

## Alternative Approaches If Classic BT Doesn't Work

### A: BLE Audio (LE Audio / LC3)
Bluetooth 5.2+ introduced LE Audio with LC3 codec. The G2 might use this instead of Classic BT. Would need to check if the glasses advertise LE Audio services. Bleak doesn't support LE Audio — would need custom BLE stack.

### B: Intercept Phone App Traffic
Run the official Even app and intercept its Bluetooth communication:
- Android: Use Bluetooth HCI snoop log (enable in developer options)
- This would reveal exactly which BT profile carries audio
- Could also reveal the cloud STT endpoint URL for potential direct API use

### C: MITM the Cloud API
If the app sends audio to a known endpoint:
- Proxy the app's HTTPS traffic (mitmproxy)
- Discover the STT API endpoint and auth
- Send audio directly to their API without the app

### D: Use the Phone as Audio Relay
Instead of fighting the BT audio problem:
- Let the official app handle mic → cloud → transcription
- Intercept the transcription text the app pushes to the glasses
- Our BLE bridge already sees all 0x5402 traffic — we could parse incoming transcriptions

## macOS-Specific Notes

- `bleak` only does BLE, not Classic BT
- `PyBluez` doesn't compile easily on modern macOS
- Best macOS approach: Use `IOBluetooth` framework via `pyobjc`
  - `pip install pyobjc-framework-IOBluetooth`
  - Can query SDP, open RFCOMM/SCO connections
- Alternative: `system_profiler SPBluetoothDataType` to see paired device profiles
- Audio capture: If glasses pair as audio device, use `sounddevice` or `pyaudio` to record

## Files Reference

| File | Purpose |
|------|---------|
| `bridge/server.py` | BLE bridge with all working commands |
| `sdk/src/index.ts` | TypeScript SDK (setText, setTeleprompter, nav, etc.) |
| `sdk/examples/mic-capture.py` | BLE audio capture attempts (all failed) |
| `sdk/examples/probe-channels.py` | BLE channel survey (only 0x5402 responds) |
| `proto/g2_re/transcribe.proto` | Transcribe service proto definition |
| `proto/g2_re/conversate.proto` | Conversate service proto (has useAudio field) |
| `proto/g2_re/dev_settings.proto` | Device settings (has AudControl commands) |
