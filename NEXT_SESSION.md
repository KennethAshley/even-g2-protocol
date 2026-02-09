# Next Session: Continue Dashboard Protocol Investigation

## Setup

```bash
cd /Users/ken/Projects/Personal/even-g2-protocol/examples/notify
# Activate the existing virtualenv
source .venv/bin/activate
# Or create fresh:
# python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

Scripts are run from `examples/notify/`. The venv has `bleak`, `sounddevice`, and `openai-whisper`.

## What's Been Cracked

- **Conversate (text display)**: `notify.py` — sends text to glasses via service `0x0B-20` type=5 transcription. **WORKS.**
- **Teleprompter**: `notify.py --method teleprompter` — multi-page scrolling text via `0x06-20`. **WORKS.**
- **Live captions**: `live_captions.py` — laptop mic → Whisper → glasses text. **WORKS.**
- **Widget workaround**: `widget.py` — shows clock/text using Conversate service. **WORKS.**

## What's NOT Working: Dashboard

Five test iterations (`dashboard_test.py` through `dashboard_test5.py`) all produce the same result: **glasses silently accept all commands but display nothing.** Zero responses on 5402, zero display data on 6402.

### `dashboard_test5.py` — Latest Attempt

Corrected packet order based on capture analysis:
1. Dashboard Enable (`0x0A-20`)
2. Dashboard Refresh (`0x07-20`)
3. Screen Mode (`0x10-20`)
4. Widget Config (`0x01-20`) — declares 3 widgets
5. Widget Setup packets (`0x01-20` × 2)
6. Calendar entries (`0x01-20` × 3)
7. Display Wake (`0x04-20`)
8. ... wait ...
9. Display Config (`0x0E-20`) — sent AFTER dashboard, not before

**Result**: Still zero responses. Commands silently accepted.

### Key Findings from Capture Analysis

Full analysis in `docs/dashboard-protocol.md`. Summary:

- **Capture file**: `captures/scripted-session.log` (3.6MB Samsung BTSnoop, datalink 768)
- **Extraction**: Raw byte search for `52 42 08 21` (ATT Write to handle 0x0842 + G2 type 0x21)
- **456 packets** extracted, 413 first-fragments, 4 sessions
- **Dual lens**: Both left + right lens traffic interleaved (dedup by content hash)
- **Auth absent**: Auth happened before capture started (no `0x80-XX` packets)
- **Dashboard responses exist in capture**: Glasses DO respond to dashboard commands with 52 Widget Data acks (`0x01-00`) — our test gets zero
- **Multi-packet fragments**: Packets with `pkt_ser > 1` appear as fake `0x20-XX` service IDs

### Hypotheses for Why Dashboard Fails

1. **Missing init packets**: Every session in the capture starts with `0x00-08` and `0x20-08` packets BEFORE dashboard commands. Our tests skip these entirely. These might establish required session state.

2. **Gesture requirement**: The glasses may need to be in "dashboard mode" (user touches back of glasses → selects Dashboard) before accepting dashboard data. Conversate works without gestures because it's a real-time transcription overlay.

3. **App-level session state**: The Even app may maintain persistent BLE state that our connect-auth-send-disconnect cycle doesn't replicate.

4. **The `0x00-08` service**: Appears at session start with payloads similar to auth but on a different service ID. These are ATT Writes FROM the app (not responses). May be required handshake.

5. **The `0x20-08` service**: 85 packets in capture, appears throughout. Includes a critical packet between Screen Mode and Widget Config: `0110181a0c0a06105e301001180045740000`. May be a required sync/handshake.

### What to Try Next

1. **Send the 0x00-08 and 0x20-08 init packets** before dashboard. The capture shows this exact sequence at each session start:
   ```
   0x00-08: 04100c1a0408011004c6
   0x20-08: 05100e22020802
   0x20-08: 01100f081108061001...
   0x00-08: 0410101a040801100400
   0x00-08: 0410111a040801100461
   0x20-08: 0510122202080121
   0x20-08: 011013081108061001...
   → Then Dashboard Enable, Refresh, etc.
   ```

2. **Test with glasses in dashboard mode**: Have the user long-press the back of the glasses to enter the service menu, select Dashboard, THEN run the script while the dashboard screen is active.

3. **Check the `0x20-08` packet between Screen Mode and Widget Config**: This appears in both sessions and might be a required sync point. Hex: `0110181a0c0a06105e301001180045740000`

4. **Try exact captured msg_ids**: Instead of sequential from 0x14, use the exact values from the capture (20, 22, 23, 25, 26, 27, 28, 29, 31, 32) which have specific gaps.

5. **Parse ATT Notifications from capture**: 1613 notifications from glasses on handle 0x0844. These contain dashboard acks (`0x01-00`: 52, `0x0A-01`: 26) that our test doesn't receive. Understanding WHEN in the sequence they arrive could reveal timing requirements.

## Key Files

| File | Purpose |
|------|---------|
| `examples/notify/notify.py` | Working notification sender (Conversate + Teleprompter) |
| `examples/notify/dashboard_test5.py` | Latest dashboard test (corrected order, still fails) |
| `examples/notify/widget.py` | Widget workaround using Conversate |
| `examples/notify/live_captions.py` | Laptop mic → glasses via Whisper |
| `docs/dashboard-protocol.md` | Full dashboard packet analysis with hex payloads |
| `docs/services.md` | Service ID reference |
| `docs/packet-structure.md` | G2 frame format documentation |
| `analyze_capture.py` | Comprehensive BTSnoop capture parser |
| `parse_btsnoop.py` | BTSnoop record parser (limited by Samsung format) |
| `extract_service_01_20.py` | Widget data extractor from captures |
| `captures/scripted-session.log` | Main capture with dashboard + conversate traffic |
| `captures/auth-sequence.log` | Auth-only capture |
| `captures/fresh-pairing.log` | Full pairing capture (includes other BLE devices) |

## Protocol Quick Reference

- **BLE Characteristic**: Write to `0x5401`, notifications on `0x5402`, display data on `0x6402`
- **Packet format**: `AA 21 seq len tot ser svc_hi svc_lo [protobuf] [crc16]`
- **Auth**: 7 packets on `0x80-00`/`0x80-20`, gets 5 responses
- **Conversate text**: `0x0B-20` type=1 (session start) then type=5 (transcription with text)
- **Dashboard**: `0x0A-20` (enable) → `0x07-20` (refresh) → `0x10-20` (screen mode) → `0x01-20` (widgets) → `0x04-20` (wake)
- **Response service IDs**: Commands use `XX-20`, responses use `XX-00` or `XX-01`
