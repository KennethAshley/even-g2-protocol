# Dashboard Protocol Analysis

Reverse-engineered from Samsung BTSnoop capture (`scripted-session.log`, 3.6MB).

## Capture Parsing

- **Format**: Samsung BTSnoop v1, datalink type 768 (proprietary)
- **G2 frame marker**: ATT Write Command `52 42 08` (opcode=0x52, handle=0x0842 LE) immediately followed by G2 type byte `0x21` — zero gap bytes
- **Frame structure**: `21 seq len tot ser svc_hi svc_lo [protobuf...]`
  - No AA prefix in ATT writes (AA is only in the app-level framing, stripped before BLE write)
- **Dual lens**: Capture contains interleaved left + right lens traffic (duplicate seq numbers confirm two BLE connections)
- **Auth absent**: `scripted-session.log` starts after authentication. No `0x80-00` or `0x80-20` packets found.

### Extraction method

```python
marker = bytes([0x52, 0x42, 0x08, 0x21])
# Find marker, frame starts at marker+3 (skip ATT opcode + handle)
# Validate: pkt_len 2-200, pkt_tot 1-20, pkt_ser 1-pkt_tot
# Protobuf payload = frame[7 : 7 + pkt_len - 2]
```

Total extracted: 456 packets, 413 first-fragments, across 4 sessions.

### Multi-packet fragments

Packets with `pkt_ser > 1` appear as fake service IDs like `0x20-63`, `0x20-6F`, etc. These are continuation fragments where the "service bytes" are actually payload data from the previous packet's overflow. Filter by `pkt_ser == 1` to get real service packets.

## Dashboard Activation Sequence

The correct order, confirmed across all 4 sessions in the capture:

| Step | Service | Type | Description |
|------|---------|------|-------------|
| 1 | `0x0A-20` | type=0 | Dashboard Enable |
| 2 | `0x07-20` | type=10 | Dashboard Refresh |
| 3 | `0x10-20` | type=1 | Screen Mode (f3={f1:4}) |
| 4 | `0x01-20` | type=2 | Widget Config (declares widget types) |
| 5 | `0x01-20` | type=2 | Widget setup - calendar init |
| 6 | `0x01-20` | type=2 | Widget setup - layout/color data |
| 7-9 | `0x01-20` | type=2 | Calendar entries (one per event) |
| 10 | `0x04-20` | type=1 | Display Wake (triggers rendering) |
| ... | | | Other services (news, stocks) follow |
| N | `0x0E-20` | type=2 | Display Config (comes AFTER dashboard, not before!) |

**Critical finding**: Display Config (`0x0E-20`) is sent ~20 packets AFTER the dashboard data, NOT at the start. All previous test scripts (v1-v4) sent it first, which may have put the glasses in a different rendering mode.

## Packet Payloads (Hex)

### Dashboard Enable (`0x0A-20`)
```
08001014
```
Protobuf: `f1=0, f2=20`

### Dashboard Refresh (`0x07-20`)
```
080a10166a0408001020
```
Protobuf: `f1=10, f2=22, f13={f1:0, f2:32}`

Note: f13.f2=32 matches the Display Wake msg_id. May be a forward reference.

### Screen Mode (`0x10-20`)
```
080110171a020804
```
Protobuf: `f1=1, f2=23, f3={f1:4}`

### Widget Config (`0x01-20`, 25 bytes)
```
0802101922131211080410031a0301020320042a0401030202
```
Protobuf: `f1=2, f2=25, f4={f2={f1:4, f2:3, f3:[01,02,03], f4:4, f5:[01,03,02,02]}}`

- `f3=[01,02,03]` = widget type IDs: calendar=1, news=2, stocks=3
- `f5=[01,03,02,02]` = widget order/slot assignment

### Widget Setup - Calendar Init (`0x01-20`, 16 bytes)
```
0802101a220a1a081206120408001000
```
Protobuf: `f1=2, f2=26, f4={f3={f2={f2={f1:0, f2:0}}}}`

### Widget Setup - Layout Data (`0x01-20`, 28 bytes)
```
0802101b22161a140a120a100a1f1001180220330000007300000073
```

### Calendar Entry Template (`0x01-20`)

Calendar events use nested protobuf with this structure:
```
f1=2, f2=<msg_id>, f4={
  f3={
    f2={
      f3={
        f1: 3              # widget_type = calendar
        f2: <event_index>  # 0, 1, 2, ...
        f3: {
          f2: "<title>"           # e.g. "[CALENDAR_EVENT]"
          f3: "<location>"        # e.g. "No location provided"
          f4: "<time_range>"      # e.g. "HH:MM-HH:MM" or "Tmr HH:MM-HH:MM"
          f5: <day_offset>        # 6 = today?
        }
      }
    }
  }
}
```

### Stock Entry Template (`0x01-20`)

```
f1=2, f2=<msg_id>, f4={
  f3={
    f2={
      f2={
        f1: 7              # widget_type = stocks
        f2: <stock_index>
        f3: {
          f1: "<ticker>"     # e.g. "BTCE.XAMS"
          f2: ""
          f4: <price_float>
          f5: <change_float>
          f6: "<full_name>"  # e.g. "BTCetc - Bitcoin Exchange Traded Crypto"
        }
      }
    }
  }
}
```

### Display Wake (`0x04-20`)
```
080110201a080801100118052801
```
Protobuf: `f1=1, f2=32, f3={f1:1, f2:1, f3:5, f5:1}`

### Display Config (`0x0E-20`, 112 bytes)
```
08021033226a0801121308021​04e1d001d452500000000280030001213
0803100f1d006005452500000000280030001212080410001d00004225
00000000280030001212080510001d000042250000000028003000
1212080610001d000042250000000028003000180000000​01c0000
```

Contains display parameters with float values (wire type 5) for positioning.

## Message ID Pattern

After auth (which uses msg_ids 12-19), dashboard uses sequential msg_ids starting at 20:

```
20: Dashboard Enable
(21: gap - possibly response or internal)
22: Dashboard Refresh
23: Screen Mode
(24: gap - 0x20-08 control packet)
25: Widget Config
26-29: Widget setup + calendar entries
(30: gap - multi-packet fragment counter)
31: Calendar entry 3
32: Display Wake
```

Sessions 1-3 used identical msg_ids. Session 4 used different absolute values but same structure.

## What Failed in Tests v1-v4

1. **Display Config sent first** — capture shows it comes AFTER dashboard data
2. **Missing Widget setup packets** — the calendar init and layout data packets between Widget Config and calendar entries were omitted
3. **Wrong packet order** — various ordering mistakes in different test versions

## Service 0x00-08 (Unknown Init)

Appears at the start of each session (3-5 packets). Not protobuf format. Possibly a heartbeat or status service. Payload examples:
```
04100c1a0408011004c6
0410101a040801100400
0410111a040801100461
```

## Service 0x20-08 (Control/Handshake)

Appears throughout sessions. Has its own protobuf schema. Sometimes includes response-like payloads between dashboard commands. Example:
```
0110181a0c0a06105e301001180045  (between Screen Mode and Widget Config)
```
