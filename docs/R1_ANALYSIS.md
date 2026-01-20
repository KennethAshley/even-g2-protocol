# Even R1 Ring & G2 Debug Protocol Analysis

## Key Discovery: Dual Communication Architecture

The R1 ring uses **two BLE connections**:
1. **R1 ↔ Phone**: Battery, limited gestures, state sync
2. **R1 ↔ G2 Glasses**: Direct gesture control (not visible to phone BTSnoop)



---

## R1 Ring BLE Specification

### Service UUID
```
BAE80001-4F05-4503-8E65-3AF1F7329D1F
```

### Characteristic UUIDs
| UUID | Handle | Purpose |
|------|--------|---------|
| `BAE80012-4F05-4503-8E65-3AF1F7329D1F` | ? | Write characteristic |
| `BAE80013-4F05-4503-8E65-3AF1F7329D1F` | ? | Notify characteristic |

### BLE Handles (from capture)
| Handle | Type | Purpose | Example |
|--------|------|---------|---------|
| 0x0020 | Notify | **Battery Level** | `6400` = 100% |
| 0x0021 | CCCD | Battery notifications | `0100` = enable |
| 0x0024 | Notify | **Gesture Events** | `ff0320` = HOLD |
| 0x0025 | CCCD | Gesture notifications | `0100` = enable |
| 0x0028 | Notify | **State/Menu Toggle** | `01`/`00` |
| 0x0029 | CCCD | State notifications | `0100` = enable |
| 0x002c | Read | Config/Version | `02010101` |
| 0x0030 | Write | Config commands | `fc`, `11` |

---

## Gesture Protocol

### Gesture Packet Format
```
[0xFF] [gesture_type] [parameter]
```

### Gesture Types
| Code | Gesture | Notes |
|------|---------|-------|
| `0x03` | **HOLD** | Long press - shows menu |
| `0x04` | **TAP** | Single/Double tap |
| `0x05` | **SWIPE** | Swipe gestures (up/down) |

### Parameter Values
| Value | Meaning |
|-------|---------|
| `0x01` | Single tap |
| `0x02` | Double tap |
| `0x20` | Hold (duration indicator?) |

### State Values (Handle 0x0028)
| Value | Meaning |
|-------|---------|
| `0x01` | Ready/Active |
| `0x00` | Menu/Selection mode |

---

## Capture Timeline vs Action Script

### Connection Sequence (23.7s - 24.1s)
```
23.74s  Enable battery notifications (0x0021)
23.80s  Battery: 100% (0x64)
23.81s  Enable gesture notifications (0x0025)
23.87s  Read config: 02010101
23.96s  Write config: fc
24.02s  Enable state notifications (0x0029)
24.08s  State: 01 (ready)
24.09s  Write config: 11
```

### Gesture Events

| Time | Packet | Decoded | Script Action |
|------|--------|---------|---------------|
| 24.42s | `ff0320` | **HOLD** (0x20) | Step 4: "Hold (menu appears)" ✓ |
| 25.81s | state=`00` | Menu opened | - |
| 26.27s | state=`01` | Menu closing | - |
| 26.27s | `ff0402` | **TAP** (double) | Step 6: "Double tap (menu disappears)" ✓ |
| [gap] | - | Gestures go R1→G2 | Steps 7-24: Swipes, taps, scrolls |
| 116.18s | state=`00` | Menu active | - |
| 159.55s | state=`01` | Menu closing | - |
| 159.55s | `ff0402` | **TAP** (double) | One of the later double taps |

### Missing Gestures (went R1→G2 directly)
- Steps 5, 8, 11: Swipe down
- Steps 7, 10: Hold
- Steps 13, 17, 20, 22, 24: Single tap
- Steps 14-15, 18: Scroll down/up
- Steps 16, 19, 21, 23: Double tap

---

## Ring Protobuf Messages 

### RingDataPackage (main envelope)
```protobuf
message RingDataPackage {
    eRingCommandId commandId = 1;  // 1=EVENT, 2=RAW_DATA
    int32 magicRandom = 2;
    optional RingEvent event = 3;
    optional RingRawData rawData = 4;
}
```

### RingEvent (gesture events)
```protobuf
message RingEvent {
    bytes ringMac = 1;
    eRingEvent eventId = 2;  // BLE_ADV=1
    int32 eventParam = 3;
    eErrorCode errorCode = 4;
}
```

### RingRawData (health metrics)
```protobuf
message RingRawData {
    int32 battery = 1;
    int32 chargeStates = 2;
    int32 hr = 3;             // Heart rate
    int32 hrTimestamp = 4;
    int32 spo2 = 5;           // Blood oxygen
    int32 spo2Timestamp = 6;
    int32 hrv = 7;            // Heart rate variability
    int32 hrvTimestamp = 8;
    int32 temp = 9;           // Temperature
    int32 tempTimestamp = 10;
    int32 actKcal = 11;       // Active calories
    int32 actKcalTimestamp = 12;
    int32 allKcal = 13;       // Total calories
    int32 allKcalTimestamp = 14;
    int32 steps = 15;
    int32 stepsTimestamp = 16;
    eErrorCode errorCode = 17;
}
```

---

## Config Values (Handle 0x002c, 0x0030)

### Read Config (0x002c)
```
02010101
```
Possibly: [type][major][minor][patch] = v1.1.1

### Write Config (0x0030)
- `fc` - Initialization command?
- `11` - Mode setting?

---

## Dashboard Integration

When ring gestures trigger dashboard actions, the G2 glasses send state updates to the phone:

```
Dashboard Service (0x0720):
- cmd=10 (0x0a): Dashboard navigation
- Contains page state, widget index, scroll position

DashboardMain Service (0x1020):
- cmd=1: Page state update
- field 3: Active widget type (News=1, Stock=2, etc.)
```

---

## Summary

| Component | Status |
|-----------|--------|
| Battery reading | ✅ Working |
| Gesture detection | ⚠️ Partial (most go R1→G2) |
| State sync | ✅ Working |
| Health data | ❓ Not seen in this capture |
| Config commands | ❓ Needs more analysis |
