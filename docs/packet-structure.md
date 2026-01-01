# Even G2 Packet Structure

## Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         G2 BLE Packet                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│   │      HEADER      │  │     PAYLOAD      │  │       CRC        │  │
│   │     8 bytes      │  │   Variable len   │  │     2 bytes      │  │
│   │                  │  │                  │  │                  │  │
│   │  AA 21 01 0C     │  │  Protobuf data   │  │  Little-endian   │  │
│   │  01 01 80 00     │  │  (service-       │  │  CRC-16/CCITT    │  │
│   │                  │  │   specific)      │  │                  │  │
│   └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                       │
│   Phone → Glasses: Type = 0x21 (Command)                             │
│   Glasses → Phone: Type = 0x12 (Response)                            │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Transport Layer

All packets follow this structure:

```
┌────────┬────────┬────────┬────────┬────────┬────────┬────────┬────────┬─────────────┬────────┬────────┐
│ Magic  │  Type  │  Seq   │  Len   │  Pkt   │  Pkt   │  Svc   │  Svc   │   Payload   │  CRC   │  CRC   │
│  0xAA  │        │   ID   │        │  Tot   │  Ser   │  Hi    │  Lo    │     ...     │   Lo   │   Hi   │
└────────┴────────┴────────┴────────┴────────┴────────┴────────┴────────┴─────────────┴────────┴────────┘
   [0]      [1]      [2]      [3]      [4]      [5]      [6]      [7]       [8:N-2]      [N-1]    [N]
```

### Header Fields (8 bytes)

| Offset | Field | Description |
|--------|-------|-------------|
| 0 | Magic | Always `0xAA` |
| 1 | Type | `0x21` = Command, `0x12` = Response |
| 2 | Sequence | Incrementing counter (0-255) |
| 3 | Length | Payload length + 2 (includes CRC) |
| 4 | Packet Total | Total packets in message (usually `0x01`) |
| 5 | Packet Serial | Current packet number (usually `0x01`) |
| 6 | Service Hi | Service ID high byte |
| 7 | Service Lo | Service ID low byte |

### Payload

Variable length, protobuf-encoded. Structure depends on service.

### CRC (2 bytes)

- **Algorithm**: CRC-16/CCITT
- **Init Value**: 0xFFFF
- **Polynomial**: 0x1021
- **Input**: Payload bytes only (skip first 8 bytes)
- **Output**: Little-endian (low byte first)

```python
def crc16_ccitt(data, init=0xFFFF):
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc

def build_packet(seq, service_hi, service_lo, payload):
    header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, service_hi, service_lo])
    crc = crc16_ccitt(payload)
    return header + payload + bytes([crc & 0xFF, (crc >> 8) & 0xFF])
```

## Message Types

### Command (0x21)
Sent from phone to glasses.

```
AA 21 01 0C 01 01 80 00 [payload] [crc]
       ↑              ↑
       seq=1          service=0x8000
```

### Response (0x12)
Sent from glasses to phone.

```
AA 12 FD 08 01 01 80 00 [payload] [crc]
       ↑
       glasses uses its own seq counter
```

## Multi-Packet Messages

For payloads exceeding MTU (512 bytes):

```
Packet 1: AA 21 05 EC 05 01 ...  (total=5, serial=1)
Packet 2: AA 21 05 EC 05 02 ...  (total=5, serial=2)
Packet 3: AA 21 05 EC 05 03 ...  (total=5, serial=3)
...
```

- `Packet Total` (byte 4): Total number of packets
- `Packet Serial` (byte 5): Current packet (1 to N)
- Sequence ID remains constant across all packets

## Varint Encoding

Payload fields use protobuf-style varint encoding:

| Value | Encoding |
|-------|----------|
| 0-127 | Single byte |
| 128-16383 | Two bytes (MSB has bit 7 set) |
| 16384+ | Three+ bytes |

```python
def encode_varint(value):
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)
```

Examples:
- `10` → `0x0A`
- `127` → `0x7F`
- `128` → `0x80 0x01`
- `255` → `0xFF 0x01`
- `300` → `0xAC 0x02`
