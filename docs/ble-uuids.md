# Even G2 BLE UUIDs & Characteristics

## Service UUID

```
Base UUID: 00002760-08c2-11e1-9073-0e8ac72e{xxxx}
```

| UUID Suffix | Full UUID | Purpose |
|-------------|-----------|---------|
| `0000` | `00002760-08c2-11e1-9073-0e8ac72e0000` | Main Service |
| `5401` | `00002760-08c2-11e1-9073-0e8ac72e5401` | Write (Commands) |
| `5402` | `00002760-08c2-11e1-9073-0e8ac72e5402` | Notify (Responses) |
| `5450` | `00002760-08c2-11e1-9073-0e8ac72e5450` | Service Declaration |
| `6402` | `00002760-08c2-11e1-9073-0e8ac72e6402` | Display Rendering |

## ATT Handles

| Handle | UUID Suffix | Direction | Purpose |
|--------|-------------|-----------|---------|
| `0x0842` | 5401 | Write | Commands (Phone -> Glasses) |
| `0x0844` | 5402 | Notify | Responses (Glasses -> Phone) |
| `0x0864` | 6402 | Write | Display/Rendering commands |
| `0x0884` | ? | Notify | Secondary control (audio?) |

## Characteristic Properties

### Write Characteristic (0x5401)
- **Properties**: Write Without Response
- **Usage**: All commands sent to glasses
- **MTU**: 512 bytes (supports multi-packet)

### Notify Characteristic (0x5402)
- **Properties**: Notify
- **Usage**: All responses from glasses
- **CCCD**: Must enable notifications (write 0x0100)

### Display Characteristic (0x6402)
- **Properties**: Write Without Response
- **Usage**: 204-byte rendering packets
- **Format**: Binary display commands

## Connection Parameters

```
Connection Interval: 7.5ms - 30ms (typical)
Slave Latency: 0
Supervision Timeout: 2000ms
MTU: 512 bytes
```

## Device Naming

G2 glasses advertise with names like:
- `Even G2_XX_L_YYYYYY` (Left)
- `Even G2_XX_R_YYYYYY` (Right)

Where:
- `XX` = Model variant
- `L/R` = Left/Right ear
- `YYYYYY` = Serial suffix

## Pairing

The G2 uses **custom application-level authentication** rather than BLE pairing/bonding:
- No PIN required
- No secure pairing
- Session established via 7-packet handshake
- Timestamp + transaction ID exchange
