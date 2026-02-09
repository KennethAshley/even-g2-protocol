# Even Realities G2 Smart Glasses - Protocol Documentation

I have been reverse engineering the Even Realities G2 smart glasses BLE protocol. If you are interersted in joining this effort, please do!

## What the hell does that even mean???

The G2 glasses use a custom protocol created by EvenRealities. This BLE (bluetooth) protocol is used to transmit data in packets to and from the glasses. Currently, the G2 glasses are restricted to the functionality offered in the Even app - reverse engineering the BLE protocol removes this restriction.



## Status

| Feature | Status | Notes |
|---------|--------|-------|
| BLE Connection | Working | Standard BLE, no special pairing |
| Authentication | Working | 7-packet handshake sequence |
| Teleprompter | Working | Custom text display confirmed |
| Calendar Widget | Working | Display events on glasses |
| Notifications | Cracked! | Text display via Conversate service |
| Even AI | Cracked! | Transcription display protocol decoded |
| Navigation | Research | High display traffic observed |

## Quick Start

```bash
cd examples/notify
pip install -r requirements.txt

# Send a notification to your glasses
python notify.py "Hello from Python!"

# With a title
python notify.py "Meeting in 5 minutes" --title "Calendar"

# Alternative: use teleprompter display (scrollable text)
python notify.py "Hello from Python!" --method teleprompter
```

### Teleprompter

```bash
cd examples/teleprompter
pip install -r requirements.txt

python teleprompter.py "Hello from Python!"
```

## Documentation

- [BLE Services & UUIDs](docs/ble-uuids.md) - Complete characteristic mapping
- [Packet Structure](docs/packet-structure.md) - Transport layer format
- [Service Reference](docs/services.md) - All known service IDs
- [Teleprompter Protocol](docs/teleprompter.md) - Text display implementation (Work in Progress)

## Protocol Files

- [proto/](proto/) - Protobuf definitions for payload encoding

## Key Findings

### CRC Algorithm
- **Type**: CRC-16/CCITT
- **Init**: 0xFFFF
- **Polynomial**: 0x1021
- **Scope**: Calculated over payload bytes only (skip 8-byte header)
- **Format**: Little-endian

### Packet Structure
```
[AA] [21] [seq] [len] [01] [01] [svc_hi] [svc_lo] [payload...] [crc_lo] [crc_hi]
```

### Architecture
The G2 uses a dual-channel design:
- **Content Channel** (0x5401): What to display (text, data)
- **Rendering Channel** (0x6402): How to display (positioning, styling)

## Contributing

Pull requests welcome! Areas needing research:
- Navigation turn-by-turn protocol
- Even AI request/response format
- Translation feature
- Display rendering commands (0x6402)

## Credits

- Protocol research by the Even Realities community


## Disclaimer

This is an unofficial community project for educational purposes. Not affiliated with Even Realities.

## Discord
For all communications, I recommend Discord. Join the [EvenRealities Discord Server](https://discord.gg/arDkX3pr), which contains a reverse engineering channel containing many threads, including G2 RE.
