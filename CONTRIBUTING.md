# Contributing

Thanks for your interest in contributing to the Even G2 protocol documentation!

## How to Help

### 1. Capture New Traffic

The best way to contribute is capturing BLE traffic for features we haven't fully documented:

- **Navigation** - Turn-by-turn instructions
- **Even AI** - Request/response format
- **Translation** - Source/target language encoding
- **Notifications** - Full notification content (if possible)

#### Capture Method (Android)

1. Enable Developer Options
2. Enable "Bluetooth HCI snoop log"
3. Use the feature on your glasses
4. Pull the log: `adb pull /data/misc/bluetooth/logs/btsnoop_hci.log`

### 2. Decode New Protocols

If you've figured out a new message type or service:

1. Document the packet structure
2. Add protobuf definitions to `proto/g2_protocol.proto`
3. Create an example script if applicable

### 3. Improve Documentation

- Fix errors or unclear explanations
- Add diagrams or visualizations
- Translate to other languages

## Submitting Changes

1. Fork the repository
2. Create a branch for your changes
3. Submit a pull request with:
   - Clear description of what you've added/changed
   - Any relevant packet captures or test results

## Code Style

For Python examples:
- Use type hints where helpful
- Keep functions focused and documented
- Follow the existing code structure

## Questions?

Open an issue if you:
- Found something that doesn't match your observations
- Need help understanding the protocol
- Want to discuss a new feature

## Areas Needing Research

| Feature | Status | What's Missing |
|---------|--------|----------------|
| Navigation | Unknown | Full protocol not captured |
| Even AI | Partial | Request format unclear |
| Translation | Unknown | Language encoding |
| Display Rendering (0x6402) | Partial | Marker byte meanings |
| Scroll bar sizing | Partial | Exact calculation |
