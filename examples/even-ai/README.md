# Even AI - Custom Q&A Display

Display custom questions and answers on the G2 glasses Even AI card.

**Status**: ✅ Working - Protocol fully cracked!

---

## Quick Start

```bash
# Install
pip install bleak

# Display custom Q&A
python even_ai.py "What is 2+2?" "The answer is 4!"

# Or with named arguments
python even_ai.py -q "Hello" -a "Hi there!"
```

You should see:
1. Even AI card appears with animated icon
2. Your question types out
3. Your answer displays below

---

## How It Works

The Even AI display requires a specific sequence:

```
1. AUTH          → 7-packet handshake (same as other features)
2. CTRL(ENTER)   → commandId=1, status=2 → Enter AI mode
3. ASK           → commandId=3 → Display question text
4. REPLY         → commandId=5 → Display answer text
```

**Key Discovery**: The `CTRL(ENTER)` command is required before ASK/REPLY will work!

---

## Scripts

### even_ai.py
Clean, production-ready script for displaying Q&A.

```bash
python even_ai.py "What's the weather?" "Sunny, 72°F"
```

### test_even_ai_bubble.py
Testing script with multiple approaches. Used to discover the working protocol.

```bash
# Test specific approach
python test_even_ai_bubble.py --approach 7

# Test all approaches
python test_even_ai_bubble.py
```

---

## Protocol Details

### Service ID
- **0x0720** → Commands to glasses (ASK, REPLY, CTRL)
- **0x0700** → Responses/ACKs from glasses

### Command IDs

| commandId | Name | Purpose |
|-----------|------|---------|
| 1 | CTRL | Enter/Exit AI mode |
| 2 | VAD_INFO | Voice activity detection |
| 3 | ASK | Display question |
| 5 | REPLY | Display answer |
| 10 | CONFIG | Configure AI settings |

### CTRL Status Values

| status | Name | Purpose |
|--------|------|---------|
| 1 | WAKE_UP | "Hey Even" detected |
| 2 | ENTER | Enter AI mode |
| 3 | EXIT | Exit AI mode |

### Working Packet Examples

**CTRL(ENTER)**:
```
aa21080a01010720080110641a0208025ca9
```

**ASK "What is 2 + 2?"**:
```
aa21091e01010720080310652a16080010001800220e576861742069732032202b20323fc72b
```

**REPLY "The answer is 4!"**:
```
aa210a2001010720080510663a18080010001800221054686520616e737765722069732034218432
```

---

## Future: Claude API Integration

With the display protocol working, the next step is to integrate with Claude:

```
┌─────────────────┐
│  Your Voice     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Speech-to-Text  │  (Whisper)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Claude API     │  (Anthropic SDK)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ BLE → G2        │  (This example!)
└─────────────────┘
```

### Requirements for Full Integration

```bash
pip install anthropic         # Claude API
pip install bleak            # BLE (already done!)
pip install whisper          # Speech recognition
pip install pyaudio          # Audio capture
```

### API Key

```bash
export ANTHROPIC_API_KEY="your-key-here"
```

---

## Comparison to Even AI

| Feature | Even AI | Our Implementation |
|---------|---------|-------------------|
| AI Model | Even's servers | Your choice (Claude, GPT, etc.) |
| Network | Required | Required for AI, optional for display |
| Privacy | Data to Even | You control where data goes |
| Cost | Free | API costs (~$0.01/query for Claude) |
| Customization | None | Full control |
| Offline | No | Display works offline, AI needs network |

---

## Known Limitations

1. **Text length**: Long responses may need truncation
2. **Display time**: No control over how long card stays visible
3. **Multi-turn**: Context not maintained between queries (yet)

---

## Credits

- **Protocol Discovery**: Tyler (soxi) - January 2, 2026
- **Protobuf Definitions**: aegray (community)
- **Testing**: Systematic approach testing revealed CTRL(ENTER) requirement

---

## See Also

- [Even AI Protocol](../../docs/even-ai.md) - Full protocol documentation
- [Conversate Protocol](../../docs/conversate.md) - Speech transcription
- [Service IDs](../../docs/services.md) - All service references
