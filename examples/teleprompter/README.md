# Teleprompter Example

Display custom scrollable text on Even G2 glasses.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Simple text
python teleprompter.py "Hello world!"

# Multi-line (use actual newlines or \n)
python teleprompter.py "Line one
Line two
Line three"

# Use right eye instead of left
python teleprompter.py "Hello" --right
```

## How It Works

1. Connects to G2 glasses via BLE
2. Sends 7-packet session initialization
3. Configures display settings
4. Sends text as content pages (10 lines per page)
5. Glasses auto-wake and display text in manual scroll mode

## Controls

Once text is displayed on your glasses:
- **Swipe forward**: Scroll down
- **Swipe back**: Scroll up
- **Tap**: Exit teleprompter
