# Even G2 Service IDs

## Service ID Format

Service IDs are 2 bytes in the packet header (bytes 6-7):

```
AA 21 01 0C 01 01 [hi] [lo] ...
                   ↑    ↑
              Service ID
```

## Known Services

### Core Services

| Service ID | Name | Description |
|------------|------|-------------|
| `0x80-00` | Auth Control | Session management, sync |
| `0x80-20` | Auth Data | Authentication with payload |
| `0x80-01` | Auth Response | Glasses auth acknowledgment |

### Feature Services

| Service ID | Name | Description |
|------------|------|-------------|
| `0x04-20` | Display Wake | Activate display |
| `0x06-20` | Teleprompter | Text display, scripts |
| `0x07-20` | Dashboard | Widget data |
| `0x09-00` | Device Info | Version, firmware |
| `0x0B-20` | Conversate | Speech transcription |
| `0x0C-20` | Tasks | Todo list items |
| `0x0D-00` | Configuration | Device settings |
| `0x0E-20` | Display Config | Display parameters |
| `0x11-20` | Conversate (alt) | Alternative conversate ID |
| `0x20-20` | Commit | Confirm/commit changes |
| `0x81-20` | Display Trigger | Wake/activate display |

### Service ID Breakdown

The service ID appears to encode:
- **High byte**: Service category/type
- **Low byte**: Sub-service or mode
  - `0x00` = Control/query
  - `0x01` = Response
  - `0x20` = Data/payload

## Service Details

### 0x80-00 / 0x80-20 (Authentication)

Used for session establishment:

```
Type 0x04: Capability query
Type 0x05: Capability response
Type 0x80: Time sync with transaction ID
```

### 0x06-20 (Teleprompter)

Text display service with multiple message types:

| Type | Purpose |
|------|---------|
| `0x01` | Init/select script |
| `0x02` | Script list |
| `0x03` | Content page |
| `0x04` | Content complete |
| `0xFF` | Mid-stream marker |

### 0x0E-20 (Display Config)

Display configuration sent before content:

```
08-02         Type = 2
10-XX         msg_id
22-6A         Field 4, length 106
  [config]    Display parameters
```

### 0x07-20 (Dashboard)

Widget display (calendar, weather, etc.):

```
08-XX         Widget type
10-XX         msg_id
1A-XX         Widget data
```

## Service Discovery

Services can be enumerated by observing traffic patterns:

1. **Auth services** (0x80-xx): Always first in session
2. **Config services** (0x0D-xx, 0x0E-xx): After auth
3. **Feature services**: On-demand based on user action

## Adding New Services

When you discover a new service ID:

1. Note the packet context (what triggered it)
2. Capture the full packet sequence
3. Identify the payload structure
4. Document the message types within the service
