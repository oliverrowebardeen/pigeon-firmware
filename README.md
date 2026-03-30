# Pigeon Mesh Node Firmware

Firmware for Pigeon mesh network nodes. Each node is a self-contained LoRa + BLE relay that moves encrypted messages between phones over a decentralized mesh network. Nodes are opaque relays — they never inspect or decrypt message content.

**Phone → BLE → Node → LoRa → Mesh → Node → BLE → Phone**

## How It Works

A Pigeon mesh node does three things:

1. **BLE GATT server** — An iPhone running [pigeon-ios](https://github.com/oliverrowebardeen/pigeon-ios) connects via Bluetooth and writes encrypted message blobs
2. **LoRa mesh relay** — The node broadcasts those blobs over LoRa and relays messages from other nodes (flood routing with TTL and deduplication)
3. **BLE notification** — When a LoRa message arrives, the node pushes it to any connected phone

Nodes are equal peers. There's no coordinator, no routing table, no configuration. Plug one into USB power and it joins the mesh automatically.

### WiFi Bridge Mode

When configured with WiFi credentials (via BLE), a node stores the password encrypted in NVS, connects to the [pigeon-relay](https://github.com/oliverrowebardeen/pigeon-relay) server over `wss://`, and bridges traffic between the local LoRa mesh and the internet. This lets phones reach each other across the internet through any bridge-enabled node.

### Meshtastic Compatible Mode

Nodes support a second LoRa mode that speaks the [Meshtastic](https://meshtastic.org/) LongFast wire format. When enabled, stock Meshtastic devices relay Pigeon traffic transparently — every Meshtastic node in the field becomes part of the Pigeon mesh.

- Pigeon envelopes are wrapped as protobuf `Data{portnum=256}` (PRIVATE_APP)
- AES-128-CTR encryption with the default LongFast PSK
- RSSI-based intelligent relay (closer nodes relay first, redundant rebroadcasts suppressed)
- WiFi bridge is disabled in this mode
- Switch modes via BLE: `{"lora_mode":"meshtastic"}` or `{"lora_mode":"native"}`
- No Meshtastic GPL code — implemented from the public wire format spec

## Hardware

| Component | Part |
|-----------|------|
| MCU | [Seeed XIAO ESP32S3](https://www.seeedstudio.com/XIAO-ESP32S3-p-5627.html) |
| Radio | [Wio-SX1262 LoRa Shield](https://www.seeedstudio.com/Wio-SX1262-with-XIAO-ESP32S3-p-5982.html) (Kit version, B2B connector) |
| Antenna | 915MHz LoRa antenna (SMA or IPEX, must be connected before powering on) |

**Pin mapping (Kit/B2B version):**

| Function | GPIO |
|----------|------|
| CS (NSS) | 41 |
| DIO1 (IRQ) | 39 |
| RESET | 42 |
| BUSY | 40 |
| SCK | 7 |
| MOSI | 9 |
| MISO | 8 |

> **Note:** The non-kit version (pin header shield) uses different pins (CS=5, DIO1=2, RESET=3, BUSY=4). This firmware targets the kit version only.

## Building & Flashing

### Prerequisites

```bash
brew install platformio
```

### Build

```bash
pio run -e pigeon
```

### Flash

```bash
# List available serial ports
ls /dev/cu.usb*

# Flash to a specific board
pio run -e pigeon --target upload --upload-port /dev/cu.usbmodemXXXX
```

If the port is busy (BLE stack can lock USB CDC on ESP32S3), unplug the board and plug it back in, then flash immediately.

### Serial Monitor

```bash
pio device monitor --port /dev/cu.usbmodemXXXX --baud 115200
```

## LoRa Configuration

The node supports two LoRa modes, selectable via BLE. The mode persists across reboots.

### Pigeon Native (default)

| Parameter | Value |
|-----------|-------|
| Frequency | 915.0 MHz |
| Bandwidth | 125.0 kHz |
| Spreading Factor | 9 |
| Coding Rate | 4/7 |
| Sync Word | 0x12 |
| Preamble | 8 symbols |
| TX Power | 22 dBm |
| Max Payload | ~2KB (fragmented) |

### Meshtastic Compatible

| Parameter | Value |
|-----------|-------|
| Frequency | 915.0 MHz |
| Bandwidth | 250.0 kHz |
| Spreading Factor | 11 |
| Coding Rate | 4/5 |
| Sync Word | 0x2B |
| Preamble | 16 symbols |
| TX Power | 22 dBm |
| Max Payload | 233 bytes (single packet) |

## Mesh Protocol

### Pigeon Native

Each LoRa packet carries a mesh header:

```
[sender: 6B MAC][dest: 6B MAC][msgID: 2B][ttl: 1B][payloadLen: 1B][payload]
```

- **Flood routing** — broadcast messages are relayed by every node that hears them
- **Deduplication** — each node tracks recently seen (sender, msgID) pairs (64 entries, 30s expiry)
- **TTL** — decremented on each relay hop, dropped at 0
- **Fragmentation** — messages exceeding the 250-byte LoRa limit are split into fragments with a 4-byte fragment header: `[fragGroupID: 2B][fragIndex: 1B][fragTotal: 1B]`

### Meshtastic Compatible

Uses the standard Meshtastic 16-byte header (little-endian):

```
[to: 4B][from: 4B][id: 4B][flags: 1B][channel: 1B][nextHop: 1B][relayNode: 1B]
```

- **RSSI-based relay** — closer nodes relay with shorter delay (20-500ms), suppressing redundant rebroadcasts from farther nodes
- **Deduplication** — separate dedup table keyed by (from, id)
- **No fragmentation** — payloads must fit in a single 233-byte Meshtastic data slot
- **Encrypted payload** — AES-128-CTR with the default LongFast PSK; header is plaintext

## BLE Protocol

The GATT service matches [pigeon-ios](https://github.com/oliverrowebardeen/pigeon-ios) exactly:

| Characteristic | UUID | Properties |
|---------------|------|------------|
| Service | `E1A71B10-9F11-4F1F-93F8-1A0D3A2B0001` | — |
| Message | `...0002` | Write, WriteWithoutResponse, Notify |
| Identity | `...0003` | Read |
| ACK | `...0004` | Write, WriteWithoutResponse, Notify |
| Bridge Control | `...0005` | Write, WriteWithoutResponse, Notify |

### Chunking

Messages are chunked with a 22-byte header (matching the iOS app protocol):

```
[messageID: 16B UUID][chunkIndex: 2B BE][totalChunks: 2B BE][payloadSize: 2B BE][payload: 0-480B]
```

### Identity

The Identity characteristic returns JSON:

```json
{
  "publicKey": "<base64 32-byte X25519 key>",
  "pigeonID": "<8 hex chars>",
  "displayName": "Pigeon Mesh Node",
  "isMeshNode": true,
  "bridgeEnabled": false,
  "relayReachable": false,
  "bridgeProtocolVersion": 1,
  "bridgeCapacityRemaining": 0,
  "loraMode": "native"
}
```

- `publicKey` — X25519 public key, persisted in NVS across reboots
- `pigeonID` — first 4 bytes of SHA-256(publicKey) as hex
- `bridgeEnabled` — `true` if WiFi credentials are configured
- `relayReachable` — `true` if the node has an authenticated WebSocket to the relay server
- `loraMode` — `"native"` or `"meshtastic"`

### Bridge Control

Accepts JSON commands:

| Command | Payload |
|---------|---------|
| Set WiFi | `{"ssid": "MyNetwork", "pass": "password123"}` |
| Clear WiFi | `{"wifi": "off"}` |
| Register phone | `{"type": "register", "pigeonID": "..."}` |
| Switch LoRa mode | `{"lora_mode": "meshtastic"}` or `{"lora_mode": "native"}` |

Sends notifications with bridge status updates and peer presence.

## Node Identity

Each node derives its mesh address from the ESP32's hardware MAC address (6 bytes). The BLE identity uses a separately generated X25519 keypair stored in flash. Both are stable across reboots.

## Deployment

Nodes need only USB power (5V). No data connection to the host. Battery packs, phone chargers, wall adapters — anything with USB-C works. Scatter them around and they form a mesh automatically.

## Project Structure

```
src/
  pigeon.cpp   — Production firmware (BLE + LoRa mesh + WiFi bridge)
  mesh.cpp     — Mesh-only firmware (no BLE, for testing)
  tx.cpp       — Transmitter test firmware
  rx.cpp       — Receiver test firmware
platformio.ini — Build environments
```

## Related

- [pigeon-ios](https://github.com/oliverrowebardeen/pigeon-ios) — iOS app
- [pigeon-relay](https://github.com/oliverrowebardeen/pigeon-relay) — Relay server

## License

MIT
