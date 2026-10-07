# Pigeon Mesh Node Firmware

**Experimental, unaudited firmware for Pigeon mesh network nodes.** Each node is a self-contained LoRa + BLE relay that moves encrypted messages between phones over a decentralized mesh network. Nodes forward encrypted message content. Bridge registration/control messages addressed to the node are decrypted by the node.

**Phone → BLE → Node → LoRa → Mesh → Node → BLE → Phone**

## How It Works

A Pigeon mesh node does three things:

1. **BLE GATT server** — An iPhone running [pigeon-ios](https://github.com/oliverrowebardeen/pigeon-ios) connects via Bluetooth and writes encrypted message blobs
2. **LoRa mesh relay** — The node broadcasts those blobs over LoRa and relays messages from other nodes (flood routing with TTL and deduplication)
3. **BLE notification** — When a LoRa message arrives, the node pushes it to any connected phone

Nodes use flood routing without a coordinator. Nodes with matching radio parameters discover one another after startup; review the radio settings for your hardware and region before powering a flashed device.

### WiFi Bridge Mode

When built with a relay endpoint and configured with WiFi credentials (via BLE), a node stores the password encrypted in NVS, connects to the [pigeon-relay](https://github.com/oliverrowebardeen/pigeon-relay) server over `wss://`, and bridges traffic between the local LoRa mesh and the internet. This lets phones reach each other across the internet through any bridge-enabled node.

### Meshtastic Compatible Mode

Nodes include an experimental implementation of the [Meshtastic](https://meshtastic.org/) LongFast wire format. Interoperation requires matching frequency, modem parameters, channel name/key, and compatible forwarding settings. This is not a complete Meshtastic implementation, and compatibility with arbitrary stock nodes has not been established. In particular, the fixed 915.0 MHz default does not follow Meshtastic's region/channel frequency selection; consult the [Meshtastic LoRa configuration](https://meshtastic.org/docs/configuration/radio/lora/) and verify actual settings on both devices.

- Pigeon envelopes are wrapped as protobuf `Data{portnum=256}` (PRIVATE_APP)
- AES-128-CTR encryption with the default LongFast PSK
- RSSI-based intelligent relay (closer nodes relay first, redundant rebroadcasts suppressed)
- WiFi bridge is disabled in this mode
- Switch modes via BLE: `{"lora_mode":"meshtastic"}` or `{"lora_mode":"native"}`
- Protocol codec implemented in `src/pigeon.cpp`; no Meshtastic firmware is vendored

### Neighbor Discovery

Nodes track who else is on the mesh from the packets they receive. Two in-memory tables drive this:

- **Node table** — recently-heard Pigeon nodes (capacity 8, LRU eviction). Populated from any received packet, not just beacons, so a node that relays without beaconing is still discovered.
- **Neighbor table** — per-node RSSI (capacity 16), used for the Meshtastic intelligent-relay delay calculation and for the OLED neighbor view.

In Meshtastic mode, received non-Pigeon traffic is counted separately in the neighbor view. These tables show recently heard senders, not a complete topology. Pigeon beacons run every 30–35 seconds; the first is due about 30 seconds after boot. Node and peer entries expire after about 90 seconds without traffic; the display also expires neighbor entries at 90 seconds.

## Hardware

| Component | Part |
|-----------|------|
| MCU | [Seeed XIAO ESP32S3](https://www.seeedstudio.com/XIAO-ESP32S3-p-5627.html) |
| Radio | [Wio-SX1262 LoRa Shield](https://www.seeedstudio.com/Wio-SX1262-with-XIAO-ESP32S3-p-5982.html) (Kit version, B2B connector) |
| Display | SSD1306 128x64 OLED (I2C, included on XIAO Expansion Board) |
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

## Security Status

This is experimental firmware. See [SECURITY.md](SECURITY.md) before deployment: Bluetooth provisioning/control currently assumes trusted physical surroundings, the default Meshtastic channel key is public, and NVS encryption is not a defense against full flash extraction. These limitations do not replace the client envelope encryption, but they matter for node administration and metadata privacy.

## Building & Flashing

### Prerequisites

Install Python 3.10 or newer and [pipx](https://pipx.pypa.io/latest/how-to/install-pipx.html), then install the same PlatformIO version used by CI:

```bash
pipx install platformio==6.1.19
pio --version
```

The first build downloads the pinned ESP32 platform, toolchain, and libraries and requires internet access.

### Build

```bash
# Build all four environments, as CI does
pio run

# Or build only the BLE/LoRa node
pio run -e pigeon
```

The other environments are radio development tools: `transmitter` sends a plaintext test packet every 3 seconds, `receiver` listens and prints radio metrics, and `mesh` sends plaintext discovery beacons every 10 seconds. They do not implement encrypted phone messaging.

### Local relay and radio settings

Copy `include/pigeon_config.example.h` to `include/pigeon_config.local.h` and edit it before building. The local file is ignored by Git. The default relay host is empty: BLE and LoRa remain available, while WiFi provisioning and internet bridging are disabled. Set `PIGEON_RELAY_HOST` to the hostname of a relay you operate or are authorized to use. The default port is 443 and path is `/v1/ws`.

Both relay connections validate TLS using the public ISRG Root X1 CA. If your relay uses a different CA, define `PIGEON_RELAY_ROOT_CA` as its PEM string in the local header. Do not put private keys or WiFi credentials in build configuration; provision WiFi through BLE in trusted surroundings.

`PIGEON_LORA_FREQUENCY_MHZ` and `PIGEON_LORA_POWER_DBM` override the frequency and transmit power for all four environments and both Pigeon modes. Review the radio limitations below before flashing.

### Flash

```bash
# List available serial ports
pio device list

# Flash to a specific board
pio run -e pigeon --target upload --upload-port /dev/cu.usbmodemXXXX
```

If the port is busy (BLE stack can lock USB CDC on ESP32S3), unplug the board and plug it back in, then flash immediately.

### Serial Monitor

```bash
pio device monitor --port /dev/cu.usbmodemXXXX --baud 115200
```

The `pigeon` target logs initialization and errors. Set `PIGEON_DEBUG_LOGS` to `1` in the local configuration header to enable routine packet and bridge traces. Logs omit peer identifiers, message/tunnel IDs, relay hostnames, SSIDs, IPs, and message payloads. The three radio development targets print packet counts and radio metrics. Review device logs before sharing them; timing and signal measurements can still reveal activity.

## LoRa Configuration

The node supports two LoRa modes, selectable via BLE. The mode persists across reboots.

All environments default to **915.0 MHz and 22 dBm** for the specified 915 MHz hardware. The firmware has no region selector, duty-cycle enforcement, or automatic transmit-power compliance. These defaults are not suitable worldwide and do not establish regulatory compliance. Before flashing, check the permitted frequency, power (including antenna gain), airtime, and equipment requirements where you will operate, and adjust the local configuration. A matching antenna must be connected whenever a target may transmit.

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
| Set WiFi | `{"ssid": "<your-ssid>", "pass": "<your-wifi-password>"}` |
| Clear WiFi | `{"wifi": "off"}` |
| Register phone | `{"type": "register", "pigeonID": "..."}` |
| Switch LoRa mode | `{"lora_mode": "meshtastic"}` or `{"lora_mode": "native"}` |

Sends notifications with bridge state and capacity, plus separate peer presence updates. Bridge status omits the SSID and local IP; client UIs should treat those fields as optional.

## Node Identity

Each node derives its mesh address from the ESP32's hardware MAC address (6 bytes). The BLE identity uses a separately generated X25519 keypair stored in flash. Both are stable across reboots.

## Deployment

After flashing and verifying suitable radio settings, nodes can run from a stable 5V USB supply without a host data connection. Use an appropriate supply and antenna. Test discovery, delivery, power consumption, and any bridge connection on your hardware before leaving a node running; unattended operation has not been validated.

## Project Structure

```
src/
  pigeon.cpp   — Main experimental firmware (BLE + LoRa mesh + WiFi bridge)
  mesh.cpp     — Mesh-only test firmware (no BLE)
  tx.cpp       — Transmitter test firmware
  rx.cpp       — Receiver test firmware
lib/
  curve25519/  — Vendored curve25519-donna (BSD license, see THIRD-PARTY-LICENSES)
platformio.ini — Build environments
```

## Related

- [pigeon-ios](https://github.com/oliverrowebardeen/pigeon-ios) — iOS app
- [pigeon-relay](https://github.com/oliverrowebardeen/pigeon-relay) — Relay server

## License

MIT — see [LICENSE](LICENSE). Third-party code is listed in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).

## Validation

CI builds all four PlatformIO environments and runs host parser tests with address and undefined-behavior sanitizers. There is no PlatformIO `native` test environment; run the standalone host test command in CONTRIBUTING.md. Direct dependencies are pinned to the versions in `platformio.ini`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test command and required device-test notes. Successful builds do not verify radio behavior, interoperability, or unattended operation.
