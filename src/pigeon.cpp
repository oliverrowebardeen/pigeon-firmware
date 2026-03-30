// Pigeon Firmware - Phase 5: BLE Bridge + Mesh Relay
// Unified firmware: LoRa mesh relay + BLE GATT server for iOS app.
// The node is an opaque relay — it never inspects message content.
//
// BLE protocol matches pigeon-ios exactly:
//   Service: E1A71B10-9F11-4F1F-93F8-1A0D3A2B0001
//   Message: ...0002 (Write+Notify, chunked)
//   Identity: ...0003 (Read, JSON)
//   ACK: ...0004 (Write+Notify)
//   Bridge Control: ...0005 (Write+Notify)

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLE2902.h>
#include <esp_mac.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <esp_bt.h>
#include <U8x8lib.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include "curve25519-donna.h"
#include <mbedtls/md.h>
#include <mbedtls/aes.h>

// ============================================================================
// Configuration
// ============================================================================

// --- Pin mapping: XIAO ESP32S3 + Wio-SX1262 (Kit/B2B version) ---
#define LORA_CS    41
#define LORA_DIO1  39
#define LORA_RESET 42
#define LORA_BUSY  40
#define LORA_SCK   7
#define LORA_MOSI  9
#define LORA_MISO  8

// --- LoRa parameters ---
static const float LORA_FREQ        = 915.0;   // MHz (US ISM band)
static const float LORA_BW          = 125.0;   // kHz bandwidth
static const uint8_t LORA_SF        = 9;       // Spreading factor
static const uint8_t LORA_CR        = 7;       // Coding rate 4/7
static const uint8_t LORA_SYNC_WORD = 0x12;    // Private network sync word
static const int8_t LORA_POWER      = 22;      // TX power in dBm (max)
static const uint16_t LORA_PREAMBLE = 8;       // Preamble length
static const float LORA_TCXO_V      = 1.8;     // TCXO voltage via DIO3

// --- LoRa protocol mode ---
enum LoRaMode : uint8_t { LORA_NATIVE = 0, LORA_MESHTASTIC = 1 };
static LoRaMode loraMode = LORA_NATIVE;

// --- Meshtastic LongFast radio parameters ---
static const float MSHT_BW          = 250.0;   // kHz
static const uint8_t MSHT_SF        = 11;
static const uint8_t MSHT_CR        = 5;       // 4/5
static const uint8_t MSHT_SYNC_WORD = 0x2B;
static const uint16_t MSHT_PREAMBLE = 16;
static const size_t MSHT_MAX_PACKET = 255;
static const size_t MSHT_HEADER_SIZE = 16;
static const size_t MSHT_MAX_PAYLOAD = 239;    // 255 - 16
static const uint8_t MSHT_HOP_DEFAULT = 3;
static const uint8_t MSHT_CHANNEL_HASH = 0x08; // xorHash("LongFast") ^ xorHash(defaultPSK)
static const uint32_t MSHT_BROADCAST = 0xFFFFFFFF;
static const uint16_t MSHT_PORTNUM_PRIVATE_APP = 256;

// Meshtastic default PSK (LongFast, AES-128)
static const uint8_t MSHT_DEFAULT_PSK[16] = {
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
};

// --- Mesh parameters ---
static const uint8_t DEFAULT_TTL         = 5;
static const uint8_t BROADCAST_ADDR[6]   = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const size_t ADDR_LEN             = 6;
static const size_t DEDUP_TABLE_SIZE     = 64;
static const uint32_t DEDUP_EXPIRY_MS    = 30000;

// --- Mesh packet: [sender:6][dest:6][msgID:2][ttl:1][payloadLen:1][payload] ---
static const size_t MESH_HEADER_SIZE     = 16;
static const size_t MAX_LORA_PACKET      = 250;
// Payload includes 4-byte fragment header + data
static const size_t FRAG_HEADER_SIZE     = 4;   // [fragGroupID:2][fragIdx:1][fragTotal:1]
static const size_t MAX_FRAG_DATA        = MAX_LORA_PACKET - MESH_HEADER_SIZE - FRAG_HEADER_SIZE; // 230

// Meshtastic protobuf overhead and max payload sizes
static const size_t MSHT_PROTOBUF_OVERHEAD = 6;  // field1(3) + field2_tag(1) + varint_len(1-2)
static const size_t MSHT_MAX_PIGEON_DATA = MSHT_MAX_PAYLOAD - MSHT_PROTOBUF_OVERHEAD; // 233
// Note: no Pigeon fragmentation in Meshtastic mode — payloads must fit in one packet

// --- LoRa reassembly ---
static const size_t LORA_REASM_SLOTS     = 8;
static const size_t MAX_LORA_MSG_SIZE    = 2048;  // Max reassembled message
static const uint32_t LORA_REASM_TIMEOUT = 30000;

// --- BLE UUIDs (must match pigeon-ios exactly) ---
#define BLE_SERVICE_UUID       "E1A71B10-9F11-4F1F-93F8-1A0D3A2B0001"
#define BLE_MSG_CHAR_UUID      "E1A71B10-9F11-4F1F-93F8-1A0D3A2B0002"
#define BLE_IDENTITY_CHAR_UUID "E1A71B10-9F11-4F1F-93F8-1A0D3A2B0003"
#define BLE_ACK_CHAR_UUID      "E1A71B10-9F11-4F1F-93F8-1A0D3A2B0004"
#define BLE_BRIDGE_CHAR_UUID   "E1A71B10-9F11-4F1F-93F8-1A0D3A2B0005"

// --- BLE chunking (matches pigeon-ios protocol) ---
// Chunk: [messageID:16][chunkIndex:2 BE][totalChunks:2 BE][payloadSize:2 BE][payload:0-480]
static const size_t BLE_CHUNK_HEADER     = 22;
static const size_t BLE_MAX_CHUNK_DATA   = 480;
static const size_t BLE_REASM_SLOTS      = 4;
static const uint32_t BLE_REASM_TIMEOUT  = 30000;

// --- BLE event queue (thread-safe BLE callback -> loop() handoff) ---
static const size_t BLE_EVENT_QUEUE_LEN  = 8;
static const size_t BLE_MAX_WRITE_SIZE   = 512;
// --- BLE advertising watchdog ---
static const uint32_t BLE_ADV_RESTART_MS = 5000;
// --- Bridge status periodic re-notification ---
static const uint32_t BRIDGE_STATUS_INTERVAL_MS = 5000;

// --- Phone registration (phones identify themselves to the node) ---
static const size_t MAX_REGISTERED_PHONES = 3;
static const size_t PIGEON_ID_LEN         = 4;   // 4 bytes = 8 hex chars

// --- Peer discovery (mesh-reachable phones via LoRa beacons) ---
static const size_t PEER_TABLE_SIZE       = 16;
static const uint32_t PEER_EXPIRY_MS      = 90000; // 3× beacon interval
static const uint32_t PEER_NOTIFY_MS      = 10000; // BLE notification interval
static const uint8_t BEACON_TYPE_PRESENCE    = 0x01;  // Legacy: 4-byte pigeonIDs
static const uint8_t BEACON_TYPE_PRESENCE_V2 = 0x02;  // V2: 32-byte public keys
static const size_t  PUBKEY_LEN              = 32;
static const size_t  MAX_BEACON_PEERS        = 7;     // floor((234 - 2) / 32)

// --- Relay queue (deferred relay to avoid fragment loss) ---
static const size_t RELAY_QUEUE_SIZE      = 8;

// --- Radio watchdog ---
static const uint32_t RADIO_WATCHDOG_MS   = 5000;

enum BLEEventType : uint8_t {
    BLE_EVENT_MSG_WRITE,
    BLE_EVENT_ACK_WRITE,
    BLE_EVENT_BRIDGE_WRITE,
};

struct BLEEvent {
    BLEEventType type;
    size_t len;
    uint8_t data[BLE_MAX_WRITE_SIZE];
};

struct RegisteredPhone {
    char pigeonID[9];       // 8 hex chars + null
    uint8_t pigeonIDBytes[PIGEON_ID_LEN]; // Binary form for beacon payload
    uint8_t publicKey[PUBKEY_LEN];        // Full Curve25519 public key
    bool hasPublicKey;
    uint16_t connId;        // BLE connection ID to track disconnects
    bool active;
};

struct PeerEntry {
    char pigeonID[9];       // 8 hex chars + null
    uint8_t publicKey[PUBKEY_LEN]; // Full Curve25519 public key
    bool hasPublicKey;
    uint32_t lastSeen;      // millis() timestamp
    float rssi;             // Signal strength from beacon
    bool active;
};

// --- Mesh node presence (nodes discovered via LoRa beacons) ---
static const size_t NODE_TABLE_SIZE = 8;
struct NodeEntry {
    uint8_t addr[ADDR_LEN]; // LoRa MAC address
    uint32_t lastSeen;
    bool active;
};


struct RelayItem {
    uint8_t data[MAX_LORA_PACKET];
    size_t len;
    bool pending;
};

// ============================================================================
// Data structures
// ============================================================================

struct MeshPacket {
    uint8_t sender[ADDR_LEN];
    uint8_t dest[ADDR_LEN];
    uint16_t msgID;
    uint8_t ttl;
    uint8_t payloadLen;
    uint8_t payload[MAX_LORA_PACKET - MESH_HEADER_SIZE];
};

struct DedupEntry {
    uint8_t sender[ADDR_LEN];
    uint16_t msgID;
    uint32_t timestamp;
    bool active;
};

struct LoRaReasmSlot {
    uint8_t sender[ADDR_LEN];
    uint16_t fragGroupID;
    uint8_t fragTotal;
    uint8_t fragsReceived;
    bool fragPresent[16]; // max 16 fragments
    uint8_t data[MAX_LORA_MSG_SIZE];
    size_t fragSizes[16];
    uint32_t timestamp;
    bool active;
};

struct BLEReasmSlot {
    uint8_t messageID[16];  // UUID bytes
    uint16_t totalChunks;
    uint16_t chunksReceived;
    bool chunkPresent[16];  // max 16 chunks
    uint8_t data[MAX_LORA_MSG_SIZE];
    size_t chunkSizes[16];
    uint32_t timestamp;
    bool active;
};

// --- Meshtastic packet header (16 bytes, little-endian on wire) ---
struct MshtHeader {
    uint32_t to;
    uint32_t from;
    uint32_t id;
    uint8_t flags;
    uint8_t channel;
    uint8_t nextHop;
    uint8_t relayNode;
};

struct MshtDedupEntry {
    uint32_t from;
    uint32_t id;
    uint32_t timestamp;
    bool active;
};

static const size_t NEIGHBOR_TABLE_SIZE = 16;
struct NeighborEntry {
    uint32_t nodeNum;
    float rssi;
    uint32_t lastSeen;
    bool active;
};

struct MshtRelayItem {
    uint8_t data[MSHT_MAX_PACKET];
    size_t len;
    uint32_t from;      // for suppression check
    uint32_t id;        // for suppression check
    uint32_t queuedAt;  // millis() when queued
    uint32_t delayMs;   // RSSI-based delay
    bool pending;
};

// ============================================================================
// Globals
// ============================================================================

SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RESET, LORA_BUSY);

uint8_t nodeAddr[ADDR_LEN];
char nodePigeonID[9]; // 8 hex chars + null
uint8_t nodePublicKey[32];  // X25519 public key (persisted in NVS)
uint8_t nodePrivateKey[32]; // X25519 private key (persisted in NVS)
char nodePublicKeyB64[45];  // base64-encoded public key
uint16_t nextMsgID = 0;
uint16_t nextFragGroupID = 0;

DedupEntry dedupTable[DEDUP_TABLE_SIZE];
LoRaReasmSlot loraReasmTable[LORA_REASM_SLOTS];
BLEReasmSlot bleReasmTable[BLE_REASM_SLOTS];

// Meshtastic mode globals
static uint32_t mshtNodeNum = 0;
static uint32_t mshtPacketCounter = 0;
MshtDedupEntry mshtDedupTable[DEDUP_TABLE_SIZE];
NeighborEntry neighborTable[NEIGHBOR_TABLE_SIZE];
MshtRelayItem mshtRelayQueue[RELAY_QUEUE_SIZE];

volatile bool rxFlag = false;

// BLE state
BLEServer* pServer = nullptr;
BLECharacteristic* pMsgChar = nullptr;
BLECharacteristic* pIdentityChar = nullptr;
BLECharacteristic* pAckChar = nullptr;
BLECharacteristic* pBridgeChar = nullptr;
volatile bool bleClientConnected = false;
static uint32_t lastBridgeStatusNotify = 0;
volatile bool pendingConnectNotify = false;
volatile uint32_t pendingNotifyStart = 0;
static const uint32_t DEFERRED_NOTIFY_DELAY_MS = 500;

// Queue for BLE->LoRa messages (phone wrote to us)
static const size_t BLE_TX_QUEUE_SIZE = 4;
struct BLETxItem {
    uint8_t data[MAX_LORA_MSG_SIZE];
    size_t len;
    bool pending;
};
BLETxItem bleTxQueue[BLE_TX_QUEUE_SIZE];

// Queue for LoRa->BLE messages (received from mesh, send to phone)
static const size_t LORA_RX_QUEUE_SIZE = 4;
struct LoRaRxItem {
    uint8_t data[MAX_LORA_MSG_SIZE];
    size_t len;
    bool pending;
};
LoRaRxItem loraRxQueue[LORA_RX_QUEUE_SIZE];

// BLE event queue and advertising watchdog
static QueueHandle_t bleEventQueue = nullptr;
uint32_t lastBLEAdvRestart = 0;

// Phone registration (phones connected via BLE that have identified themselves)
RegisteredPhone registeredPhones[MAX_REGISTERED_PHONES];

// Peer table (mesh-reachable phones discovered via LoRa beacons)
PeerEntry peerTable[PEER_TABLE_SIZE];
uint32_t lastPeerNotify = 0;
bool peerTableChanged = false;

// Node table (mesh nodes heard via LoRa beacons)
NodeEntry nodeTable[NODE_TABLE_SIZE];

// Relay queue (deferred relay to prevent fragment loss)
RelayItem relayQueue[RELAY_QUEUE_SIZE];

// Radio watchdog
uint32_t lastRadioWatchdog = 0;

// Track the most recent BLE connection ID for associating with phone registration
uint16_t lastBLEConnId = 0;

// Relay jitter (random delay to reduce collision between relay nodes)
uint32_t lastRelayTime = 0;
uint32_t relayJitterMs = 0;

// OLED display (XIAO Expansion Board: SSD1306 128x64 I2C)
U8X8_SSD1306_128X64_NONAME_HW_I2C u8x8(U8X8_PIN_NONE);
uint32_t lastDisplayUpdate = 0;
static const uint32_t DISPLAY_UPDATE_MS = 1000;

// Activity counters for display
uint32_t statLoRaRx = 0;
uint32_t statRelay = 0;
uint32_t statBleIn = 0;
uint32_t statBleOut = 0;
float lastRSSI = 0;
bool hasRSSI = false;

// LoRa heartbeat beacon
static const uint32_t BEACON_INTERVAL_MS = 30000;
uint32_t lastBeaconTime = 0;

// WiFi state
static char wifiSSID[33] = {0};
static char wifiPass[65] = {0};
static bool wifiConfigured = false;
static bool wifiConnected = false;
static uint32_t lastWifiRetry = 0;
static const uint32_t WIFI_RETRY_MS = 10000;

// Bridge state
enum BridgeState : uint8_t {
    BRIDGE_NO_WIFI,
    BRIDGE_CONNECTING,
    BRIDGE_WIFI_ONLY,
    BRIDGE_AUTH,
    BRIDGE_ONLINE,
    BRIDGE_OFFLINE
};
static BridgeState bridgeState = BRIDGE_NO_WIFI;

// Relay server
static const char* RELAY_HOST = "relay.example.com";
static const uint16_t RELAY_PORT = 443;
static const char* RELAY_PATH = "/v1/ws";
static const char RELAY_ROOT_CA[] PROGMEM = R"CERT(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
)CERT";
static const char* WIFI_PASS_LEGACY_KEY = "wifi_pass";
static const char* WIFI_PASS_VERSION_KEY = "wifi_pw_ver";
static const char* WIFI_PASS_LENGTH_KEY = "wifi_pw_len";
static const char* WIFI_PASS_IV_KEY = "wifi_pw_iv";
static const char* WIFI_PASS_CT_KEY = "wifi_pw_ct";
static const char* WIFI_PASS_MAC_KEY = "wifi_pw_mac";
static const uint8_t WIFI_PASS_STORAGE_VERSION = 1;
static const size_t WIFI_PASS_IV_LEN = 16;
static const size_t WIFI_PASS_MAC_LEN = 16;

// WebSocket state
WebSocketsClient webSocket;
static bool wsConnected = false;
static bool wsAuthenticated = false;
static uint32_t wsReconnectDelay = 1000;
static uint32_t wsLastAttempt = 0;
static const uint32_t WS_MAX_BACKOFF = 60000;

// Routing header: [message_id:16B UUID][recipient_hash:32B SHA-256]
static const size_t ROUTING_HEADER_SIZE = 48;

// Message-level dedup for internet<->LoRa bridging
static const size_t MSG_DEDUP_SIZE = 32;
struct MsgDedupEntry {
    uint8_t msgId[16];
    uint32_t timestamp;
    bool active;
};
MsgDedupEntry msgDedupTable[MSG_DEDUP_SIZE];

// ============================================================================
// Utility functions
// ============================================================================

void IRAM_ATTR onReceive() {
    rxFlag = true;
}

// Forward declarations
void handlePresenceBeacon(const uint8_t* sender, const uint8_t* payload,
                          uint8_t payloadLen, float rssi);
void bleSendChunked(BLECharacteristic* pChar, const uint8_t* data, size_t dataLen);
void saveWiFiCredentials(const char* ssid, const char* pass);
void clearWiFiCredentials();
void setupWiFi();
void notifyBridgeStatus();
void updateIdentityCharacteristic();

void macToStr(const uint8_t* mac, char* buf) {
    snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool addrMatch(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, ADDR_LEN) == 0;
}

bool isBroadcast(const uint8_t* addr) {
    return addrMatch(addr, BROADCAST_ADDR);
}

void computePigeonID(const uint8_t* pubKey, size_t keyLen, char* outHex) {
    uint8_t hash[32];
    mbedtls_sha256(pubKey, keyLen, hash, 0);
    snprintf(outHex, 9, "%02x%02x%02x%02x", hash[0], hash[1], hash[2], hash[3]);
}

// X25519 basepoint (generator) — the constant 9
static const uint8_t X25519_BASEPOINT[32] = {9};

// Load or generate X25519 keypair, persist in NVS.
// Migration: if key_version < 2, the old random token is replaced with a real keypair.
void loadOrGenerateKey() {
    Preferences prefs;
    prefs.begin("pigeon", false);

    uint8_t keyVersion = prefs.getUChar("key_version", 0);
    bool needNewKey = (keyVersion < 2);

    if (!needNewKey) {
        size_t privLen = prefs.getBytes("privkey", nodePrivateKey, 32);
        if (privLen != 32) needNewKey = true;
    }

    if (needNewKey) {
        esp_fill_random(nodePrivateKey, 32);
        // Clamp per X25519 spec (RFC 7748)
        nodePrivateKey[0]  &= 248;
        nodePrivateKey[31] &= 127;
        nodePrivateKey[31] |= 64;

        curve25519_donna(nodePublicKey, nodePrivateKey, X25519_BASEPOINT);

        prefs.putBytes("privkey", nodePrivateKey, 32);
        prefs.putBytes("pubkey", nodePublicKey, 32);
        prefs.putUChar("key_version", 2);
        Serial.println("[KEY] Generated new X25519 keypair");
    } else {
        prefs.getBytes("pubkey", nodePublicKey, 32);
        Serial.println("[KEY] Loaded existing X25519 keypair from NVS");
    }

    // Load LoRa protocol mode
    loraMode = (LoRaMode)prefs.getUChar("lora_mode", LORA_NATIVE);

    prefs.end();

    // Base64-encode the public key
    size_t b64Len = 0;
    mbedtls_base64_encode((unsigned char*)nodePublicKeyB64, sizeof(nodePublicKeyB64),
                          &b64Len, nodePublicKey, 32);
    nodePublicKeyB64[b64Len] = '\0';

    // Derive Meshtastic NodeNum from first 4 bytes of public key (little-endian)
    memcpy(&mshtNodeNum, nodePublicKey, 4);
    if (mshtNodeNum == 0 || mshtNodeNum == MSHT_BROADCAST) mshtNodeNum = 0x00000001;
}

// ============================================================================
// Deduplication
// ============================================================================

bool isDuplicate(const uint8_t* sender, uint16_t msgID) {
    uint32_t now = millis();
    for (size_t i = 0; i < DEDUP_TABLE_SIZE; i++) {
        if (dedupTable[i].active) {
            if (now - dedupTable[i].timestamp > DEDUP_EXPIRY_MS) {
                dedupTable[i].active = false;
                continue;
            }
            if (addrMatch(dedupTable[i].sender, sender) && dedupTable[i].msgID == msgID) {
                return true;
            }
        }
    }
    return false;
}

void addDedup(const uint8_t* sender, uint16_t msgID) {
    size_t slot = 0;
    uint32_t oldestTime = UINT32_MAX;
    for (size_t i = 0; i < DEDUP_TABLE_SIZE; i++) {
        if (!dedupTable[i].active) { slot = i; break; }
        if (dedupTable[i].timestamp < oldestTime) {
            oldestTime = dedupTable[i].timestamp;
            slot = i;
        }
    }
    memcpy(dedupTable[slot].sender, sender, ADDR_LEN);
    dedupTable[slot].msgID = msgID;
    dedupTable[slot].timestamp = millis();
    dedupTable[slot].active = true;
}

// ============================================================================
// Meshtastic helpers — crypto, codec, protobuf, dedup
// ============================================================================

// --- Header serialize/deserialize (little-endian on wire) ---

void mshtSerializeHeader(const MshtHeader& h, uint8_t* buf) {
    memcpy(buf + 0, &h.to, 4);
    memcpy(buf + 4, &h.from, 4);
    memcpy(buf + 8, &h.id, 4);
    buf[12] = h.flags;
    buf[13] = h.channel;
    buf[14] = h.nextHop;
    buf[15] = h.relayNode;
}

bool mshtDeserializeHeader(const uint8_t* buf, size_t len, MshtHeader& h) {
    if (len < MSHT_HEADER_SIZE) return false;
    memcpy(&h.to, buf + 0, 4);
    memcpy(&h.from, buf + 4, 4);
    memcpy(&h.id, buf + 8, 4);
    h.flags = buf[12];
    h.channel = buf[13];
    h.nextHop = buf[14];
    h.relayNode = buf[15];
    return true;
}

// --- AES-128-CTR encrypt/decrypt (same operation for CTR mode) ---

bool mshtAesCtr(const uint8_t* key, uint32_t packetId, uint32_t fromNode,
                uint8_t* data, size_t len) {
    uint8_t nonce[16] = {0};
    uint64_t pid64 = packetId;
    memcpy(nonce, &pid64, 8);        // bytes 0-7: packetId LE zero-extended
    memcpy(nonce + 8, &fromNode, 4); // bytes 8-11: fromNode LE
    // bytes 12-15: 0 (CTR block counter start)

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);

    uint8_t stream[16] = {0};
    size_t offset = 0;
    int ret = mbedtls_aes_crypt_ctr(&aes, len, &offset, nonce, stream, data, data);
    mbedtls_aes_free(&aes);
    return ret == 0;
}

// --- Protobuf varint encode/decode (minimal, hand-rolled) ---

size_t pbEncodeVarint(uint8_t* buf, uint32_t val) {
    size_t i = 0;
    while (val > 0x7F) { buf[i++] = (val & 0x7F) | 0x80; val >>= 7; }
    buf[i++] = val & 0x7F;
    return i;
}

uint32_t pbDecodeVarint(const uint8_t* buf, size_t len, size_t& pos) {
    uint32_t val = 0;
    uint8_t shift = 0;
    while (pos < len) {
        uint8_t b = buf[pos++];
        val |= (uint32_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift >= 35) break; // overflow guard
    }
    return val;
}

// Encode Pigeon data as protobuf Data{portnum=256, payload=pigeonData}
size_t mshtEncodeData(const uint8_t* pigeonData, size_t pigeonLen, uint8_t* buf) {
    size_t pos = 0;
    buf[pos++] = 0x08; // field 1 (portnum), varint wire type
    pos += pbEncodeVarint(buf + pos, MSHT_PORTNUM_PRIVATE_APP); // 256
    buf[pos++] = 0x12; // field 2 (payload), length-delimited wire type
    pos += pbEncodeVarint(buf + pos, pigeonLen);
    memcpy(buf + pos, pigeonData, pigeonLen);
    return pos + pigeonLen;
}

// Decode protobuf Data — extract portnum and payload fields
bool mshtDecodeData(const uint8_t* buf, size_t len,
                    uint32_t& portnum, const uint8_t*& outPayload, size_t& outLen) {
    size_t pos = 0;
    portnum = 0;
    outPayload = nullptr;
    outLen = 0;
    while (pos < len) {
        uint32_t tag = pbDecodeVarint(buf, len, pos);
        uint32_t fieldNum = tag >> 3;
        uint32_t wireType = tag & 0x07;
        if (fieldNum == 1 && wireType == 0) {        // portnum, varint
            portnum = pbDecodeVarint(buf, len, pos);
        } else if (fieldNum == 2 && wireType == 2) { // payload, length-delimited
            outLen = pbDecodeVarint(buf, len, pos);
            if (outLen > len || pos + outLen > len) { outLen = 0; break; }
            outPayload = buf + pos;
            pos += outLen;
        } else if (wireType == 0) {
            pbDecodeVarint(buf, len, pos); // skip unknown varint
        } else if (wireType == 2) {
            uint32_t slen = pbDecodeVarint(buf, len, pos);
            if (slen > len || pos + slen > len) break;
            pos += slen; // skip unknown bytes
        } else {
            break; // unknown wire type, stop
        }
    }
    return outPayload != nullptr;
}

// --- Meshtastic packet ID generation ---

uint32_t mshtGeneratePacketId() {
    uint32_t counter = (mshtPacketCounter++) & 0x3FF; // bottom 10 bits rolling
    return counter | ((uint32_t)esp_random() & 0xFFFFFC00); // top 22 bits random
}

// --- Meshtastic dedup ---

bool mshtIsDuplicate(uint32_t from, uint32_t id) {
    uint32_t now = millis();
    for (size_t i = 0; i < DEDUP_TABLE_SIZE; i++) {
        if (mshtDedupTable[i].active) {
            if (now - mshtDedupTable[i].timestamp > DEDUP_EXPIRY_MS) {
                mshtDedupTable[i].active = false;
                continue;
            }
            if (mshtDedupTable[i].from == from && mshtDedupTable[i].id == id)
                return true;
        }
    }
    return false;
}

void mshtAddDedup(uint32_t from, uint32_t id) {
    size_t slot = 0;
    uint32_t oldest = UINT32_MAX;
    for (size_t i = 0; i < DEDUP_TABLE_SIZE; i++) {
        if (!mshtDedupTable[i].active) { slot = i; break; }
        if (mshtDedupTable[i].timestamp < oldest) {
            oldest = mshtDedupTable[i].timestamp;
            slot = i;
        }
    }
    mshtDedupTable[slot] = {from, id, millis(), true};
}

// --- Neighbor RSSI table ---

void updateNeighbor(uint32_t nodeNum, float rssi) {
    size_t slot = 0;
    uint32_t oldest = UINT32_MAX;
    for (size_t i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
        if (neighborTable[i].active && neighborTable[i].nodeNum == nodeNum) {
            neighborTable[i].rssi = rssi;
            neighborTable[i].lastSeen = millis();
            return;
        }
        if (!neighborTable[i].active) { slot = i; oldest = 0; }
        else if (neighborTable[i].lastSeen < oldest) {
            oldest = neighborTable[i].lastSeen;
            slot = i;
        }
    }
    neighborTable[slot] = {nodeNum, rssi, millis(), true};
}

// RSSI-based relay delay: strong signal = short delay, weak = long delay
uint32_t mshtRelayDelay(float rssi) {
    if (rssi > -50.0f) return 20;
    if (rssi < -130.0f) return 500;
    return (uint32_t)(20.0f + (-50.0f - rssi) * (480.0f / 80.0f));
}

// ============================================================================
// Mesh packet serialization (Pigeon Native)
// ============================================================================

size_t serializePacket(const MeshPacket& pkt, uint8_t* buf) {
    memcpy(buf, pkt.sender, ADDR_LEN);
    memcpy(buf + ADDR_LEN, pkt.dest, ADDR_LEN);
    buf[12] = (pkt.msgID >> 8) & 0xFF;
    buf[13] = pkt.msgID & 0xFF;
    buf[14] = pkt.ttl;
    buf[15] = pkt.payloadLen;
    if (pkt.payloadLen > 0) {
        memcpy(buf + MESH_HEADER_SIZE, pkt.payload, pkt.payloadLen);
    }
    return MESH_HEADER_SIZE + pkt.payloadLen;
}

bool deserializePacket(const uint8_t* buf, size_t len, MeshPacket& pkt) {
    if (len < MESH_HEADER_SIZE) return false;
    memcpy(pkt.sender, buf, ADDR_LEN);
    memcpy(pkt.dest, buf + ADDR_LEN, ADDR_LEN);
    pkt.msgID = ((uint16_t)buf[12] << 8) | buf[13];
    pkt.ttl = buf[14];
    pkt.payloadLen = buf[15];
    if (pkt.payloadLen > MAX_LORA_PACKET - MESH_HEADER_SIZE) return false;
    if (len < MESH_HEADER_SIZE + pkt.payloadLen) return false;
    memcpy(pkt.payload, buf + MESH_HEADER_SIZE, pkt.payloadLen);
    return true;
}

// ============================================================================
// LoRa transmit and fragmentation
// ============================================================================

bool meshTransmitRaw(MeshPacket& pkt) {
    uint8_t buf[MAX_LORA_PACKET];
    size_t len = serializePacket(pkt, buf);
    int state = radio.transmit(buf, len);
    radio.startReceive();
    rxFlag = false; // Clear AFTER startReceive to avoid losing RX interrupt
    return state == RADIOLIB_ERR_NONE;
}

// Send fragmented message over LoRa mesh
void meshSendFragmented(const uint8_t* dest, const uint8_t* data, size_t dataLen) {
    uint16_t fragGroupID = nextFragGroupID++;
    // Skip ranges where high byte matches a beacon type — prevents fragment/beacon
    // misclassification in the LoRa receive dispatcher (payload[0] == beacon type check)
    if ((fragGroupID >> 8) <= BEACON_TYPE_PRESENCE_V2) {
        fragGroupID = (BEACON_TYPE_PRESENCE_V2 + 1) << 8; // 0x0300
        nextFragGroupID = fragGroupID + 1;
    }
    uint8_t fragTotal = (dataLen + MAX_FRAG_DATA - 1) / MAX_FRAG_DATA;
    if (fragTotal == 0) fragTotal = 1;

    char destStr[18];
    macToStr(dest, destStr);
    Serial.printf("[LORA TX] to=%s fragGroup=%04X frags=%d totalBytes=%d\n",
                  destStr, fragGroupID, fragTotal, dataLen);

    for (uint8_t i = 0; i < fragTotal; i++) {
        MeshPacket pkt;
        memcpy(pkt.sender, nodeAddr, ADDR_LEN);
        memcpy(pkt.dest, dest, ADDR_LEN);
        pkt.msgID = nextMsgID++;
        pkt.ttl = DEFAULT_TTL;

        // Fragment header
        pkt.payload[0] = (fragGroupID >> 8) & 0xFF;
        pkt.payload[1] = fragGroupID & 0xFF;
        pkt.payload[2] = i;
        pkt.payload[3] = fragTotal;

        // Fragment data
        size_t offset = i * MAX_FRAG_DATA;
        size_t fragLen = dataLen - offset;
        if (fragLen > MAX_FRAG_DATA) fragLen = MAX_FRAG_DATA;
        memcpy(pkt.payload + FRAG_HEADER_SIZE, data + offset, fragLen);
        pkt.payloadLen = FRAG_HEADER_SIZE + fragLen;

        addDedup(pkt.sender, pkt.msgID);

        if (!meshTransmitRaw(pkt)) {
            Serial.printf("[LORA TX] Fragment %d/%d FAILED\n", i + 1, fragTotal);
        }

        // Small delay between fragments to avoid receiver overload
        if (i < fragTotal - 1) delay(100);
    }
}

// ============================================================================
// Meshtastic TX path
// ============================================================================

// Transmit a single Pigeon payload wrapped in a Meshtastic packet
bool mshtTransmit(uint32_t destNode, const uint8_t* pigeonData, size_t pigeonLen) {
    if (pigeonLen > MSHT_MAX_PIGEON_DATA) return false;

    // Encode as protobuf Data{portnum=256, payload=pigeonData}
    uint8_t pbBuf[MSHT_MAX_PAYLOAD];
    size_t pbLen = mshtEncodeData(pigeonData, pigeonLen, pbBuf);

    // AES-CTR encrypt the protobuf payload
    uint32_t pktId = mshtGeneratePacketId();
    mshtAesCtr(MSHT_DEFAULT_PSK, pktId, mshtNodeNum, pbBuf, pbLen);

    // Build header
    MshtHeader hdr;
    hdr.to = destNode;
    hdr.from = mshtNodeNum;
    hdr.id = pktId;
    hdr.flags = MSHT_HOP_DEFAULT | (MSHT_HOP_DEFAULT << 5); // hop_limit=3, hop_start=3
    hdr.channel = MSHT_CHANNEL_HASH;
    hdr.nextHop = 0;
    hdr.relayNode = 0;

    uint8_t buf[MSHT_MAX_PACKET];
    mshtSerializeHeader(hdr, buf);
    memcpy(buf + MSHT_HEADER_SIZE, pbBuf, pbLen);

    mshtAddDedup(mshtNodeNum, pktId);

    int state = radio.transmit(buf, MSHT_HEADER_SIZE + pbLen);
    radio.startReceive();
    rxFlag = false;
    return state == RADIOLIB_ERR_NONE;
}

// Build V2 beacon payload into buffer. Returns payload length (0 if nothing to send).
// Shared between Pigeon Native and Meshtastic modes.
size_t buildBeaconPayload(uint8_t* buf, size_t bufSize) {
    static uint8_t beaconRoundRobin = 0;

    // Collect all known public keys: registered phones + peer table
    struct PubKeyEntry { uint8_t key[PUBKEY_LEN]; };
    PubKeyEntry allKeys[MAX_REGISTERED_PHONES + PEER_TABLE_SIZE];
    uint8_t totalKeys = 0;

    for (size_t i = 0; i < MAX_REGISTERED_PHONES; i++) {
        if (registeredPhones[i].active && registeredPhones[i].hasPublicKey) {
            memcpy(allKeys[totalKeys].key, registeredPhones[i].publicKey, PUBKEY_LEN);
            totalKeys++;
        }
    }
    for (int i = 0; i < (int)PEER_TABLE_SIZE; i++) {
        if (peerTable[i].active && peerTable[i].hasPublicKey) {
            bool dup = false;
            for (uint8_t k = 0; k < totalKeys; k++) {
                if (memcmp(allKeys[k].key, peerTable[i].publicKey, PUBKEY_LEN) == 0) {
                    dup = true; break;
                }
            }
            if (!dup) {
                memcpy(allKeys[totalKeys].key, peerTable[i].publicKey, PUBKEY_LEN);
                totalKeys++;
            }
        }
    }

    uint8_t numToSend = (totalKeys <= MAX_BEACON_PEERS) ? totalKeys : MAX_BEACON_PEERS;
    uint8_t startIdx = 0;
    if (totalKeys > MAX_BEACON_PEERS) {
        startIdx = beaconRoundRobin % totalKeys;
        beaconRoundRobin++;
    }

    size_t payloadLen = 2 + numToSend * PUBKEY_LEN;
    if (payloadLen > bufSize) return 0;

    buf[0] = BEACON_TYPE_PRESENCE_V2;
    buf[1] = numToSend;
    for (uint8_t p = 0; p < numToSend; p++) {
        uint8_t idx = (startIdx + p) % totalKeys;
        memcpy(buf + 2 + p * PUBKEY_LEN, allKeys[idx].key, PUBKEY_LEN);
    }
    return payloadLen;
}

// Send beacon wrapped in Meshtastic packet
void sendMshtBeacon() {
    uint8_t beaconBuf[MSHT_MAX_PIGEON_DATA];
    size_t beaconLen = buildBeaconPayload(beaconBuf, sizeof(beaconBuf));
    if (beaconLen > 0) {
        mshtTransmit(MSHT_BROADCAST, beaconBuf, beaconLen);
        Serial.printf("[MSHT BEACON] Sent v2 presence (%d bytes)\n", beaconLen);
    }
}

// ============================================================================
// LoRa fragment reassembly
// ============================================================================

// Returns index into loraRxQueue if message complete, -1 otherwise
int loraReassemble(const uint8_t* sender, uint16_t fragGroupID,
                   uint8_t fragIndex, uint8_t fragTotal,
                   const uint8_t* fragData, size_t fragDataLen) {
    uint32_t now = millis();

    // Find existing slot or allocate new
    int slotIdx = -1;
    for (int i = 0; i < (int)LORA_REASM_SLOTS; i++) {
        if (loraReasmTable[i].active) {
            if (now - loraReasmTable[i].timestamp > LORA_REASM_TIMEOUT) {
                loraReasmTable[i].active = false;
                continue;
            }
            if (addrMatch(loraReasmTable[i].sender, sender) &&
                loraReasmTable[i].fragGroupID == fragGroupID) {
                slotIdx = i;
                break;
            }
        }
    }

    if (slotIdx < 0) {
        // Allocate new slot
        for (int i = 0; i < (int)LORA_REASM_SLOTS; i++) {
            if (!loraReasmTable[i].active) { slotIdx = i; break; }
        }
        if (slotIdx < 0) {
            // Evict oldest
            uint32_t oldest = UINT32_MAX;
            slotIdx = 0;
            for (int i = 0; i < (int)LORA_REASM_SLOTS; i++) {
                if (loraReasmTable[i].timestamp < oldest) {
                    oldest = loraReasmTable[i].timestamp;
                    slotIdx = i;
                }
            }
        }
        memset(&loraReasmTable[slotIdx], 0, sizeof(LoRaReasmSlot));
        memcpy(loraReasmTable[slotIdx].sender, sender, ADDR_LEN);
        loraReasmTable[slotIdx].fragGroupID = fragGroupID;
        loraReasmTable[slotIdx].fragTotal = fragTotal;
        loraReasmTable[slotIdx].timestamp = now;
        loraReasmTable[slotIdx].active = true;
    }

    LoRaReasmSlot& slot = loraReasmTable[slotIdx];
    if (fragIndex >= 16 || fragIndex >= fragTotal) return -1;

    if (!slot.fragPresent[fragIndex]) {
        // Store fragment data at the correct offset
        size_t offset = (size_t)fragIndex * MAX_FRAG_DATA;
        if (offset + fragDataLen > MAX_LORA_MSG_SIZE) return -1;
        memcpy(slot.data + offset, fragData, fragDataLen);
        slot.fragSizes[fragIndex] = fragDataLen;
        slot.fragPresent[fragIndex] = true;
        slot.fragsReceived++;
    }

    if (slot.fragsReceived >= slot.fragTotal) {
        // Calculate total size
        size_t totalLen = 0;
        for (uint8_t i = 0; i < slot.fragTotal; i++) {
            totalLen += slot.fragSizes[i];
        }

        // Find free slot in loraRxQueue
        for (int q = 0; q < (int)LORA_RX_QUEUE_SIZE; q++) {
            if (!loraRxQueue[q].pending) {
                // Reassemble into contiguous buffer
                size_t pos = 0;
                for (uint8_t i = 0; i < slot.fragTotal; i++) {
                    size_t fragOff = (size_t)i * MAX_FRAG_DATA;
                    memcpy(loraRxQueue[q].data + pos, slot.data + fragOff, slot.fragSizes[i]);
                    pos += slot.fragSizes[i];
                }
                loraRxQueue[q].len = totalLen;
                loraRxQueue[q].pending = true;
                slot.active = false;

                char senderStr[18];
                macToStr(sender, senderStr);
                Serial.printf("[LORA RX] Reassembled from=%s fragGroup=%04X totalBytes=%d\n",
                              senderStr, fragGroupID, totalLen);
                return q;
            }
        }
        Serial.println("[LORA RX] Queue full, dropping reassembled message");
        slot.active = false;
    }
    return -1;
}

// ============================================================================
// LoRa receive handler
// ============================================================================

void handleLoRaReceive() {
    uint8_t buf[MAX_LORA_PACKET];
    int state = radio.readData(buf, MAX_LORA_PACKET);

    if (state == RADIOLIB_ERR_NONE) {
        lastRSSI = radio.getRSSI();
        hasRSSI = true;
        size_t len = radio.getPacketLength();
        MeshPacket pkt;

        if (deserializePacket(buf, len, pkt)) {
            char senderStr[18];
            macToStr(pkt.sender, senderStr);

            if (!isDuplicate(pkt.sender, pkt.msgID)) {
                addDedup(pkt.sender, pkt.msgID);
                statLoRaRx++;

                bool forUs = addrMatch(pkt.dest, nodeAddr) || isBroadcast(pkt.dest);

                bool isBeacon = (pkt.payload[0] == BEACON_TYPE_PRESENCE ||
                                pkt.payload[0] == BEACON_TYPE_PRESENCE_V2);
                if (forUs && pkt.payloadLen >= 1 && isBeacon) {
                    // Presence beacon — update peer table
                    handlePresenceBeacon(pkt.sender, pkt.payload, pkt.payloadLen, lastRSSI);
                } else if (forUs && pkt.payloadLen >= FRAG_HEADER_SIZE && !isBeacon) {
                    // Message fragment — reassemble
                    uint16_t fragGroupID = ((uint16_t)pkt.payload[0] << 8) | pkt.payload[1];
                    uint8_t fragIndex = pkt.payload[2];
                    uint8_t fragTotal = pkt.payload[3];
                    const uint8_t* fragData = pkt.payload + FRAG_HEADER_SIZE;
                    size_t fragDataLen = pkt.payloadLen - FRAG_HEADER_SIZE;

                    if (fragTotal == 0 || fragTotal > 16) {
                        Serial.printf("[LORA RX] Invalid fragTotal=%d from %s, dropping\n",
                                      fragTotal, senderStr);
                    } else {
                        Serial.printf("[LORA RX] from=%s frag=%d/%d fragGroup=%04X\n",
                                      senderStr, fragIndex + 1, fragTotal, fragGroupID);
                        loraReassemble(pkt.sender, fragGroupID, fragIndex, fragTotal, fragData, fragDataLen);
                    }
                }

                // Queue for relay if not from us and TTL allows
                // (Deferred relay prevents fragment loss — TX during RX drops next fragment)
                if (!addrMatch(pkt.sender, nodeAddr) && pkt.ttl > 1) {
                    pkt.ttl--;
                    // Serialize and queue instead of transmitting inline
                    bool queued = false;
                    for (int q = 0; q < (int)RELAY_QUEUE_SIZE; q++) {
                        if (!relayQueue[q].pending) {
                            relayQueue[q].len = serializePacket(pkt, relayQueue[q].data);
                            relayQueue[q].pending = true;
                            queued = true;
                            break;
                        }
                    }
                    if (!queued) {
                        static uint32_t relayDrops = 0;
                        relayDrops++;
                        Serial.printf("[RELAY] Queue full, dropping packet (total drops: %lu)\n",
                                      (unsigned long)relayDrops);
                    }
                }
            }
        }
    } else if (state != -7) { // Don't spam CRC errors
        Serial.printf("[LORA] Read error: %d\n", state);
    }

    radio.startReceive();
}

// ============================================================================
// Meshtastic RX path
// ============================================================================

void handleMshtReceive() {
    uint8_t buf[MSHT_MAX_PACKET];
    int state = radio.readData(buf, MSHT_MAX_PACKET);
    if (state != RADIOLIB_ERR_NONE) {
        if (state != -7) Serial.printf("[MSHT] Read error: %d\n", state);
        radio.startReceive();
        return;
    }

    size_t len = radio.getPacketLength();
    lastRSSI = radio.getRSSI();
    hasRSSI = true;

    MshtHeader hdr;
    if (!mshtDeserializeHeader(buf, len, hdr)) { radio.startReceive(); return; }
    if (hdr.from == 0 || hdr.from == mshtNodeNum) { radio.startReceive(); return; }

    // Duplicate check — also drives relay suppression
    bool isDup = mshtIsDuplicate(hdr.from, hdr.id);

    if (isDup) {
        // Suppress any pending relay of this packet (heard from better node)
        for (int q = 0; q < (int)RELAY_QUEUE_SIZE; q++) {
            if (mshtRelayQueue[q].pending &&
                mshtRelayQueue[q].from == hdr.from && mshtRelayQueue[q].id == hdr.id) {
                mshtRelayQueue[q].pending = false;
            }
        }
        radio.startReceive();
        return;
    }

    mshtAddDedup(hdr.from, hdr.id);
    updateNeighbor(hdr.from, lastRSSI);
    statLoRaRx++;

    // Queue for relay if hop_limit > 0
    uint8_t hopLimit = hdr.flags & 0x07;
    if (hopLimit > 0) {
        // Decrement hop_limit, set relay_node to our last byte
        buf[12] = (hdr.flags & 0xF8) | ((hopLimit - 1) & 0x07);
        buf[15] = (uint8_t)(mshtNodeNum & 0xFF);

        uint32_t relayDelay = mshtRelayDelay(lastRSSI);
        for (int q = 0; q < (int)RELAY_QUEUE_SIZE; q++) {
            if (!mshtRelayQueue[q].pending) {
                memcpy(mshtRelayQueue[q].data, buf, len);
                mshtRelayQueue[q].len = len;
                mshtRelayQueue[q].from = hdr.from;
                mshtRelayQueue[q].id = hdr.id;
                mshtRelayQueue[q].queuedAt = millis();
                mshtRelayQueue[q].delayMs = relayDelay;
                mshtRelayQueue[q].pending = true;
                break;
            }
        }
    }

    // Decrypt payload
    size_t payloadLen = len - MSHT_HEADER_SIZE;
    if (payloadLen == 0) { radio.startReceive(); return; }

    uint8_t decrypted[MSHT_MAX_PAYLOAD];
    memcpy(decrypted, buf + MSHT_HEADER_SIZE, payloadLen);
    mshtAesCtr(MSHT_DEFAULT_PSK, hdr.id, hdr.from, decrypted, payloadLen);

    // Parse protobuf — extract portnum and payload
    uint32_t portnum = 0;
    const uint8_t* pigeonData = nullptr;
    size_t pigeonLen = 0;
    if (!mshtDecodeData(decrypted, payloadLen, portnum, pigeonData, pigeonLen)) {
        radio.startReceive();
        return; // Can't parse protobuf — still relayed above
    }

    if (portnum != MSHT_PORTNUM_PRIVATE_APP || pigeonLen == 0) {
        // Stock Meshtastic traffic — relay only, no BLE delivery
        Serial.printf("[MSHT RX] Stock Meshtastic portnum=%d from=%08X (relay only)\n",
                      portnum, hdr.from);
        radio.startReceive();
        return;
    }

    // Pigeon payload — process beacon or deliver raw to BLE
    bool isBeacon = (pigeonData[0] == BEACON_TYPE_PRESENCE ||
                     pigeonData[0] == BEACON_TYPE_PRESENCE_V2);

    if (isBeacon && pigeonLen >= 2 && pigeonLen <= 255) {
        // Beacon: handle for peer discovery (not delivered to BLE)
        uint8_t senderPadded[6] = {0};
        memcpy(senderPadded + 2, &hdr.from, 4);
        handlePresenceBeacon(senderPadded, pigeonData, (uint8_t)pigeonLen, lastRSSI);
    } else {
        // Non-beacon payload (e.g. CompactEnvelope from iOS) — deliver raw to BLE
        bool queued = false;
        for (int q = 0; q < (int)LORA_RX_QUEUE_SIZE; q++) {
            if (!loraRxQueue[q].pending) {
                memcpy(loraRxQueue[q].data, pigeonData, pigeonLen);
                loraRxQueue[q].len = pigeonLen;
                loraRxQueue[q].pending = true;
                queued = true;
                break;
            }
        }
        if (queued) {
            Serial.printf("[MSHT RX] from=%08X payload=%d bytes, queued for BLE\n",
                          hdr.from, pigeonLen);
        } else {
            Serial.println("[MSHT RX] LoRa->BLE queue full, dropping payload");
        }
    }

    radio.startReceive();
}

// ============================================================================
// BLE chunk reassembly (incoming from phone)
// ============================================================================

void handleBLEChunkWrite(const uint8_t* data, size_t len) {
    if (len < BLE_CHUNK_HEADER) {
        Serial.printf("[BLE RX] Chunk too short: %d bytes\n", len);
        return;
    }

    // Parse chunk header (all big-endian)
    const uint8_t* msgID = data;               // 16 bytes
    uint16_t chunkIndex = ((uint16_t)data[16] << 8) | data[17];
    uint16_t totalChunks = ((uint16_t)data[18] << 8) | data[19];
    uint16_t payloadSize = ((uint16_t)data[20] << 8) | data[21];
    const uint8_t* payload = data + BLE_CHUNK_HEADER;

    if (payloadSize > len - BLE_CHUNK_HEADER) {
        Serial.printf("[BLE RX] Payload size mismatch\n");
        return;
    }

    Serial.printf("[BLE RX] chunk %d/%d payloadSize=%d\n",
                  chunkIndex + 1, totalChunks, payloadSize);

    // Find or create reassembly slot
    uint32_t now = millis();
    int slotIdx = -1;
    for (int i = 0; i < (int)BLE_REASM_SLOTS; i++) {
        if (bleReasmTable[i].active) {
            if (now - bleReasmTable[i].timestamp > BLE_REASM_TIMEOUT) {
                bleReasmTable[i].active = false;
                continue;
            }
            if (memcmp(bleReasmTable[i].messageID, msgID, 16) == 0) {
                slotIdx = i;
                break;
            }
        }
    }

    if (slotIdx < 0) {
        for (int i = 0; i < (int)BLE_REASM_SLOTS; i++) {
            if (!bleReasmTable[i].active) { slotIdx = i; break; }
        }
        if (slotIdx < 0) {
            // Evict oldest slot
            uint32_t oldest = UINT32_MAX;
            slotIdx = 0;
            for (int i = 0; i < (int)BLE_REASM_SLOTS; i++) {
                if (bleReasmTable[i].timestamp < oldest) {
                    oldest = bleReasmTable[i].timestamp;
                    slotIdx = i;
                }
            }
            Serial.println("[BLE RX] Evicting oldest reassembly slot");
        }
        memset(&bleReasmTable[slotIdx], 0, sizeof(BLEReasmSlot));
        memcpy(bleReasmTable[slotIdx].messageID, msgID, 16);
        bleReasmTable[slotIdx].totalChunks = totalChunks;
        bleReasmTable[slotIdx].timestamp = now;
        bleReasmTable[slotIdx].active = true;
    }

    BLEReasmSlot& slot = bleReasmTable[slotIdx];
    if (chunkIndex >= 16 || chunkIndex >= totalChunks) return;

    if (!slot.chunkPresent[chunkIndex]) {
        size_t offset = (size_t)chunkIndex * BLE_MAX_CHUNK_DATA;
        if (offset + payloadSize > MAX_LORA_MSG_SIZE) return;
        memcpy(slot.data + offset, payload, payloadSize);
        slot.chunkSizes[chunkIndex] = payloadSize;
        slot.chunkPresent[chunkIndex] = true;
        slot.chunksReceived++;
    }

    if (slot.chunksReceived >= slot.totalChunks) {
        // Reassemble complete — queue for LoRa TX
        size_t totalLen = 0;
        for (uint16_t i = 0; i < slot.totalChunks; i++) {
            totalLen += slot.chunkSizes[i];
        }

        bool queued = false;
        for (int q = 0; q < (int)BLE_TX_QUEUE_SIZE; q++) {
            if (!bleTxQueue[q].pending) {
                size_t pos = 0;
                for (uint16_t i = 0; i < slot.totalChunks; i++) {
                    size_t chunkOff = (size_t)i * BLE_MAX_CHUNK_DATA;
                    memcpy(bleTxQueue[q].data + pos, slot.data + chunkOff, slot.chunkSizes[i]);
                    pos += slot.chunkSizes[i];
                }
                bleTxQueue[q].len = totalLen;
                bleTxQueue[q].pending = true;
                queued = true;
                Serial.printf("[BLE RX] Complete message reassembled: %d bytes -> LoRa TX queue\n", totalLen);
                break;
            }
        }
        if (!queued) {
            // Keep slot active so next loop iteration can retry when a TX slot frees up
            Serial.printf("[BLE RX] TX queue full, deferring %d byte message (will retry)\n", totalLen);
            return;
        }
        slot.active = false;
    }
}

// ============================================================================
// Phone registration (phone identifies itself to the node)
// ============================================================================

void handleBridgeWrite(const uint8_t* data, size_t len) {
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, data, len);
    if (err) {
        Serial.printf("[BRIDGE] JSON parse error: %s\n", err.c_str());
        return;
    }

    // LoRa mode switch: {"lora_mode":"meshtastic"} or {"lora_mode":"native"}
    if (!doc["lora_mode"].isNull()) {
        const char* mode = doc["lora_mode"];
        LoRaMode newMode = LORA_NATIVE;
        if (mode && strcmp(mode, "meshtastic") == 0) newMode = LORA_MESHTASTIC;

        Preferences prefs;
        prefs.begin("pigeon", false);
        prefs.putUChar("lora_mode", newMode);
        prefs.end();

        Serial.printf("[BRIDGE] LoRa mode set to %s, rebooting...\n",
                      newMode == LORA_MESHTASTIC ? "Meshtastic" : "Native");
        delay(500);
        ESP.restart();
        return;
    }

    // WiFi provisioning: {"ssid":"...", "pass":"..."}
    if (!doc["ssid"].isNull()) {
        if (loraMode == LORA_MESHTASTIC) {
            Serial.println("[BRIDGE] WiFi bridge not available in Meshtastic mode");
            return;
        }
        const char* ssid = doc["ssid"];
        const char* pass = doc["pass"] | "";
        if (!ssid || strlen(ssid) == 0) {
            Serial.println("[BRIDGE] Empty SSID, ignoring");
            return;
        }
        Serial.println("[BRIDGE] WiFi provisioning requested");
        saveWiFiCredentials(ssid, pass);
        setupWiFi();
        // Defer notification — WiFi.begin() triggers a radio coex switch that
        // can drop BLE notifications if sent immediately. Reuse the deferred
        // notify mechanism (fires after DEFERRED_NOTIFY_DELAY_MS in loop).
        pendingNotifyStart = millis();
        pendingConnectNotify = true;
        return;
    }

    // WiFi disconnect: {"wifi":"off"}
    if (!doc["wifi"].isNull()) {
        const char* wifiCmd = doc["wifi"];
        if (wifiCmd && strcmp(wifiCmd, "off") == 0) {
            Serial.println("[BRIDGE] WiFi disconnect requested");
            WiFi.disconnect(true);
            clearWiFiCredentials();
            notifyBridgeStatus();
        }
        return;
    }

    // Phone registration: {"type":"register","pigeonID":"a1b2c3d4"}
    const char* cmdType = doc["type"];
    if (cmdType && strcmp(cmdType, "register") == 0) {
        const char* pigeonID = doc["pigeonID"];
        if (!pigeonID || strlen(pigeonID) != 8) {
            Serial.printf("[BRIDGE] Invalid pigeonID\n");
            return;
        }

        uint8_t pidBytes[PIGEON_ID_LEN];
        for (int i = 0; i < (int)PIGEON_ID_LEN; i++) {
            char hex[3] = {pigeonID[i*2], pigeonID[i*2+1], '\0'};
            pidBytes[i] = (uint8_t)strtol(hex, nullptr, 16);
        }

        // Check if already registered
        for (size_t i = 0; i < MAX_REGISTERED_PHONES; i++) {
            if (registeredPhones[i].active && strcmp(registeredPhones[i].pigeonID, pigeonID) == 0) {
                Serial.printf("[BRIDGE] Phone %s already registered (slot %d)\n", pigeonID, i);
                return;
            }
        }

        // Decode optional publicKey (base64-encoded 32-byte Curve25519 key)
        uint8_t phonePubKey[PUBKEY_LEN];
        bool hasPubKey = false;
        const char* pubKeyB64 = doc["publicKey"];
        if (pubKeyB64 && strlen(pubKeyB64) > 0) {
            size_t decoded = 0;
            int ret = mbedtls_base64_decode(phonePubKey, PUBKEY_LEN, &decoded,
                                            (const unsigned char*)pubKeyB64, strlen(pubKeyB64));
            if (ret == 0 && decoded == PUBKEY_LEN) {
                hasPubKey = true;
                Serial.printf("[BRIDGE] Phone %s provided public key\n", pigeonID);
            } else {
                Serial.printf("[BRIDGE] Phone %s publicKey decode failed (ret=%d, len=%d)\n",
                              pigeonID, ret, (int)decoded);
            }
        }

        // Find empty slot
        for (size_t i = 0; i < MAX_REGISTERED_PHONES; i++) {
            if (!registeredPhones[i].active) {
                strncpy(registeredPhones[i].pigeonID, pigeonID, 9);
                memcpy(registeredPhones[i].pigeonIDBytes, pidBytes, PIGEON_ID_LEN);
                registeredPhones[i].connId = lastBLEConnId;
                registeredPhones[i].hasPublicKey = hasPubKey;
                if (hasPubKey) memcpy(registeredPhones[i].publicKey, phonePubKey, PUBKEY_LEN);
                registeredPhones[i].active = true;
                Serial.printf("[BRIDGE] Registered phone %s (slot %d, conn_id=%d, hasKey=%d)\n",
                              pigeonID, i, lastBLEConnId, hasPubKey);
                return;
            }
        }
        Serial.println("[BRIDGE] Registration full, ignoring");
        return;
    }

    Serial.printf("[BRIDGE] Unknown command\n");
}

// ============================================================================
// Presence beacon handling (receive beacons from other nodes)
// ============================================================================

// Compute pigeonID (8 hex chars) from a 32-byte public key
void pigeonIDFromPubKey(const uint8_t* pubKey, char* pidOut, uint8_t* pidBytesOut) {
    uint8_t hash[32];
    mbedtls_sha256(pubKey, PUBKEY_LEN, hash, 0);
    snprintf(pidOut, 9, "%02x%02x%02x%02x", hash[0], hash[1], hash[2], hash[3]);
    if (pidBytesOut) memcpy(pidBytesOut, hash, PIGEON_ID_LEN);
}

// Update or insert a peer into the peer table
void upsertPeer(const char* pid, const uint8_t* pubKey, bool hasPubKey,
                float rssi, const char* via) {
    uint32_t now = millis();

    // Skip our own registered phones
    for (size_t i = 0; i < MAX_REGISTERED_PHONES; i++) {
        if (registeredPhones[i].active && strcmp(registeredPhones[i].pigeonID, pid) == 0) {
            return;
        }
    }

    int slot = -1, emptySlot = -1, oldestSlot = 0;
    uint32_t oldestTime = UINT32_MAX;
    for (int i = 0; i < (int)PEER_TABLE_SIZE; i++) {
        if (peerTable[i].active && strcmp(peerTable[i].pigeonID, pid) == 0) {
            slot = i;
            break;
        }
        if (!peerTable[i].active && emptySlot < 0) emptySlot = i;
        if (peerTable[i].active && peerTable[i].lastSeen < oldestTime) {
            oldestTime = peerTable[i].lastSeen;
            oldestSlot = i;
        }
    }

    if (slot < 0) {
        slot = (emptySlot >= 0) ? emptySlot : oldestSlot;
        memcpy(peerTable[slot].pigeonID, pid, 9);
        peerTableChanged = true;
        Serial.printf("[PEERS] New peer %s via %s RSSI=%.1f\n", pid, via, rssi);
    }

    // Upgrade: if we didn't have pubkey but now do, update it
    if (hasPubKey && pubKey && (!peerTable[slot].hasPublicKey || !peerTable[slot].active)) {
        memcpy(peerTable[slot].publicKey, pubKey, PUBKEY_LEN);
        peerTable[slot].hasPublicKey = true;
        peerTableChanged = true;
    }

    peerTable[slot].lastSeen = now;
    peerTable[slot].rssi = rssi;
    peerTable[slot].active = true;
}

void handlePresenceBeacon(const uint8_t* sender, const uint8_t* payload,
                          uint8_t payloadLen, float rssi) {
    if (payloadLen < 2) return;

    uint8_t beaconType = payload[0];
    uint8_t numPeers = payload[1];
    char senderStr[18];
    macToStr(sender, senderStr);
    Serial.printf("[BEACON RX] from=%s type=0x%02X peers=%d RSSI=%.1f\n",
                  senderStr, beaconType, numPeers, rssi);

    // Track the sending node regardless of peer count
    {
        uint32_t now = millis();
        int slot = -1, emptySlot = -1;
        for (int i = 0; i < (int)NODE_TABLE_SIZE; i++) {
            if (nodeTable[i].active && addrMatch(nodeTable[i].addr, sender)) { slot = i; break; }
            if (!nodeTable[i].active && emptySlot < 0) emptySlot = i;
        }
        if (slot < 0) slot = (emptySlot >= 0) ? emptySlot : 0;
        memcpy(nodeTable[slot].addr, sender, ADDR_LEN);
        nodeTable[slot].lastSeen = now;
        nodeTable[slot].active = true;
    }

    if (numPeers == 0) return;

    if (beaconType == BEACON_TYPE_PRESENCE_V2) {
        // V2: [0x02][numPeers][pubKey_1:32B][pubKey_2:32B]...
        size_t expectedLen = 2 + (size_t)numPeers * PUBKEY_LEN;
        if (payloadLen < expectedLen) {
            Serial.printf("[BEACON] Truncated v2 from %s (got %d, need %d)\n",
                          senderStr, payloadLen, (int)expectedLen);
            return;
        }
        for (uint8_t p = 0; p < numPeers; p++) {
            const uint8_t* pubKey = payload + 2 + p * PUBKEY_LEN;
            char pid[9];
            pigeonIDFromPubKey(pubKey, pid, nullptr);
            upsertPeer(pid, pubKey, true, rssi, senderStr);
        }
    } else {
        // V1 legacy: [0x01][numPhones][pigeonID_1:4B][pigeonID_2:4B]...
        size_t expectedLen = 2 + (size_t)numPeers * PIGEON_ID_LEN;
        if (payloadLen < expectedLen) {
            Serial.printf("[BEACON] Truncated v1 from %s (got %d, need %d)\n",
                          senderStr, payloadLen, (int)expectedLen);
            return;
        }
        for (uint8_t p = 0; p < numPeers; p++) {
            const uint8_t* pidBytes = payload + 2 + p * PIGEON_ID_LEN;
            char pid[9];
            snprintf(pid, 9, "%02x%02x%02x%02x",
                     pidBytes[0], pidBytes[1], pidBytes[2], pidBytes[3]);
            upsertPeer(pid, nullptr, false, rssi, senderStr);
        }
    }
}

// Expire old peer entries, returns number of active peers
uint8_t expirePeers() {
    uint32_t now = millis();
    uint8_t count = 0;
    for (int i = 0; i < (int)PEER_TABLE_SIZE; i++) {
        if (peerTable[i].active) {
            if (now - peerTable[i].lastSeen > PEER_EXPIRY_MS) {
                Serial.printf("[PEERS] Expired peer %s\n", peerTable[i].pigeonID);
                peerTable[i].active = false;
                peerTableChanged = true;
            } else {
                count++;
            }
        }
    }
    return count;
}

// ============================================================================
// Crypto helpers (ECDH auth)
// ============================================================================

// HKDF-SHA256 extract-then-expand (manual implementation since mbedtls_hkdf
// is not always linked in Arduino ESP32 builds)
bool hkdfSHA256(const uint8_t* salt, size_t saltLen,
                const uint8_t* ikm, size_t ikmLen,
                const uint8_t* info, size_t infoLen,
                uint8_t* out, size_t outLen) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    uint8_t prk[32];
    if (mbedtls_md_hmac(md, salt, saltLen, ikm, ikmLen, prk) != 0) return false;
    // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01) — only need 32 bytes (one block)
    if (outLen > 32) return false;
    uint8_t expandInput[256];
    if (infoLen + 1 > sizeof(expandInput)) return false;
    memcpy(expandInput, info, infoLen);
    expandInput[infoLen] = 0x01;
    if (mbedtls_md_hmac(md, prk, 32, expandInput, infoLen + 1, out) != 0) return false;
    return true;
}

bool hmacSHA256(const uint8_t* key, size_t keyLen,
                const uint8_t* msg, size_t msgLen,
                uint8_t* out) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_md_hmac(md, key, keyLen, msg, msgLen, out) == 0;
}

bool aesCtrCrypt(const uint8_t* key, size_t keyBits,
                 const uint8_t* nonce, uint8_t* data, size_t len) {
    uint8_t nonceCounter[16];
    memcpy(nonceCounter, nonce, sizeof(nonceCounter));

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int ret = mbedtls_aes_setkey_enc(&aes, key, keyBits);
    if (ret == 0) {
        uint8_t stream[16] = {0};
        size_t offset = 0;
        ret = mbedtls_aes_crypt_ctr(&aes, len, &offset, nonceCounter, stream, data, data);
    }
    mbedtls_aes_free(&aes);
    return ret == 0;
}

bool secureZeroCompare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

// Derives a storage key from nodePrivateKey. If the private key is ever
// regenerated, previously encrypted WiFi passwords become inaccessible.
bool deriveWiFiStorageKey(const char* info, uint8_t* out, size_t outLen) {
    static const uint8_t salt[] = "pigeon-wifi-storage-v1";
    return hkdfSHA256(
        salt, sizeof(salt) - 1,
        nodePrivateKey, sizeof(nodePrivateKey),
        (const uint8_t*)info, strlen(info),
        out, outLen
    );
}

bool storeEncryptedWiFiPassword(Preferences& prefs, const char* pass) {
    size_t passLen = strnlen(pass, sizeof(wifiPass) - 1);
    if (passLen >= sizeof(wifiPass)) return false;

    uint8_t encKey[32];
    uint8_t macKey[32];
    if (!deriveWiFiStorageKey("wifi-pass-enc", encKey, sizeof(encKey)) ||
        !deriveWiFiStorageKey("wifi-pass-mac", macKey, sizeof(macKey))) {
        return false;
    }

    uint8_t iv[WIFI_PASS_IV_LEN];
    uint8_t ciphertext[sizeof(wifiPass) - 1] = {0};
    uint8_t mac[32];
    uint8_t macInput[1 + WIFI_PASS_IV_LEN + (sizeof(wifiPass) - 1)] = {0};

    esp_fill_random(iv, sizeof(iv));
    if (passLen > 0) {
        memcpy(ciphertext, pass, passLen);
        if (!aesCtrCrypt(encKey, 256, iv, ciphertext, passLen)) return false;
    }

    macInput[0] = WIFI_PASS_STORAGE_VERSION;
    memcpy(macInput + 1, iv, sizeof(iv));
    if (passLen > 0) memcpy(macInput + 1 + sizeof(iv), ciphertext, passLen);
    if (!hmacSHA256(macKey, sizeof(macKey), macInput, 1 + sizeof(iv) + passLen, mac)) {
        return false;
    }

    prefs.putUChar(WIFI_PASS_VERSION_KEY, WIFI_PASS_STORAGE_VERSION);
    prefs.putUChar(WIFI_PASS_LENGTH_KEY, (uint8_t)passLen);
    if (prefs.putBytes(WIFI_PASS_IV_KEY, iv, sizeof(iv)) != sizeof(iv)) return false;
    if (passLen > 0 && prefs.putBytes(WIFI_PASS_CT_KEY, ciphertext, passLen) != passLen) return false;
    if (passLen == 0) prefs.remove(WIFI_PASS_CT_KEY);
    if (prefs.putBytes(WIFI_PASS_MAC_KEY, mac, WIFI_PASS_MAC_LEN) != WIFI_PASS_MAC_LEN) return false;
    prefs.remove(WIFI_PASS_LEGACY_KEY);
    return true;
}

bool loadEncryptedWiFiPassword(Preferences& prefs, char* out, size_t outSize) {
    if (prefs.getUChar(WIFI_PASS_VERSION_KEY, 0) != WIFI_PASS_STORAGE_VERSION) {
        return false;
    }

    size_t passLen = prefs.getUChar(WIFI_PASS_LENGTH_KEY, 0xFF);
    if (passLen == 0xFF || passLen >= outSize) {
        return false;
    }

    uint8_t iv[WIFI_PASS_IV_LEN];
    uint8_t storedMac[WIFI_PASS_MAC_LEN];
    if (prefs.getBytes(WIFI_PASS_IV_KEY, iv, sizeof(iv)) != sizeof(iv)) return false;
    if (prefs.getBytes(WIFI_PASS_MAC_KEY, storedMac, sizeof(storedMac)) != sizeof(storedMac)) return false;

    uint8_t ciphertext[sizeof(wifiPass) - 1] = {0};
    if (passLen > 0 && prefs.getBytes(WIFI_PASS_CT_KEY, ciphertext, passLen) != passLen) {
        return false;
    }

    uint8_t encKey[32];
    uint8_t macKey[32];
    if (!deriveWiFiStorageKey("wifi-pass-enc", encKey, sizeof(encKey)) ||
        !deriveWiFiStorageKey("wifi-pass-mac", macKey, sizeof(macKey))) {
        return false;
    }

    uint8_t macInput[1 + WIFI_PASS_IV_LEN + (sizeof(wifiPass) - 1)] = {0};
    macInput[0] = WIFI_PASS_STORAGE_VERSION;
    memcpy(macInput + 1, iv, sizeof(iv));
    if (passLen > 0) memcpy(macInput + 1 + sizeof(iv), ciphertext, passLen);

    uint8_t computedMac[32];
    if (!hmacSHA256(macKey, sizeof(macKey), macInput, 1 + sizeof(iv) + passLen, computedMac) ||
        !secureZeroCompare(storedMac, computedMac, WIFI_PASS_MAC_LEN)) {
        return false;
    }

    if (passLen > 0 && !aesCtrCrypt(encKey, 256, iv, ciphertext, passLen)) {
        return false;
    }

    memcpy(out, ciphertext, passLen);
    out[passLen] = '\0';
    return true;
}

void clearStoredWiFiPassword(Preferences& prefs) {
    prefs.remove(WIFI_PASS_LEGACY_KEY);
    prefs.remove(WIFI_PASS_VERSION_KEY);
    prefs.remove(WIFI_PASS_LENGTH_KEY);
    prefs.remove(WIFI_PASS_IV_KEY);
    prefs.remove(WIFI_PASS_CT_KEY);
    prefs.remove(WIFI_PASS_MAC_KEY);
}

// Parse UUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to 16 raw bytes
bool parseUUID(const char* uuid, uint8_t* out) {
    int pos = 0;
    for (int i = 0; uuid[i] && pos < 16; i++) {
        if (uuid[i] == '-') continue;
        char hex[3] = {uuid[i], uuid[i+1], 0};
        out[pos++] = (uint8_t)strtol(hex, nullptr, 16);
        i++;
    }
    return pos == 16;
}

// ============================================================================
// Message-level dedup (internet<->LoRa bridging)
// ============================================================================

bool isMsgDuplicate(const uint8_t* msgId) {
    uint32_t now = millis();
    for (size_t i = 0; i < MSG_DEDUP_SIZE; i++) {
        if (msgDedupTable[i].active) {
            if (now - msgDedupTable[i].timestamp > 60000) {
                msgDedupTable[i].active = false;
                continue;
            }
            if (memcmp(msgDedupTable[i].msgId, msgId, 16) == 0) return true;
        }
    }
    return false;
}

void addMsgDedup(const uint8_t* msgId) {
    size_t slot = 0;
    uint32_t oldest = UINT32_MAX;
    for (size_t i = 0; i < MSG_DEDUP_SIZE; i++) {
        if (!msgDedupTable[i].active) { slot = i; break; }
        if (msgDedupTable[i].timestamp < oldest) {
            oldest = msgDedupTable[i].timestamp;
            slot = i;
        }
    }
    memcpy(msgDedupTable[slot].msgId, msgId, 16);
    msgDedupTable[slot].timestamp = millis();
    msgDedupTable[slot].active = true;
}

// ============================================================================
// WiFi connection subsystem
// ============================================================================

// Forward declarations
void notifyBridgeStatus();
void connectWebSocket();

bool loadWiFiCredentials() {
    wifiSSID[0] = '\0';
    wifiPass[0] = '\0';

    Preferences prefs;
    prefs.begin("pigeon", false);
    String ssid = prefs.getString("wifi_ssid", "");
    bool haveEncryptedPassword = loadEncryptedWiFiPassword(prefs, wifiPass, sizeof(wifiPass));
    if (!haveEncryptedPassword && prefs.isKey(WIFI_PASS_LEGACY_KEY)) {
        String legacyPass = prefs.getString(WIFI_PASS_LEGACY_KEY, "");
        strncpy(wifiPass, legacyPass.c_str(), sizeof(wifiPass) - 1);
        wifiPass[sizeof(wifiPass) - 1] = '\0';
        if (!storeEncryptedWiFiPassword(prefs, wifiPass)) {
            Serial.println("[WIFI] Failed to migrate encrypted password storage");
        }
    }
    prefs.end();

    if (ssid.length() > 0) {
        strncpy(wifiSSID, ssid.c_str(), sizeof(wifiSSID) - 1);
        wifiSSID[sizeof(wifiSSID) - 1] = '\0';
        wifiConfigured = true;
        return true;
    }
    return false;
}

void saveWiFiCredentials(const char* ssid, const char* pass) {
    Preferences prefs;
    prefs.begin("pigeon", false);
    prefs.putString("wifi_ssid", ssid);
    if (!storeEncryptedWiFiPassword(prefs, pass)) {
        clearStoredWiFiPassword(prefs);
        Serial.println("[WIFI] Failed to persist encrypted WiFi password");
    }
    prefs.end();

    strncpy(wifiSSID, ssid, sizeof(wifiSSID) - 1);
    strncpy(wifiPass, pass, sizeof(wifiPass) - 1);
    wifiSSID[sizeof(wifiSSID) - 1] = '\0';
    wifiPass[sizeof(wifiPass) - 1] = '\0';
    wifiConfigured = true;
}

void clearWiFiCredentials() {
    Preferences prefs;
    prefs.begin("pigeon", false);
    prefs.remove("wifi_ssid");
    clearStoredWiFiPassword(prefs);
    prefs.end();

    wifiSSID[0] = '\0';
    wifiPass[0] = '\0';
    wifiConfigured = false;
    wifiConnected = false;
    bridgeState = BRIDGE_NO_WIFI;
}

void setupWiFi() {
    if (!wifiConfigured) {
        Serial.println("[WIFI] No credentials configured");
        bridgeState = BRIDGE_NO_WIFI;
        return;
    }

    WiFi.mode(WIFI_STA);
    WiFi.setAutoReconnect(true);
    Serial.println("[WIFI] Connecting to configured network...");
    WiFi.begin(wifiSSID, wifiPass);
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
    bridgeState = BRIDGE_CONNECTING;
    lastWifiRetry = millis();
}

void wifiLoop() {
    if (!wifiConfigured) return;

    bool nowConnected = (WiFi.status() == WL_CONNECTED);

    if (nowConnected && !wifiConnected) {
        wifiConnected = true;
        bridgeState = BRIDGE_WIFI_ONLY;
        Serial.println("[WIFI] Connected");
        connectWebSocket();
        notifyBridgeStatus();
    } else if (!nowConnected && wifiConnected) {
        wifiConnected = false;
        wsConnected = false;
        wsAuthenticated = false;
        bridgeState = BRIDGE_CONNECTING;
        Serial.println("[WIFI] Connection lost, will auto-reconnect");
        notifyBridgeStatus();
    } else if (!nowConnected) {
        uint32_t now = millis();
        if (now - lastWifiRetry >= WIFI_RETRY_MS) {
            lastWifiRetry = now;
            Serial.println("[WIFI] Retrying configured network...");
            WiFi.disconnect();
            WiFi.begin(wifiSSID, wifiPass);
        }
    }
}

// ============================================================================
// WebSocket relay connection
// ============================================================================

// Forward declarations
void sendAuthHello();
void handleAuthChallenge(JsonDocument& doc);
void handleMsgDeliver(JsonDocument& doc);

void webSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
    switch (type) {
        case WStype_DISCONNECTED:
            Serial.println("[WS] Disconnected");
            wsConnected = false;
            wsAuthenticated = false;
            bridgeState = wifiConnected ? BRIDGE_OFFLINE : BRIDGE_CONNECTING;
            notifyBridgeStatus();
            break;

        case WStype_CONNECTED:
            Serial.println("[WS] Connected to relay");
            wsConnected = true;
            wsReconnectDelay = 1000;
            bridgeState = BRIDGE_AUTH;
            notifyBridgeStatus();
            sendAuthHello();
            break;

        case WStype_TEXT: {
            JsonDocument doc;
            DeserializationError err = deserializeJson(doc, payload, length);
            if (err) {
                Serial.printf("[WS] JSON parse error: %s\n", err.c_str());
                break;
            }
            const char* msgType = doc["type"];
            if (!msgType) break;

            if (strcmp(msgType, "auth_challenge") == 0) {
                handleAuthChallenge(doc);
            } else if (strcmp(msgType, "auth_ok") == 0) {
                Serial.println("[AUTH] Authenticated!");
                wsAuthenticated = true;
                bridgeState = BRIDGE_ONLINE;
                notifyBridgeStatus();
            } else if (strcmp(msgType, "auth_error") == 0) {
                Serial.printf("[AUTH] Auth failed: %s\n",
                    doc["payload"]["reason"] | "unknown");
                wsReconnectDelay = WS_MAX_BACKOFF;
                webSocket.disconnect();
            } else if (strcmp(msgType, "msg_deliver") == 0) {
                handleMsgDeliver(doc);
            } else if (strcmp(msgType, "msg_dup") == 0) {
                Serial.printf("[BRIDGE] Server deduped message: %s\n",
                    doc["payload"]["message_id"] | "?");
            }
            break;
        }

        case WStype_PING:
        case WStype_PONG:
            break;

        default:
            break;
    }
}

void connectWebSocket() {
    Serial.printf("[WS] Connecting to %s:%d%s over TLS\n", RELAY_HOST, RELAY_PORT, RELAY_PATH);
    webSocket.beginSslWithCA(RELAY_HOST, RELAY_PORT, RELAY_PATH, RELAY_ROOT_CA);
    webSocket.onEvent(webSocketEvent);
    webSocket.setReconnectInterval(0);
    wsLastAttempt = millis();
}

void wsLoop() {
    if (!wifiConnected) return;

    webSocket.loop();

    if (!wsConnected) {
        uint32_t now = millis();
        if (now - wsLastAttempt >= wsReconnectDelay) {
            wsLastAttempt = now;
            wsReconnectDelay = min(wsReconnectDelay * 2, WS_MAX_BACKOFF);
            connectWebSocket();
        }
    }
}

// ============================================================================
// ECDH auth handshake
// ============================================================================

void sendAuthHello() {
    char json[128];
    snprintf(json, sizeof(json),
        "{\"type\":\"auth_hello\",\"payload\":{\"public_key_b64\":\"%s\"}}",
        nodePublicKeyB64);
    webSocket.sendTXT(json);
    Serial.println("[AUTH] Sent auth_hello");
}

void handleAuthChallenge(JsonDocument& doc) {
    const char* ephPubB64 = doc["payload"]["ephemeral_public_key_b64"];
    const char* nonceB64 = doc["payload"]["nonce_b64"];
    const char* challengeId = doc["payload"]["challenge_id"];
    int64_t issuedAt = doc["payload"]["issued_at"];

    if (!ephPubB64 || !nonceB64 || !challengeId) {
        Serial.println("[AUTH] Invalid auth_challenge: missing fields");
        return;
    }

    uint8_t serverEphPub[32];
    size_t decoded = 0;
    mbedtls_base64_decode(serverEphPub, 32, &decoded,
                          (const unsigned char*)ephPubB64, strlen(ephPubB64));
    if (decoded != 32) {
        Serial.println("[AUTH] Invalid ephemeral public key length");
        return;
    }

    uint8_t nonce[32];
    mbedtls_base64_decode(nonce, 32, &decoded,
                          (const unsigned char*)nonceB64, strlen(nonceB64));
    if (decoded != 32) {
        Serial.println("[AUTH] Invalid nonce length");
        return;
    }

    uint8_t challengeIdBytes[16];
    if (!parseUUID(challengeId, challengeIdBytes)) {
        Serial.println("[AUTH] Invalid challenge_id UUID");
        return;
    }

    // X25519 ECDH
    uint8_t sharedSecret[32];
    curve25519_donna(sharedSecret, nodePrivateKey, serverEphPub);

    // RFC 7748 section 6.1: abort if shared secret is all-zero
    uint8_t zero[32] = {0};
    if (memcmp(sharedSecret, zero, 32) == 0) {
        Serial.println("[AUTH] ECDH produced zero shared secret — aborting");
        webSocket.disconnect();
        return;
    }

    // HKDF-SHA256
    const char* salt = "pigeon-relay-auth-v1";
    uint8_t info[80]; // 16 + 32 + 32
    memcpy(info, challengeIdBytes, 16);
    memcpy(info + 16, nonce, 32);
    memcpy(info + 48, nodePublicKey, 32);

    uint8_t authKey[32];
    if (!hkdfSHA256((const uint8_t*)salt, strlen(salt),
                    sharedSecret, 32, info, 80, authKey, 32)) {
        Serial.println("[AUTH] HKDF failed");
        return;
    }

    // HMAC-SHA256
    uint8_t hmacInput[24]; // 16 + 8
    memcpy(hmacInput, challengeIdBytes, 16);
    for (int i = 7; i >= 0; i--) {
        hmacInput[16 + (7 - i)] = (uint8_t)(issuedAt >> (i * 8));
    }

    uint8_t proof[32];
    if (!hmacSHA256(authKey, 32, hmacInput, 24, proof)) {
        Serial.println("[AUTH] HMAC failed");
        return;
    }

    char proofB64[45];
    size_t proofB64Len = 0;
    mbedtls_base64_encode((unsigned char*)proofB64, sizeof(proofB64),
                          &proofB64Len, proof, 32);
    proofB64[proofB64Len] = '\0';

    char json[256];
    snprintf(json, sizeof(json),
        "{\"type\":\"auth_prove\",\"payload\":{\"challenge_id\":\"%s\",\"proof_b64\":\"%s\"}}",
        challengeId, proofB64);
    webSocket.sendTXT(json);
    Serial.println("[AUTH] Sent auth_prove");
}

// ============================================================================
// Message bridging
// ============================================================================

void bridgeToRelay(const uint8_t* data, size_t len) {
    if (!wsAuthenticated || len < ROUTING_HEADER_SIZE) return;

    const uint8_t* msgIdBytes = data;
    const uint8_t* recipientHash = data + 16;
    const uint8_t* envelope = data + ROUTING_HEADER_SIZE;
    size_t envelopeLen = len - ROUTING_HEADER_SIZE;

    // Don't re-bridge messages we received from the internet
    if (isMsgDuplicate(msgIdBytes)) return;

    char msgIdStr[37];
    snprintf(msgIdStr, sizeof(msgIdStr),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        msgIdBytes[0], msgIdBytes[1], msgIdBytes[2], msgIdBytes[3],
        msgIdBytes[4], msgIdBytes[5], msgIdBytes[6], msgIdBytes[7],
        msgIdBytes[8], msgIdBytes[9], msgIdBytes[10], msgIdBytes[11],
        msgIdBytes[12], msgIdBytes[13], msgIdBytes[14], msgIdBytes[15]);

    char recipientHex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(recipientHex + i * 2, 3, "%02x", recipientHash[i]);
    }

    size_t b64BufSize = 4 * ((envelopeLen + 2) / 3) + 1;
    char* envelopeB64 = (char*)malloc(b64BufSize);
    if (!envelopeB64) {
        Serial.println("[BRIDGE] malloc failed for envelope base64");
        return;
    }
    size_t b64Len = 0;
    mbedtls_base64_encode((unsigned char*)envelopeB64, b64BufSize,
                          &b64Len, envelope, envelopeLen);
    envelopeB64[b64Len] = '\0';

    size_t jsonBufSize = 128 + 36 + 64 + b64Len;
    char* json = (char*)malloc(jsonBufSize);
    if (!json) {
        free(envelopeB64);
        Serial.println("[BRIDGE] malloc failed for JSON");
        return;
    }
    snprintf(json, jsonBufSize,
        "{\"type\":\"msg_send\",\"payload\":"
        "{\"message_id\":\"%s\",\"recipient_hash_hex\":\"%s\",\"envelope_b64\":\"%s\"}}",
        msgIdStr, recipientHex, envelopeB64);

    webSocket.sendTXT(json);
    Serial.printf("[BRIDGE] LoRa->Relay: msgID=%s (%d bytes)\n", msgIdStr, (int)envelopeLen);

    free(envelopeB64);
    free(json);
}

void handleMsgDeliver(JsonDocument& doc) {
    const char* msgIdStr = doc["payload"]["message_id"];
    const char* recipientHashHex = doc["payload"]["recipient_hash_hex"];
    const char* envelopeB64 = doc["payload"]["envelope_b64"];

    if (!msgIdStr || !recipientHashHex || !envelopeB64) {
        Serial.println("[BRIDGE] Invalid msg_deliver: missing fields");
        return;
    }
    if (strlen(recipientHashHex) != 64) {
        Serial.println("[BRIDGE] Invalid recipient_hash_hex length");
        return;
    }

    uint8_t msgIdBytes[16];
    if (!parseUUID(msgIdStr, msgIdBytes)) {
        Serial.println("[BRIDGE] Invalid message_id UUID");
        return;
    }

    if (isMsgDuplicate(msgIdBytes)) {
        Serial.printf("[BRIDGE] Duplicate msg_deliver: %s\n", msgIdStr);
        return;
    }
    addMsgDedup(msgIdBytes);

    uint8_t recipientHash[32];
    for (int i = 0; i < 32; i++) {
        char hex[3] = {recipientHashHex[i*2], recipientHashHex[i*2+1], 0};
        recipientHash[i] = (uint8_t)strtol(hex, nullptr, 16);
    }

    size_t envelopeB64Len = strlen(envelopeB64);
    size_t maxDecoded = envelopeB64Len;
    uint8_t* envelope = (uint8_t*)malloc(maxDecoded);
    if (!envelope) {
        Serial.println("[BRIDGE] malloc failed for envelope decode");
        return;
    }
    size_t envelopeLen = 0;
    mbedtls_base64_decode(envelope, maxDecoded, &envelopeLen,
                          (const unsigned char*)envelopeB64, envelopeB64Len);

    size_t fullLen = ROUTING_HEADER_SIZE + envelopeLen;
    uint8_t* fullMsg = (uint8_t*)malloc(fullLen);
    if (!fullMsg) {
        free(envelope);
        Serial.println("[BRIDGE] malloc failed for full message");
        return;
    }
    memcpy(fullMsg, msgIdBytes, 16);
    memcpy(fullMsg + 16, recipientHash, 32);
    memcpy(fullMsg + ROUTING_HEADER_SIZE, envelope, envelopeLen);
    free(envelope);

    Serial.printf("[BRIDGE] Relay->LoRa: msgID=%s (%d bytes)\n", msgIdStr, (int)envelopeLen);

    meshSendFragmented(BROADCAST_ADDR, fullMsg, fullLen);
    // Strip routing header for BLE delivery — phone expects raw envelope JSON
    bleSendChunked(pMsgChar, fullMsg + ROUTING_HEADER_SIZE, envelopeLen);

    free(fullMsg);

    char ackJson[128];
    snprintf(ackJson, sizeof(ackJson),
        "{\"type\":\"msg_ack\",\"payload\":{\"message_id\":\"%s\"}}", msgIdStr);
    webSocket.sendTXT(ackJson);
}

// ============================================================================
// Identity and bridge status notifications
// ============================================================================

void updateIdentityCharacteristic() {
    if (!pIdentityChar) return;
    char json[512];
    snprintf(json, sizeof(json),
        "{\"publicKey\":\"%s\","
        "\"pigeonID\":\"%s\","
        "\"displayName\":\"Pigeon Mesh Node\","
        "\"bridgeProtocolVersion\":1,"
        "\"bridgeEnabled\":%s,"
        "\"isMeshNode\":true,"
        "\"relayReachable\":%s,"
        "\"loraMode\":\"%s\","
        "\"bridgeCapacityRemaining\":0}",
        nodePublicKeyB64,
        nodePigeonID,
        wifiConfigured ? "true" : "false",
        (bridgeState == BRIDGE_ONLINE) ? "true" : "false",
        loraMode == LORA_MESHTASTIC ? "meshtastic" : "native"
    );
    pIdentityChar->setValue(json);
}

void notifyBridgeStatus() {
    updateIdentityCharacteristic();
    if (!pBridgeChar || !bleClientConnected) {
        Serial.printf("[BRIDGE] Skip notify (char=%s, client=%s)\n",
                      pBridgeChar ? "ok" : "null",
                      bleClientConnected ? "yes" : "no");
        return;
    }

    // iOS app expects ssid/ip fields in bridge_status for the WiFi Bridge UI.
    // BLE is local/short-range so exposing these over BLE is acceptable.
    char json[128];
    if (bridgeState == BRIDGE_ONLINE) {
        snprintf(json, sizeof(json),
            "{\"type\":\"bridge_status\",\"bridge\":\"online\",\"ssid\":\"%s\",\"ip\":\"%s\"}",
            wifiSSID, WiFi.localIP().toString().c_str());
    } else if (bridgeState == BRIDGE_WIFI_ONLY || bridgeState == BRIDGE_AUTH) {
        snprintf(json, sizeof(json),
            "{\"type\":\"bridge_status\",\"bridge\":\"wifi_connected\",\"ssid\":\"%s\",\"ip\":\"%s\"}",
            wifiSSID, WiFi.localIP().toString().c_str());
    } else if (bridgeState == BRIDGE_OFFLINE) {
        snprintf(json, sizeof(json),
            "{\"type\":\"bridge_status\",\"bridge\":\"offline\",\"ssid\":\"%s\"}", wifiSSID);
    } else if (bridgeState == BRIDGE_NO_WIFI) {
        snprintf(json, sizeof(json), "{\"type\":\"bridge_status\",\"bridge\":\"no_wifi\"}");
    } else { // BRIDGE_CONNECTING
        snprintf(json, sizeof(json),
            "{\"type\":\"bridge_status\",\"bridge\":\"connecting\",\"ssid\":\"%s\"}", wifiSSID);
    }
    pBridgeChar->setValue(json);
    pBridgeChar->notify();
    lastBridgeStatusNotify = millis();
    const char* stateStr =
        (bridgeState == BRIDGE_ONLINE) ? "online" :
        (bridgeState == BRIDGE_WIFI_ONLY || bridgeState == BRIDGE_AUTH) ? "wifi_connected" :
        (bridgeState == BRIDGE_OFFLINE) ? "offline" :
        (bridgeState == BRIDGE_NO_WIFI) ? "no_wifi" : "connecting";
    Serial.printf("[BRIDGE] Notified bridge state: %s\n", stateStr);
}

// ============================================================================
// BLE chunked notification (send to phone)
// ============================================================================

void bleSendChunked(BLECharacteristic* pChar, const uint8_t* data, size_t dataLen) {
    if (!bleClientConnected || !pChar) return;

    // Generate random messageID (16 bytes)
    uint8_t msgID[16];
    esp_fill_random(msgID, 16);

    uint16_t totalChunks = (dataLen + BLE_MAX_CHUNK_DATA - 1) / BLE_MAX_CHUNK_DATA;
    if (totalChunks == 0) totalChunks = 1;

    Serial.printf("[BLE TX] Sending %d bytes in %d chunks\n", dataLen, totalChunks);

    for (uint16_t i = 0; i < totalChunks; i++) {
        size_t offset = (size_t)i * BLE_MAX_CHUNK_DATA;
        size_t chunkDataLen = dataLen - offset;
        if (chunkDataLen > BLE_MAX_CHUNK_DATA) chunkDataLen = BLE_MAX_CHUNK_DATA;

        uint8_t chunk[BLE_CHUNK_HEADER + BLE_MAX_CHUNK_DATA];
        // Header
        memcpy(chunk, msgID, 16);
        chunk[16] = (i >> 8) & 0xFF;
        chunk[17] = i & 0xFF;
        chunk[18] = (totalChunks >> 8) & 0xFF;
        chunk[19] = totalChunks & 0xFF;
        chunk[20] = (chunkDataLen >> 8) & 0xFF;
        chunk[21] = chunkDataLen & 0xFF;
        // Payload
        memcpy(chunk + BLE_CHUNK_HEADER, data + offset, chunkDataLen);

        pChar->setValue(chunk, BLE_CHUNK_HEADER + chunkDataLen);
        pChar->notify();
        delay(20); // Small gap between notifications
    }
}

// ============================================================================
// BLE callbacks
// ============================================================================

class ServerCallbacks : public BLEServerCallbacks {
    void onConnect(BLEServer* pServer, esp_ble_gatts_cb_param_t* param) override {
        bleClientConnected = true;
        lastBLEConnId = param->connect.conn_id;
        Serial.printf("[BLE] Client connected (conn_id=%d, %d total)\n",
                      lastBLEConnId, pServer->getConnectedCount());
        // Defer bridge status notification — give the phone time to discover
        // services and subscribe to notifications (~500ms typical on iOS)
        pendingNotifyStart = millis();
        pendingConnectNotify = true;
        BLEDevice::startAdvertising();
    }
    void onDisconnect(BLEServer* pServer, esp_ble_gatts_cb_param_t* param) override {
        uint16_t disconnId = param->disconnect.conn_id;
        uint16_t remaining = pServer->getConnectedCount();
        bleClientConnected = (remaining > 0);
        Serial.printf("[BLE] Client disconnected (conn_id=%d, %d remaining)\n",
                      disconnId, remaining);
        // Remove phone registration for this specific connection
        for (size_t i = 0; i < MAX_REGISTERED_PHONES; i++) {
            if (registeredPhones[i].active && registeredPhones[i].connId == disconnId) {
                Serial.printf("[BLE] Unregistered phone %s (conn_id=%d disconnected)\n",
                              registeredPhones[i].pigeonID, disconnId);
                registeredPhones[i].active = false;
            }
        }
        BLEDevice::startAdvertising();
    }
};

class MsgCharCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* pChar) override {
        // Runs on Bluedroid task — enqueue for processing in loop()
        std::string val = pChar->getValue();
        if (val.length() > 0 && bleEventQueue) {
            BLEEvent evt;
            evt.type = BLE_EVENT_MSG_WRITE;
            evt.len = val.length();
            if (evt.len > BLE_MAX_WRITE_SIZE) evt.len = BLE_MAX_WRITE_SIZE;
            memcpy(evt.data, val.data(), evt.len);
            if (xQueueSend(bleEventQueue, &evt, 0) != pdTRUE) {
                Serial.println("[BLE] Event queue full, dropping write");
            }
        }
    }
};

class AckCharCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* pChar) override {
        // Runs on Bluedroid task — enqueue for processing in loop()
        std::string val = pChar->getValue();
        if (val.length() > 0 && bleEventQueue) {
            BLEEvent evt;
            evt.type = BLE_EVENT_ACK_WRITE;
            evt.len = val.length();
            if (evt.len > BLE_MAX_WRITE_SIZE) evt.len = BLE_MAX_WRITE_SIZE;
            memcpy(evt.data, val.data(), evt.len);
            if (xQueueSend(bleEventQueue, &evt, 0) != pdTRUE) {
                Serial.println("[BLE] Event queue full, dropping ACK");
            }
        }
    }
};

class BridgeCharCallbacks : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic* pChar) override {
        std::string val = pChar->getValue();
        if (val.length() > 0 && bleEventQueue) {
            BLEEvent evt;
            evt.type = BLE_EVENT_BRIDGE_WRITE;
            evt.len = val.length();
            if (evt.len > BLE_MAX_WRITE_SIZE) evt.len = BLE_MAX_WRITE_SIZE;
            memcpy(evt.data, val.data(), evt.len);
            if (xQueueSend(bleEventQueue, &evt, 0) != pdTRUE) {
                Serial.println("[BLE] Event queue full, dropping bridge write");
            }
        }
    }
};

// ============================================================================
// BLE setup
// ============================================================================

void setupBLE() {
    BLEDevice::init("Pigeon");

    pServer = BLEDevice::createServer();
    pServer->setCallbacks(new ServerCallbacks());

    BLEService* pService = pServer->createService(BLE_SERVICE_UUID);

    // Message characteristic: Write + WriteWithoutResponse + Notify
    pMsgChar = pService->createCharacteristic(
        BLE_MSG_CHAR_UUID,
        BLECharacteristic::PROPERTY_WRITE |
        BLECharacteristic::PROPERTY_WRITE_NR |
        BLECharacteristic::PROPERTY_NOTIFY
    );
    pMsgChar->addDescriptor(new BLE2902());
    pMsgChar->setCallbacks(new MsgCharCallbacks());

    // Identity characteristic: Read
    pIdentityChar = pService->createCharacteristic(
        BLE_IDENTITY_CHAR_UUID,
        BLECharacteristic::PROPERTY_READ
    );
    // Set identity JSON — updated dynamically as bridge state changes
    updateIdentityCharacteristic();

    // ACK characteristic: Write + WriteWithoutResponse + Notify
    pAckChar = pService->createCharacteristic(
        BLE_ACK_CHAR_UUID,
        BLECharacteristic::PROPERTY_WRITE |
        BLECharacteristic::PROPERTY_WRITE_NR |
        BLECharacteristic::PROPERTY_NOTIFY
    );
    pAckChar->addDescriptor(new BLE2902());
    pAckChar->setCallbacks(new AckCharCallbacks());

    // Bridge Control characteristic: Write + WriteWithoutResponse + Notify
    pBridgeChar = pService->createCharacteristic(
        BLE_BRIDGE_CHAR_UUID,
        BLECharacteristic::PROPERTY_WRITE |
        BLECharacteristic::PROPERTY_WRITE_NR |
        BLECharacteristic::PROPERTY_NOTIFY
    );
    pBridgeChar->addDescriptor(new BLE2902());
    pBridgeChar->setCallbacks(new BridgeCharCallbacks());

    pService->start();

    // Set BLE TX power to maximum for better discoverability
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
    esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);

    BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(BLE_SERVICE_UUID);
    pAdvertising->setScanResponse(true);
    // Apple recommends 100-152.5ms advertising interval for accessories.
    // Units are 0.625ms: 100ms = 0xA0, 152.5ms = 0xF4
    pAdvertising->setMinInterval(0xA0);
    pAdvertising->setMaxInterval(0xF4);
    pAdvertising->setMinPreferred(0x06);  // 7.5ms min connection interval
    pAdvertising->setMaxPreferred(0x0C);  // 15ms max connection interval
    BLEDevice::startAdvertising();

    Serial.printf("[BLE] GATT server started, advertising as 'Pigeon' (ID: %s)\n", nodePigeonID);
}

// ============================================================================
// LoRa setup
// ============================================================================

void applyRadioConfig() {
    if (loraMode == LORA_MESHTASTIC) {
        radio.setBandwidth(MSHT_BW);
        radio.setSpreadingFactor(MSHT_SF);
        radio.setCodingRate(MSHT_CR);
        radio.setSyncWord(MSHT_SYNC_WORD);
        radio.setPreambleLength(MSHT_PREAMBLE);
        Serial.println("[LORA] Mode: Meshtastic LongFast (SF11/BW250/0x2B)");
    } else {
        radio.setBandwidth(LORA_BW);
        radio.setSpreadingFactor(LORA_SF);
        radio.setCodingRate(LORA_CR);
        radio.setSyncWord(LORA_SYNC_WORD);
        radio.setPreambleLength(LORA_PREAMBLE);
        Serial.println("[LORA] Mode: Pigeon Native (SF9/BW125/0x12)");
    }
    radio.setFrequency(LORA_FREQ);
    radio.setOutputPower(LORA_POWER);
    radio.setCRC(2);
    radio.setRxBoostedGainMode(true);
}

void setupLoRa() {
    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);

    Serial.print("[SX1262] Initializing...");
    int state = radio.begin();
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf(" FAILED, code: %d\n", state);
        while (true) delay(1000);
    }
    radio.setDio2AsRfSwitch(true);
    radio.setTCXO(LORA_TCXO_V);
    applyRadioConfig();
    Serial.println(" OK");

    radio.setPacketReceivedAction(onReceive);
    state = radio.startReceive();
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[LORA] startReceive FAILED: %d\n", state);
        while (true) delay(1000);
    }
}

// ============================================================================
// OLED display
// ============================================================================

// Count active mesh nodes (from node table, 90s expiry matches PEER_EXPIRY_MS)
uint8_t countMeshNodes() {
    uint32_t now = millis();
    uint8_t count = 0;
    for (size_t i = 0; i < NODE_TABLE_SIZE; i++) {
        if (nodeTable[i].active) {
            if (now - nodeTable[i].lastSeen > PEER_EXPIRY_MS) {
                nodeTable[i].active = false;
            } else {
                count++;
            }
        }
    }
    return count;
}

void updateDisplay() {
    char line[17];

    u8x8.setCursor(0, 0);
    u8x8.print("PIGEON");

    u8x8.setCursor(0, 1);
    u8x8.print(nodePigeonID);

    // Connected phones and mesh nodes
    u8x8.setCursor(0, 3);
    snprintf(line, sizeof(line), "Ph:%-2u Nodes:%-4u",
             (unsigned)(pServer ? pServer->getConnectedCount() : 0),
             (unsigned)countMeshNodes());
    u8x8.print(line);

    // RSSI
    u8x8.setCursor(0, 4);
    if (hasRSSI) {
        snprintf(line, sizeof(line), "RSSI: %d dBm    ", (int)lastRSSI);
    } else {
        snprintf(line, sizeof(line), "RSSI: --        ");
    }
    u8x8.print(line);

    // Line 5: Mode/Bridge status
    u8x8.setCursor(0, 5);
    if (loraMode == LORA_MESHTASTIC) {
        snprintf(line, sizeof(line), "Mode:Meshtastic ");
    } else {
        const char* bStatus;
        switch (bridgeState) {
            case BRIDGE_NO_WIFI:   bStatus = "No WiFi";    break;
            case BRIDGE_CONNECTING: bStatus = "Connecting"; break;
            case BRIDGE_WIFI_ONLY: bStatus = "WiFi Only";  break;
            case BRIDGE_AUTH:      bStatus = "Auth...";     break;
            case BRIDGE_ONLINE:    bStatus = "Online";      break;
            case BRIDGE_OFFLINE:   bStatus = "Offline";     break;
            default:               bStatus = "?";           break;
        }
        snprintf(line, sizeof(line), "Bridge:%-9s", bStatus);
    }
    u8x8.print(line);

    // LoRa packet stats
    u8x8.setCursor(0, 6);
    snprintf(line, sizeof(line), "Rx:%-4lu Fw:%-4lu",
             (unsigned long)statLoRaRx, (unsigned long)statRelay);
    u8x8.print(line);

    // Uptime
    uint32_t sec = millis() / 1000;
    u8x8.setCursor(0, 7);
    snprintf(line, sizeof(line), "Up %luh %02lum %02lus",
             (unsigned long)(sec / 3600),
             (unsigned long)((sec % 3600) / 60),
             (unsigned long)(sec % 60));
    u8x8.print(line);
}

// ============================================================================
// Main
// ============================================================================

void setup() {
    Serial.begin(115200);
    delay(2000);

    // Initialize OLED display
    u8x8.begin();
    u8x8.setFlipMode(1); // Expansion board mounts display upside-down
    u8x8.setFont(u8x8_font_chroma48medium8_r);
    u8x8.clear();
    u8x8.setCursor(0, 0);
    u8x8.print("PIGEON");
    u8x8.setCursor(0, 2);
    u8x8.print("Booting...");

    esp_efuse_mac_get_default(nodeAddr);
    loadOrGenerateKey();
    // Derive pigeonID from publicKey (first 4 bytes of SHA256, matching iOS app)
    computePigeonID(nodePublicKey, 32, nodePigeonID);

    // Randomize counters to avoid collisions after reboot
    nextMsgID = (uint16_t)(esp_random() & 0xFFFF);
    nextFragGroupID = (uint16_t)(esp_random() & 0xFFFF);

    Serial.println("=================================");
    Serial.println("  Pigeon Mesh Node");
    Serial.printf("  Pigeon ID: %s\n", nodePigeonID);
    Serial.println("=================================");
    Serial.println();

    memset(dedupTable, 0, sizeof(dedupTable));
    memset(loraReasmTable, 0, sizeof(loraReasmTable));
    memset(bleReasmTable, 0, sizeof(bleReasmTable));
    memset(bleTxQueue, 0, sizeof(bleTxQueue));
    memset(loraRxQueue, 0, sizeof(loraRxQueue));
    memset(registeredPhones, 0, sizeof(registeredPhones));
    memset(peerTable, 0, sizeof(peerTable));
    memset(nodeTable, 0, sizeof(nodeTable));
    memset(relayQueue, 0, sizeof(relayQueue));
    memset(msgDedupTable, 0, sizeof(msgDedupTable));
    memset(mshtDedupTable, 0, sizeof(mshtDedupTable));
    memset(mshtRelayQueue, 0, sizeof(mshtRelayQueue));
    memset(neighborTable, 0, sizeof(neighborTable));
    mshtPacketCounter = esp_random() & 0x3FF;

    // Create BLE event queue before starting BLE (callbacks use it)
    bleEventQueue = xQueueCreate(BLE_EVENT_QUEUE_LEN, sizeof(BLEEvent));

    setupLoRa();
    setupBLE();

    // WiFi/bridge only available in Native mode
    if (loraMode == LORA_NATIVE) {
        loadWiFiCredentials();
        setupWiFi();
    } else {
        WiFi.mode(WIFI_OFF);
        bridgeState = BRIDGE_NO_WIFI;
    }

    // Offset beacon timing so nodes don't all beacon at the same instant
    lastBeaconTime = millis() - BEACON_INTERVAL_MS + (nodeAddr[5] * 37 % BEACON_INTERVAL_MS);

    Serial.println();
    Serial.printf("[PIGEON] LoRa mode: %s\n",
                  loraMode == LORA_MESHTASTIC ? "Meshtastic Compatible" : "Pigeon Native");
    if (loraMode == LORA_MESHTASTIC)
        Serial.printf("[PIGEON] Meshtastic NodeNum: %08X\n", mshtNodeNum);
    Serial.println("[PIGEON] Node ready. BLE + LoRa mesh active.");
    Serial.println();

    // Show initial status on display
    u8x8.clear();
    updateDisplay();
}

void loop() {
    // 1. Handle LoRa received packets
    if (rxFlag) {
        rxFlag = false;
        if (loraMode == LORA_MESHTASTIC) handleMshtReceive();
        else handleLoRaReceive();
    }

    // 2. Process BLE event queue (thread-safe handoff from BLE callbacks)
    BLEEvent evt;
    while (xQueueReceive(bleEventQueue, &evt, 0) == pdTRUE) {
        if (evt.type == BLE_EVENT_MSG_WRITE) {
            handleBLEChunkWrite(evt.data, evt.len);
        } else if (evt.type == BLE_EVENT_ACK_WRITE) {
            Serial.printf("[BLE ACK] Received %d bytes, broadcasting over LoRa\n", evt.len);
            if (loraMode == LORA_MESHTASTIC) {
                if (evt.len <= MSHT_MAX_PIGEON_DATA)
                    mshtTransmit(MSHT_BROADCAST, evt.data, evt.len);
                else
                    Serial.printf("[MSHT] ACK too large for single packet: %d > %d\n", evt.len, MSHT_MAX_PIGEON_DATA);
            } else {
                meshSendFragmented(BROADCAST_ADDR, evt.data, evt.len);
            }
        } else if (evt.type == BLE_EVENT_BRIDGE_WRITE) {
            handleBridgeWrite(evt.data, evt.len);
        }
    }

    // 3. Process BLE->LoRa queue (reassembled messages ready to send)
    for (int i = 0; i < (int)BLE_TX_QUEUE_SIZE; i++) {
        if (bleTxQueue[i].pending) {
            Serial.printf("[MESH] BLE->LoRa: %d bytes\n", bleTxQueue[i].len);
            if (loraMode == LORA_MESHTASTIC) {
                if (bleTxQueue[i].len <= MSHT_MAX_PIGEON_DATA) {
                    mshtTransmit(MSHT_BROADCAST, bleTxQueue[i].data, bleTxQueue[i].len);
                } else {
                    Serial.printf("[MSHT] BLE payload too large for single packet: %d > %d\n",
                                  bleTxQueue[i].len, MSHT_MAX_PIGEON_DATA);
                }
            } else {
                meshSendFragmented(BROADCAST_ADDR, bleTxQueue[i].data, bleTxQueue[i].len);
                bridgeToRelay(bleTxQueue[i].data, bleTxQueue[i].len);
            }
            bleTxQueue[i].pending = false;
            statBleIn++;
        }
    }

    // 4. Process LoRa->BLE queue (received from mesh, push to phone)
    for (int i = 0; i < (int)LORA_RX_QUEUE_SIZE; i++) {
        if (loraRxQueue[i].pending) {
            Serial.printf("[MESH] LoRa->BLE: %d bytes\n", loraRxQueue[i].len);
            // Bridge to relay server using full data (Native mode only)
            if (loraMode == LORA_NATIVE)
                bridgeToRelay(loraRxQueue[i].data, loraRxQueue[i].len);
            // Strip routing header before BLE delivery — phone expects raw envelope JSON.
            // All messages through the mesh have a routing header prepended by the sender.
            // Detect by checking if data after the header starts with '{' (valid JSON envelope).
            const uint8_t* bleData = loraRxQueue[i].data;
            size_t bleLen = loraRxQueue[i].len;
            if (bleLen > ROUTING_HEADER_SIZE &&
                bleData[ROUTING_HEADER_SIZE] == '{') {
                bleData += ROUTING_HEADER_SIZE;
                bleLen -= ROUTING_HEADER_SIZE;
            }
            bleSendChunked(pMsgChar, bleData, bleLen);
            loraRxQueue[i].pending = false;
            statBleOut++;
        }
    }

    // 5. LoRa heartbeat beacon with presence info (gossip: local + remote peers)
    {
        uint32_t now = millis();
        if (now - lastBeaconTime >= BEACON_INTERVAL_MS) {
            lastBeaconTime = now;

            if (loraMode == LORA_MESHTASTIC) {
                sendMshtBeacon();
            } else {
                MeshPacket pkt;
                memcpy(pkt.sender, nodeAddr, ADDR_LEN);
                memcpy(pkt.dest, BROADCAST_ADDR, ADDR_LEN);
                pkt.msgID = nextMsgID++;
                pkt.ttl = 1;

                pkt.payloadLen = buildBeaconPayload(pkt.payload, sizeof(pkt.payload));
                if (pkt.payloadLen > 0) {
                    addDedup(pkt.sender, pkt.msgID);
                    meshTransmitRaw(pkt);
                    uint8_t numKeys = pkt.payload[1];
                    Serial.printf("[BEACON] Sent v2 presence (keys=%d)\n", numKeys);
                }
            }
        }
    }

    // 6. Drain relay queue with jitter (deferred relay to avoid fragment loss during RX)
    // All radio operations happen on this task — no mutex needed (single-threaded loop)
    if (loraMode == LORA_MESHTASTIC) {
        // Meshtastic relay: RSSI-proportional delay with suppression
        uint32_t now = millis();
        for (int i = 0; i < (int)RELAY_QUEUE_SIZE; i++) {
            if (mshtRelayQueue[i].pending &&
                (now - mshtRelayQueue[i].queuedAt) >= mshtRelayQueue[i].delayMs) {
                int state = radio.transmit(mshtRelayQueue[i].data, mshtRelayQueue[i].len);
                radio.startReceive();
                rxFlag = false;
                mshtRelayQueue[i].pending = false;
                if (state == RADIOLIB_ERR_NONE) {
                    statRelay++;
                } else {
                    Serial.printf("[MSHT RELAY] TX failed: %d\n", state);
                }
                break; // one per cycle
            }
        }
    } else {
        // Native relay: random jitter
        uint32_t now = millis();
        if (now - lastRelayTime >= relayJitterMs) {
            for (int i = 0; i < (int)RELAY_QUEUE_SIZE; i++) {
                if (relayQueue[i].pending) {
                    int state = radio.transmit(relayQueue[i].data, relayQueue[i].len);
                    radio.startReceive();
                    rxFlag = false;
                    relayQueue[i].pending = false;
                    lastRelayTime = now;
                    relayJitterMs = 50 + (esp_random() % 100);
                    if (state == RADIOLIB_ERR_NONE) {
                        statRelay++;
                    } else {
                        Serial.printf("[RELAY] TX failed: %d\n", state);
                    }
                    break;
                }
            }
        }
    }

    // 7. Expire stale peers, neighbors, and send BLE peer presence notifications
    {
        uint32_t now = millis();
        static uint32_t lastPeerExpiry = 0;
        if (now - lastPeerExpiry >= 1000) {
            lastPeerExpiry = now;
            expirePeers();
            // Expire RSSI neighbors (5 min)
            for (size_t i = 0; i < NEIGHBOR_TABLE_SIZE; i++) {
                if (neighborTable[i].active && (now - neighborTable[i].lastSeen) > 300000)
                    neighborTable[i].active = false;
            }
        }

        bool shouldNotify = peerTableChanged ||
                            (now - lastPeerNotify >= PEER_NOTIFY_MS);

        if (shouldNotify && bleClientConnected && pBridgeChar) {
            lastPeerNotify = now;
            peerTableChanged = false;

            // Build JSON: {"type":"peers","peers":[{"pigeonID":"...","publicKey":"..."},...]}}
            // Use heap to avoid large stack allocation (base64 keys are ~44 chars each)
            size_t jsonBufSize = 2048;
            char* json = (char*)malloc(jsonBufSize);
            if (!json) {
                Serial.println("[PEERS] malloc failed for notification");
                goto skip_notify; // Don't return — remaining loop steps must still run
            }
            int pos = snprintf(json, jsonBufSize, "{\"type\":\"peers\",\"peers\":[");
            bool first = true;
            for (int i = 0; i < (int)PEER_TABLE_SIZE; i++) {
                if (peerTable[i].active && peerTable[i].hasPublicKey) {
                    // Base64 encode the public key
                    char b64[48]; // 32 bytes -> 44 base64 chars + null
                    size_t b64Len = 0;
                    mbedtls_base64_encode((unsigned char*)b64, sizeof(b64), &b64Len,
                                          peerTable[i].publicKey, PUBKEY_LEN);
                    b64[b64Len] = '\0';

                    // Bounds check: entry is ~70 chars
                    if (pos + 80 >= (int)jsonBufSize) break;
                    if (!first) pos += snprintf(json + pos, jsonBufSize - pos, ",");
                    pos += snprintf(json + pos, jsonBufSize - pos,
                                    "{\"pigeonID\":\"%s\",\"publicKey\":\"%s\"}",
                                    peerTable[i].pigeonID, b64);
                    first = false;
                }
            }
            snprintf(json + pos, jsonBufSize - pos, "]}");

            pBridgeChar->setValue(json);
            pBridgeChar->notify();
            free(json);
        }
        skip_notify:;
    }

    // 8. Radio watchdog — ensure receive mode is active
    {
        uint32_t now = millis();
        if (now - lastRadioWatchdog >= RADIO_WATCHDOG_MS) {
            lastRadioWatchdog = now;
            // Force restart receive mode as a safety net
            radio.startReceive();
        }
    }

    // 9. WiFi connection management (Native mode only)
    if (loraMode == LORA_NATIVE) wifiLoop();

    // 10. WebSocket relay connection (Native mode only)
    if (loraMode == LORA_NATIVE) wsLoop();

    // 11. Deferred bridge status on connect + periodic re-notification
    if (bleClientConnected) {
        uint32_t now = millis();
        // Deferred notification after BLE connect or WiFi provisioning
        if (pendingConnectNotify &&
            now - pendingNotifyStart >= DEFERRED_NOTIFY_DELAY_MS) {
            pendingConnectNotify = false;
            Serial.println("[BRIDGE] Deferred notify");
            notifyBridgeStatus();
        }
        // Periodic re-send for settled states (not transient CONNECTING/AUTH)
        if ((bridgeState == BRIDGE_ONLINE || bridgeState == BRIDGE_WIFI_ONLY ||
             bridgeState == BRIDGE_OFFLINE) &&
            now - lastBridgeStatusNotify >= BRIDGE_STATUS_INTERVAL_MS) {
            notifyBridgeStatus();
        }
    } else {
        pendingConnectNotify = false;
    }

    // 12. BLE advertising watchdog — restart if no client and interval elapsed
    if (!bleClientConnected) {
        uint32_t now = millis();
        if (now - lastBLEAdvRestart >= BLE_ADV_RESTART_MS) {
            lastBLEAdvRestart = now;
            BLEDevice::startAdvertising();
        }
    }

    // 13. Update OLED display every second
    {
        uint32_t now = millis();
        if (now - lastDisplayUpdate >= DISPLAY_UPDATE_MS) {
            lastDisplayUpdate = now;
            updateDisplay();
        }
    }

    delay(1); // Yield to FreeRTOS
}
