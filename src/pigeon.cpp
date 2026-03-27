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

enum BLEEventType : uint8_t {
    BLE_EVENT_MSG_WRITE,
    BLE_EVENT_ACK_WRITE,
};

struct BLEEvent {
    BLEEventType type;
    size_t len;
    uint8_t data[BLE_MAX_WRITE_SIZE];
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

// ============================================================================
// Globals
// ============================================================================

SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RESET, LORA_BUSY);

uint8_t nodeAddr[ADDR_LEN];
char nodePigeonID[9]; // 8 hex chars + null
uint8_t nodePublicKey[32]; // Curve25519 public key (persisted in NVS)
char nodePublicKeyB64[45]; // base64-encoded public key
uint16_t nextMsgID = 0;
uint16_t nextFragGroupID = 0;

DedupEntry dedupTable[DEDUP_TABLE_SIZE];
LoRaReasmSlot loraReasmTable[LORA_REASM_SLOTS];
BLEReasmSlot bleReasmTable[BLE_REASM_SLOTS];

volatile bool rxFlag = false;

// BLE state
BLEServer* pServer = nullptr;
BLECharacteristic* pMsgChar = nullptr;
BLECharacteristic* pIdentityChar = nullptr;
BLECharacteristic* pAckChar = nullptr;
BLECharacteristic* pBridgeChar = nullptr;
volatile bool bleClientConnected = false;

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

// ============================================================================
// Utility functions
// ============================================================================

void IRAM_ATTR onReceive() {
    rxFlag = true;
}

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

// Load or generate a 32-byte key, persist in NVS so it's stable across reboots.
// This is a random 32-byte identity token, not a real Curve25519 key.
// The iOS app uses it to derive pigeonID and identify this node.
void loadOrGenerateKey() {
    Preferences prefs;
    prefs.begin("pigeon", false);
    size_t keyLen = prefs.getBytes("pubkey", nodePublicKey, 32);
    if (keyLen != 32) {
        // Generate new random key
        esp_fill_random(nodePublicKey, 32);
        prefs.putBytes("pubkey", nodePublicKey, 32);
        Serial.println("[KEY] Generated new node key");
    } else {
        Serial.println("[KEY] Loaded existing node key from NVS");
    }
    prefs.end();

    // Base64-encode the public key
    size_t b64Len = 0;
    mbedtls_base64_encode((unsigned char*)nodePublicKeyB64, sizeof(nodePublicKeyB64),
                          &b64Len, nodePublicKey, 32);
    nodePublicKeyB64[b64Len] = '\0';
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
// Mesh packet serialization
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
    rxFlag = false;
    radio.startReceive();
    return state == RADIOLIB_ERR_NONE;
}

// Send fragmented message over LoRa mesh
void meshSendFragmented(const uint8_t* dest, const uint8_t* data, size_t dataLen) {
    uint16_t fragGroupID = nextFragGroupID++;
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

                // Reassemble fragments destined for us
                if (forUs && pkt.payloadLen >= FRAG_HEADER_SIZE) {
                    uint16_t fragGroupID = ((uint16_t)pkt.payload[0] << 8) | pkt.payload[1];
                    uint8_t fragIndex = pkt.payload[2];
                    uint8_t fragTotal = pkt.payload[3];
                    const uint8_t* fragData = pkt.payload + FRAG_HEADER_SIZE;
                    size_t fragDataLen = pkt.payloadLen - FRAG_HEADER_SIZE;

                    Serial.printf("[LORA RX] from=%s frag=%d/%d fragGroup=%04X\n",
                                  senderStr, fragIndex + 1, fragTotal, fragGroupID);
                    loraReassemble(pkt.sender, fragGroupID, fragIndex, fragTotal, fragData, fragDataLen);
                }

                // Relay if not from us and TTL allows
                if (!addrMatch(pkt.sender, nodeAddr) && pkt.ttl > 1) {
                    pkt.ttl--;
                    meshTransmitRaw(pkt);
                    statRelay++;
                }
            }
        }
    } else if (state != -7) { // Don't spam CRC errors
        Serial.printf("[LORA] Read error: %d\n", state);
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
                Serial.printf("[BLE RX] Complete message reassembled: %d bytes -> LoRa TX queue\n", totalLen);
                break;
            }
        }
        slot.active = false;
    }
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
    void onConnect(BLEServer* pServer) override {
        bleClientConnected = true;
        Serial.printf("[BLE] Client connected (%d total)\n", pServer->getConnectedCount());
        // Keep advertising so more phones can connect
        BLEDevice::startAdvertising();
    }
    void onDisconnect(BLEServer* pServer) override {
        bleClientConnected = (pServer->getConnectedCount() > 0);
        Serial.printf("[BLE] Client disconnected (%d remaining)\n", pServer->getConnectedCount());
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
        // Bridge control — handle chunked data same as messages
        std::string val = pChar->getValue();
        Serial.printf("[BLE BRIDGE] Received %d bytes\n", val.length());
        // For now, just log. Bridge control can be extended later.
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
    // Set identity JSON value — publicKey is REQUIRED by pigeon-ios
    // isMeshNode distinguishes this from phones and internet bridges
    char identityJson[512];
    snprintf(identityJson, sizeof(identityJson),
        "{\"publicKey\":\"%s\","
        "\"pigeonID\":\"%s\","
        "\"displayName\":\"Pigeon Mesh Node\","
        "\"bridgeProtocolVersion\":1,"
        "\"bridgeEnabled\":false,"
        "\"isMeshNode\":true,"
        "\"relayReachable\":false,"
        "\"bridgeCapacityRemaining\":0}",
        nodePublicKeyB64,
        nodePigeonID
    );
    pIdentityChar->setValue(identityJson);

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
    radio.setFrequency(LORA_FREQ);
    radio.setBandwidth(LORA_BW);
    radio.setSpreadingFactor(LORA_SF);
    radio.setCodingRate(LORA_CR);
    radio.setSyncWord(LORA_SYNC_WORD);
    radio.setOutputPower(LORA_POWER);
    radio.setPreambleLength(LORA_PREAMBLE);
    radio.setCRC(2);
    radio.setRxBoostedGainMode(true);
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

// Count unique mesh nodes heard recently (from dedup table)
uint8_t countMeshNodes() {
    uint32_t now = millis();
    uint8_t addrs[16][ADDR_LEN];
    uint8_t count = 0;

    for (size_t i = 0; i < DEDUP_TABLE_SIZE && count < 16; i++) {
        if (!dedupTable[i].active) continue;
        if (now - dedupTable[i].timestamp > DEDUP_EXPIRY_MS) continue;
        if (addrMatch(dedupTable[i].sender, nodeAddr)) continue;

        bool seen = false;
        for (uint8_t j = 0; j < count; j++) {
            if (addrMatch(addrs[j], dedupTable[i].sender)) { seen = true; break; }
        }
        if (!seen) {
            memcpy(addrs[count], dedupTable[i].sender, ADDR_LEN);
            count++;
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

    // Connected phones
    u8x8.setCursor(0, 3);
    snprintf(line, sizeof(line), "Phones: %-8u",
             (unsigned)(pServer ? pServer->getConnectedCount() : 0));
    u8x8.print(line);

    // Mesh nodes heard in last 30s
    u8x8.setCursor(0, 4);
    snprintf(line, sizeof(line), "Nodes:  %-8u", (unsigned)countMeshNodes());
    u8x8.print(line);

    // Last received signal strength
    u8x8.setCursor(0, 5);
    if (hasRSSI) {
        char rssi[11];
        snprintf(rssi, sizeof(rssi), "%d dBm", (int)lastRSSI);
        snprintf(line, sizeof(line), "RSSI: %-10s", rssi);
    } else {
        snprintf(line, sizeof(line), "RSSI: %-10s", "--");
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

    char nodeStr[18];
    macToStr(nodeAddr, nodeStr);

    Serial.println("=================================");
    Serial.println("  Pigeon Mesh Node");
    Serial.printf("  MAC: %s\n", nodeStr);
    Serial.printf("  Pigeon ID: %s\n", nodePigeonID);
    Serial.printf("  Public Key: %s\n", nodePublicKeyB64);
    Serial.println("=================================");
    Serial.println();

    memset(dedupTable, 0, sizeof(dedupTable));
    memset(loraReasmTable, 0, sizeof(loraReasmTable));
    memset(bleReasmTable, 0, sizeof(bleReasmTable));
    memset(bleTxQueue, 0, sizeof(bleTxQueue));
    memset(loraRxQueue, 0, sizeof(loraRxQueue));

    // Create BLE event queue before starting BLE (callbacks use it)
    bleEventQueue = xQueueCreate(BLE_EVENT_QUEUE_LEN, sizeof(BLEEvent));

    setupLoRa();
    setupBLE();

    // Offset beacon timing so nodes don't all beacon at the same instant
    lastBeaconTime = millis() - BEACON_INTERVAL_MS + (nodeAddr[5] * 37 % BEACON_INTERVAL_MS);

    Serial.println();
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
        handleLoRaReceive();
    }

    // 2. Process BLE event queue (thread-safe handoff from BLE callbacks)
    BLEEvent evt;
    while (xQueueReceive(bleEventQueue, &evt, 0) == pdTRUE) {
        if (evt.type == BLE_EVENT_MSG_WRITE) {
            handleBLEChunkWrite(evt.data, evt.len);
        } else if (evt.type == BLE_EVENT_ACK_WRITE) {
            Serial.printf("[BLE ACK] Received %d bytes, broadcasting over LoRa\n", evt.len);
            meshSendFragmented(BROADCAST_ADDR, evt.data, evt.len);
        }
    }

    // 3. Process BLE->LoRa queue (reassembled messages ready to send)
    for (int i = 0; i < (int)BLE_TX_QUEUE_SIZE; i++) {
        if (bleTxQueue[i].pending) {
            Serial.printf("[MESH] BLE->LoRa: %d bytes\n", bleTxQueue[i].len);
            meshSendFragmented(BROADCAST_ADDR, bleTxQueue[i].data, bleTxQueue[i].len);
            bleTxQueue[i].pending = false;
            statBleIn++;
        }
    }

    // 4. Process LoRa->BLE queue (received from mesh, push to phone)
    for (int i = 0; i < (int)LORA_RX_QUEUE_SIZE; i++) {
        if (loraRxQueue[i].pending) {
            Serial.printf("[MESH] LoRa->BLE: %d bytes\n", loraRxQueue[i].len);
            bleSendChunked(pMsgChar, loraRxQueue[i].data, loraRxQueue[i].len);
            loraRxQueue[i].pending = false;
            statBleOut++;
        }
    }

    // 5. LoRa heartbeat beacon — lets other nodes know we exist
    {
        uint32_t now = millis();
        if (now - lastBeaconTime >= BEACON_INTERVAL_MS) {
            lastBeaconTime = now;
            MeshPacket pkt;
            memcpy(pkt.sender, nodeAddr, ADDR_LEN);
            memcpy(pkt.dest, BROADCAST_ADDR, ADDR_LEN);
            pkt.msgID = nextMsgID++;
            pkt.ttl = 1; // Beacons don't need to propagate far
            pkt.payloadLen = 0;
            addDedup(pkt.sender, pkt.msgID);
            meshTransmitRaw(pkt);
        }
    }

    // 6. BLE advertising watchdog — restart if no client and interval elapsed
    if (!bleClientConnected) {
        uint32_t now = millis();
        if (now - lastBLEAdvRestart >= BLE_ADV_RESTART_MS) {
            lastBLEAdvRestart = now;
            BLEDevice::startAdvertising();
        }
    }

    // 6. Update OLED display every second
    {
        uint32_t now = millis();
        if (now - lastDisplayUpdate >= DISPLAY_UPDATE_MS) {
            lastDisplayUpdate = now;
            updateDisplay();
        }
    }

    delay(1); // Yield to FreeRTOS
}
