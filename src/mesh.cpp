// Pigeon - Mesh relay test firmware
// Unified firmware — all nodes are equal, can send, receive, and relay.

#include <Arduino.h>
#include "pigeon_config.h"
#include <SPI.h>
#include <RadioLib.h>

// --- Pin mapping: XIAO ESP32S3 + Wio-SX1262 (Kit/B2B version) ---
#define LORA_CS    41
#define LORA_DIO1  39
#define LORA_RESET 42
#define LORA_BUSY  40
#define LORA_SCK   7
#define LORA_MOSI  9
#define LORA_MISO  8

// --- LoRa parameters ---
static const float LORA_FREQ      = PIGEON_LORA_FREQUENCY_MHZ;
static const float LORA_BW        = 125.0;   // kHz bandwidth
static const uint8_t LORA_SF      = 9;       // Spreading factor
static const uint8_t LORA_CR      = 7;       // Coding rate 4/7
static const uint8_t LORA_SYNC    = 0x12;    // Private network sync word
static const int8_t LORA_POWER    = PIGEON_LORA_POWER_DBM;
static const uint16_t LORA_PREAMBLE = 8;     // Preamble length
static const float LORA_TCXO_V    = 1.8;     // TCXO voltage via DIO3

// --- Mesh parameters ---
static const uint8_t DEFAULT_TTL       = 5;
static const uint8_t BROADCAST_ADDR[]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const size_t ADDR_LEN           = 6;   // MAC address length
static const size_t DEDUP_TABLE_SIZE   = 64;  // Max tracked message IDs
static const uint32_t DEDUP_EXPIRY_MS  = 30000; // Expire dedup entries after 30s
static const uint32_t BEACON_INTERVAL_MS = 10000; // Send beacon every 10s

// --- Mesh packet structure ---
// [sender: 6B][dest: 6B][msgID: 2B][ttl: 1B][payloadLen: 1B][payload: 0-234B]
// Total header: 16 bytes. Max payload: 234 bytes (250 - 16).
static const size_t MESH_HEADER_SIZE   = 16;
static const size_t MAX_PAYLOAD        = 234;
static const size_t MAX_PACKET_SIZE    = 250;

struct MeshPacket {
    uint8_t sender[ADDR_LEN];
    uint8_t dest[ADDR_LEN];
    uint16_t msgID;
    uint8_t ttl;
    uint8_t payloadLen;
    uint8_t payload[MAX_PAYLOAD];
};

// --- Deduplication table ---
struct DedupEntry {
    uint8_t sender[ADDR_LEN];
    uint16_t msgID;
    uint32_t timestamp;
    bool active;
};

SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RESET, LORA_BUSY);

uint8_t nodeAddr[ADDR_LEN];
uint16_t nextMsgID = 0;
DedupEntry dedupTable[DEDUP_TABLE_SIZE];
volatile bool rxFlag = false;
bool txPending = false;
uint32_t lastBeaconTime = 0;

void IRAM_ATTR onReceive() {
    rxFlag = true;
}

// Check if two addresses match
bool addrMatch(const uint8_t* a, const uint8_t* b) {
    return memcmp(a, b, ADDR_LEN) == 0;
}

// Check if address is broadcast
bool isBroadcast(const uint8_t* addr) {
    return addrMatch(addr, BROADCAST_ADDR);
}

// Check dedup table — returns true if this is a duplicate
bool isDuplicate(const uint8_t* sender, uint16_t msgID) {
    uint32_t now = millis();
    for (size_t i = 0; i < DEDUP_TABLE_SIZE; i++) {
        if (dedupTable[i].active) {
            // Expire old entries
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

// Add entry to dedup table
void addDedup(const uint8_t* sender, uint16_t msgID) {
    // Find empty slot or oldest entry
    size_t slot = 0;
    uint32_t oldestTime = UINT32_MAX;
    for (size_t i = 0; i < DEDUP_TABLE_SIZE; i++) {
        if (!dedupTable[i].active) {
            slot = i;
            break;
        }
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

// Serialize packet to buffer
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

// Deserialize packet from buffer
bool deserializePacket(const uint8_t* buf, size_t len, MeshPacket& pkt) {
    if (len < MESH_HEADER_SIZE) return false;
    memcpy(pkt.sender, buf, ADDR_LEN);
    memcpy(pkt.dest, buf + ADDR_LEN, ADDR_LEN);
    pkt.msgID = ((uint16_t)buf[12] << 8) | buf[13];
    pkt.ttl = buf[14];
    pkt.payloadLen = buf[15];
    if (pkt.payloadLen > MAX_PAYLOAD) return false;
    if (len < MESH_HEADER_SIZE + pkt.payloadLen) return false;
    memcpy(pkt.payload, buf + MESH_HEADER_SIZE, pkt.payloadLen);
    return true;
}

// Transmit a mesh packet
bool meshTransmit(MeshPacket& pkt) {
    uint8_t buf[MAX_PACKET_SIZE];
    size_t len = serializePacket(pkt, buf);

    int state = radio.transmit(buf, len);

    // Clear spurious RX flag from TX completion and restart receive
    rxFlag = false;
    radio.startReceive();

    return state == RADIOLIB_ERR_NONE;
}

// Send a message from this node
void meshSend(const uint8_t* dest, const uint8_t* payload, uint8_t payloadLen) {
    MeshPacket pkt;
    memcpy(pkt.sender, nodeAddr, ADDR_LEN);
    memcpy(pkt.dest, dest, ADDR_LEN);
    pkt.msgID = nextMsgID++;
    pkt.ttl = DEFAULT_TTL;
    pkt.payloadLen = payloadLen;
    memcpy(pkt.payload, payload, payloadLen);

    // Add to dedup so we don't re-process our own relayed messages
    addDedup(pkt.sender, pkt.msgID);

    Serial.printf("[SENT] ttl=%d len=%d\n", pkt.ttl, pkt.payloadLen);

    if (!meshTransmit(pkt)) {
        Serial.println("[SENT] TX FAILED");
    }
}

// Handle a received packet
void handleReceived() {
    uint8_t buf[MAX_PACKET_SIZE];
    int state = radio.readData(buf, MAX_PACKET_SIZE);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[RX] Read error, code: %d\n", state);
        radio.startReceive();
        return;
    }

    size_t len = radio.getPacketLength();
    float rssi = radio.getRSSI();
    float snr = radio.getSNR();

    MeshPacket pkt;
    if (!deserializePacket(buf, len, pkt)) {
        Serial.printf("[RX] Malformed packet (%d bytes)\n", len);
        radio.startReceive();
        return;
    }

    // Check dedup
    if (isDuplicate(pkt.sender, pkt.msgID)) {
        Serial.println("[DEDUP] Already seen");
        radio.startReceive();
        return;
    }
    addDedup(pkt.sender, pkt.msgID);

    // Is this message for us?
    bool forUs = addrMatch(pkt.dest, nodeAddr) || isBroadcast(pkt.dest);

    if (forUs) {
        // Deliver to this node
        Serial.printf("[RECV] len=%d ttl=%d RSSI=%.1f SNR=%.1f\n",
                      pkt.payloadLen, pkt.ttl, rssi, snr);
    }

    // Relay if TTL > 0 (relay broadcast messages AND messages not for us)
    if (!addrMatch(pkt.sender, nodeAddr)) {
        if (pkt.ttl <= 1) {
            Serial.println("[DROP] TTL expired");
        } else {
            // Decrement TTL and relay
            pkt.ttl--;
            Serial.printf("[RELAY] ttl=%d->%d\n", pkt.ttl + 1, pkt.ttl);
            meshTransmit(pkt);
        }
    }

    radio.startReceive();
}

void setup() {
    Serial.begin(115200);
    delay(2000);

    // Get MAC address as node identity
    esp_efuse_mac_get_default(nodeAddr);

    Serial.println("=================================");
    Serial.println("  Pigeon Mesh Node");
    Serial.println("=================================");
    Serial.println();

    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);

    // Init: begin() -> DIO2 RF switch -> TCXO (triggers calibrate) -> params
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
    radio.setSyncWord(LORA_SYNC);
    radio.setOutputPower(LORA_POWER);
    radio.setPreambleLength(LORA_PREAMBLE);
    radio.setCRC(2);
    radio.setRxBoostedGainMode(true);
    Serial.println(" OK");

    // Clear dedup table
    memset(dedupTable, 0, sizeof(dedupTable));

    // Set up interrupt-driven receive
    radio.setPacketReceivedAction(onReceive);
    state = radio.startReceive();
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[RX] startReceive FAILED, code: %d\n", state);
        while (true) delay(1000);
    }

    // Offset beacon timing based on node address to avoid collisions
    lastBeaconTime = millis() - BEACON_INTERVAL_MS + (nodeAddr[5] * 37 % BEACON_INTERVAL_MS);

    Serial.println("[MESH] Node ready. Listening and beaconing.");
    Serial.println();
}

void loop() {
    // Handle received packets
    if (rxFlag) {
        rxFlag = false;
        handleReceived();
    }

    // Send periodic beacon (broadcast)
    uint32_t now = millis();
    if (now - lastBeaconTime >= BEACON_INTERVAL_MS) {
        lastBeaconTime = now;

        char msg[64];
        snprintf(msg, sizeof(msg), "beacon from pigeon %02X:%02X",
                 nodeAddr[4], nodeAddr[5]);
        meshSend(BROADCAST_ADDR, (const uint8_t*)msg, strlen(msg));
    }
}
