// Pigeon Firmware - Phase 3: Transmitter
// Sends "hello from pigeon" every 3 seconds at max power

#include <Arduino.h>
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
#define LORA_FREQ       915.0   // MHz
#define LORA_BW         125.0   // kHz
#define LORA_SF         9       // Spreading factor
#define LORA_CR         7       // Coding rate 4/7
#define LORA_SYNC       0x12    // Private network sync word
#define LORA_POWER      22      // dBm (max)
#define LORA_PREAMBLE   8
#define LORA_TCXO_V     1.8

SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RESET, LORA_BUSY);

uint32_t packetCount = 0;

void setup() {
    Serial.begin(115200);
    delay(2000);

    Serial.println("=================================");
    Serial.println("  Pigeon TX - Transmitter");
    Serial.println("=================================");
    Serial.println();

    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);

    // Init order: begin() -> DIO2 RF switch -> TCXO (triggers calibrate) -> params
    Serial.print("[SX1262] Initializing...");
    int state = radio.begin();
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print(" FAILED, code: ");
        Serial.println(state);
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
    Serial.println(" OK");

    Serial.println("[TX] Ready. Transmitting every 3 seconds.");
    Serial.println();
}

void loop() {
    packetCount++;

    char msg[64];
    snprintf(msg, sizeof(msg), "hello from pigeon #%lu", (unsigned long)packetCount);

    Serial.print("[TX] Sending: \"");
    Serial.print(msg);
    Serial.print("\" ... ");

    int state = radio.transmit((uint8_t*)msg, strlen(msg));

    if (state == RADIOLIB_ERR_NONE) {
        Serial.println("OK");
    } else {
        Serial.print("FAILED, code: ");
        Serial.println(state);
    }

    delay(3000);
}
