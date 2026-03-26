// Pigeon Firmware - Phase 3: Receiver
// Listens for LoRa packets using interrupt-driven receive, prints with RSSI

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

// --- LoRa parameters (must match transmitter) ---
#define LORA_FREQ       915.0
#define LORA_BW         125.0
#define LORA_SF         9
#define LORA_CR         7
#define LORA_SYNC       0x12
#define LORA_POWER      22
#define LORA_PREAMBLE   8
#define LORA_TCXO_V     1.8

SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RESET, LORA_BUSY);

volatile bool rxFlag = false;
uint32_t rxCount = 0;

void IRAM_ATTR onReceive() {
    rxFlag = true;
}

void setup() {
    Serial.begin(115200);
    delay(2000);

    Serial.println("=================================");
    Serial.println("  Pigeon RX - Receiver");
    Serial.println("=================================");
    Serial.println();

    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);

    // Init order matters for SX1262 with TCXO + DIO2 RF switch:
    // 1. Basic init (gets SPI working)
    // 2. DIO2 as RF switch (must be before calibration)
    // 3. TCXO (internally calls calibrate() — now with RF switch set)
    // 4. Set all LoRa parameters

    Serial.print("[SX1262] Initializing...");
    int state = radio.begin();
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print(" basic init FAILED, code: ");
        Serial.println(state);
        while (true) delay(1000);
    }

    state = radio.setDio2AsRfSwitch(true);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print(" DIO2 FAILED, code: ");
        Serial.println(state);
    }

    state = radio.setTCXO(LORA_TCXO_V);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print(" TCXO FAILED, code: ");
        Serial.println(state);
    }

    // Now set all LoRa parameters
    radio.setFrequency(LORA_FREQ);
    radio.setBandwidth(LORA_BW);
    radio.setSpreadingFactor(LORA_SF);
    radio.setCodingRate(LORA_CR);
    radio.setSyncWord(LORA_SYNC);
    radio.setOutputPower(LORA_POWER);
    radio.setPreambleLength(LORA_PREAMBLE);
    radio.setCRC(2);
    radio.setRxBoostedGainMode(true);  // Improve RX sensitivity
    Serial.println(" OK");

    // Set up interrupt on DIO1 for packet reception
    radio.setPacketReceivedAction(onReceive);

    // Start continuous receive mode
    state = radio.startReceive();
    if (state != RADIOLIB_ERR_NONE) {
        Serial.print("[RX] startReceive FAILED, code: ");
        Serial.println(state);
        while (true) delay(1000);
    }

    Serial.println("[RX] Listening for packets (interrupt mode)...");
    Serial.println();
}

void loop() {
    if (!rxFlag) return;
    rxFlag = false;

    uint8_t buf[256];
    int state = radio.readData(buf, sizeof(buf) - 1);

    if (state == RADIOLIB_ERR_NONE) {
        rxCount++;
        int len = radio.getPacketLength();
        buf[len] = '\0';

        Serial.print("[RX #");
        Serial.print(rxCount);
        Serial.print("] \"");
        Serial.print((char*)buf);
        Serial.print("\"  RSSI: ");
        Serial.print(radio.getRSSI());
        Serial.print(" dBm  SNR: ");
        Serial.print(radio.getSNR());
        Serial.println(" dB");
    } else {
        Serial.print("[RX] Read error, code: ");
        Serial.println(state);
    }

    // Restart receive
    radio.startReceive();
}
