// Pigeon Firmware - Phase 2: SX1262 LoRa Initialization Test
// Hardware: Seeed XIAO ESP32S3 + Wio-SX1262 Shield (Kit version, B2B connector)

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>

// --- Pin mapping: XIAO ESP32S3 + Wio-SX1262 (Kit/B2B version) ---
#define LORA_CS    41   // SPI chip select
#define LORA_DIO1  39   // Interrupt (IRQ)
#define LORA_RESET 42   // Module reset
#define LORA_BUSY  40   // Busy status

// SPI bus pins
#define LORA_SCK   7
#define LORA_MOSI  9
#define LORA_MISO  8

// --- LoRa parameters ---
#define LORA_FREQ       915.0   // MHz (US ISM band)
#define LORA_BW         125.0   // kHz bandwidth
#define LORA_SF         9       // Spreading factor
#define LORA_CR         7       // Coding rate (4/7)
#define LORA_SYNC       0x12    // Sync word (private network)
#define LORA_POWER      22      // TX power in dBm (max for SX1262)
#define LORA_PREAMBLE   8       // Preamble length
#define LORA_TCXO_V     1.8     // TCXO voltage via DIO3

SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RESET, LORA_BUSY);

void setup() {
    Serial.begin(115200);
    delay(2000); // Wait for serial monitor to connect

    Serial.println("=================================");
    Serial.println("  Pigeon Firmware - LoRa Test");
    Serial.println("=================================");
    Serial.println();

    // Initialize SPI with explicit pins
    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);

    Serial.print("[SX1262] Initializing at ");
    Serial.print(LORA_FREQ);
    Serial.println(" MHz...");

    // Init order: begin() -> DIO2 RF switch -> TCXO (triggers calibrate) -> params
    int state = radio.begin();
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[SX1262] Init FAILED, code: %d\n", state);
        Serial.println("Check wiring and board selection.");
        Serial.printf("  CS=%d  DIO1=%d  RST=%d  BUSY=%d\n",
                      LORA_CS, LORA_DIO1, LORA_RESET, LORA_BUSY);
        while (true) delay(1000);
    }

    radio.setDio2AsRfSwitch(true);
    Serial.println("[SX1262] DIO2 RF switch enabled");

    state = radio.setTCXO(LORA_TCXO_V);
    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[SX1262] TCXO FAILED, code: %d\n", state);
    } else {
        Serial.println("[SX1262] TCXO set to 1.8V");
    }

    radio.setFrequency(LORA_FREQ);
    radio.setBandwidth(LORA_BW);
    radio.setSpreadingFactor(LORA_SF);
    radio.setCodingRate(LORA_CR);
    radio.setSyncWord(LORA_SYNC);
    radio.setOutputPower(LORA_POWER);
    radio.setPreambleLength(LORA_PREAMBLE);
    radio.setCRC(2);

    Serial.println();
    Serial.println("LoRa initialized! All systems go.");
}

void loop() {
    // Nothing to do - just a one-time init test
    delay(10000);
}
