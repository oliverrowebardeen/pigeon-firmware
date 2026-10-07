#pragma once

// Copy pigeon_config.example.h to pigeon_config.local.h for local settings.
#if __has_include("pigeon_config.local.h")
#include "pigeon_config.local.h"
#endif

// No shared relay is selected by default. BLE and LoRa work without one.
#ifndef PIGEON_RELAY_HOST
#define PIGEON_RELAY_HOST ""
#endif
#ifndef PIGEON_RELAY_PORT
#define PIGEON_RELAY_PORT 443
#endif
#ifndef PIGEON_RELAY_PATH
#define PIGEON_RELAY_PATH "/v1/ws"
#endif

// These are radio test defaults, not automatic region compliance settings.
#ifndef PIGEON_LORA_FREQUENCY_MHZ
#define PIGEON_LORA_FREQUENCY_MHZ 915.0
#endif
#ifndef PIGEON_LORA_POWER_DBM
#define PIGEON_LORA_POWER_DBM 22
#endif

// SX1262 hardware limits (RadioLib 7.7.1), not regulatory limits.
static_assert(PIGEON_LORA_FREQUENCY_MHZ >= 150.0 && PIGEON_LORA_FREQUENCY_MHZ <= 960.0,
              "PIGEON_LORA_FREQUENCY_MHZ must be between 150 and 960 MHz");
static_assert(PIGEON_LORA_POWER_DBM >= -9 && PIGEON_LORA_POWER_DBM <= 22,
              "PIGEON_LORA_POWER_DBM must be between -9 and 22 dBm");
