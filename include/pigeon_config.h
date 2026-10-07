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
