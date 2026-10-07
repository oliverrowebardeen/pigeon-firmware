#pragma once

// Copy to pigeon_config.local.h (ignored by Git), then select your own relay.
// Use a hostname only, without a URL scheme or path. An empty host disables
// the WiFi bridge. WiFi credentials are provisioned over BLE, not built in.
#define PIGEON_RELAY_HOST ""
#define PIGEON_RELAY_PORT 443
#define PIGEON_RELAY_PATH "/v1/ws"

// TLS defaults to ISRG Root X1. For another CA, define PIGEON_RELAY_ROOT_CA
// as a PEM string literal here. Never disable certificate validation.

// Check the radio module, antenna, and local requirements before transmitting.
// All four environments use these values, including both pigeon radio modes.
#define PIGEON_LORA_FREQUENCY_MHZ 915.0
#define PIGEON_LORA_POWER_DBM 22

// Routine packet/bridge tracing for the pigeon target (disabled by default).
#define PIGEON_DEBUG_LOGS 0
