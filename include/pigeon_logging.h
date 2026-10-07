#pragma once
#include <Arduino.h>
#include "pigeon_config.h"

// Routine traffic tracing is opt-in. Never log credentials or peer identifiers.
#ifndef PIGEON_DEBUG_LOGS
#define PIGEON_DEBUG_LOGS 0
#endif
#if PIGEON_DEBUG_LOGS
#define PIGEON_TRACE(...) Serial.printf(__VA_ARGS__)
#else
#define PIGEON_TRACE(...) do {} while (0)
#endif
