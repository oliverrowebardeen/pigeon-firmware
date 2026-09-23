#pragma once
#include <stddef.h>
#include <stdint.h>

namespace pigeon {
// Validate before reserving a reassembly slot or indexing its fixed-size arrays.
inline bool validFragment(size_t index, size_t total, size_t payloadSize,
                          size_t stride, size_t maxChunks, size_t capacity) {
    if (total == 0 || total > maxChunks || index >= total || stride == 0 ||
        payloadSize > stride || index > capacity / stride) return false;
    const size_t offset = index * stride;
    return payloadSize <= capacity - offset;
}

inline bool validChallengeID(const char* value) {
    if (!value) return false;
    for (size_t i = 0; i < 36; ++i) {
        const char c = value[i];
        if (c == '\0') return false;
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                     (c >= 'A' && c <= 'F'))) return false;
    }
    return value[36] == '\0';
}

inline bool decodeVarint32(const uint8_t* data, size_t len, size_t& pos, uint32_t& value) {
    value = 0;
    for (unsigned shift = 0; shift <= 28 && pos < len; shift += 7) {
        const uint8_t byte = data[pos++];
        if (shift == 28 && byte > 0x0f) return false;
        value |= uint32_t(byte & 0x7f) << shift;
        if (!(byte & 0x80)) return true;
    }
    return false;
}

inline bool decodeMeshData(const uint8_t* data, size_t len, uint32_t& port,
                           const uint8_t*& payload, size_t& payloadLen) {
    size_t pos = 0;
    port = 0;
    payload = nullptr;
    payloadLen = 0;
    while (pos < len) {
        uint32_t tag = 0;
        if (!decodeVarint32(data, len, pos, tag) || (tag >> 3) == 0) return false;
        const uint32_t field = tag >> 3;
        const uint32_t wire = tag & 7;
        uint32_t value = 0;
        if (wire == 0) {
            if (!decodeVarint32(data, len, pos, value)) return false;
            if (field == 1) port = value;
        } else if (wire == 2) {
            if (!decodeVarint32(data, len, pos, value) || value > len - pos) return false;
            if (field == 2) { payload = data + pos; payloadLen = value; }
            pos += value;
        } else if (wire == 1 || wire == 5) {
            const size_t width = wire == 1 ? 8 : 4;
            if (width > len - pos) return false;
            pos += width;
        } else {
            return false;
        }
    }
    return payload != nullptr;
}
}
