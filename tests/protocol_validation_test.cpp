#include "protocol_validation.h"
#include <assert.h>
#include <limits>
#include <string>
#include <vector>

int main() {
    const uint8_t valid[] = {0x08, 0x80, 0x02, 0x12, 0x02, 0xab, 0xcd};
    uint32_t port;
    const uint8_t* payload;
    size_t length;
    assert(pigeon::decodeMeshData(valid, sizeof(valid), port, payload, length));
    assert(port == 256 && length == 2 && payload[0] == 0xab && payload[1] == 0xcd);
    for (size_t size = 0; size < sizeof(valid); ++size)
        assert(!pigeon::decodeMeshData(valid, size, port, payload, length));
    const std::vector<std::vector<uint8_t>> malformed = {
        {0x00, 0x00}, {0x08, 0xff, 0xff, 0xff, 0xff, 0x1f},
        {0x12, 0x01, 0xab, 0x08, 0x80}, // valid payload followed by truncated varint
        {0x12, 0xff, 0xff, 0xff, 0xff, 0x0f},
        {0x12, 0x01, 0xab, 0x1a, 0x02, 0x00}
    };
    for (const auto& frame : malformed)
        assert(!pigeon::decodeMeshData(frame.data(), frame.size(), port, payload, length));

    assert(pigeon::validChallengeID("550e8400-e29b-41d4-a716-446655440000"));
    assert(!pigeon::validChallengeID(nullptr));
    for (size_t length = 0; length < 256; ++length) {
        std::string malicious(length, 'a');
        assert(!pigeon::validChallengeID(malicious.c_str()));
    }
    assert(!pigeon::validChallengeID("550e8400-e29b-41d4-a716-446655440000a"));
    assert(!pigeon::validChallengeID("550e8400_e29b-41d4-a716-446655440000"));
    assert(pigeon::validFragment(0, 1, 480, 480, 16, 2048));
    assert(pigeon::validFragment(4, 5, 128, 480, 16, 2048));
    assert(!pigeon::validFragment(4, 5, 129, 480, 16, 2048));
    assert(!pigeon::validFragment(0, 1, 481, 480, 16, 2048));
    assert(!pigeon::validFragment(0, 0, 0, 480, 16, 2048));
    assert(!pigeon::validFragment(0, 17, 1, 480, 16, 2048));
    assert(!pigeon::validFragment(1, 1, 1, 480, 16, 2048));
    assert(!pigeon::validFragment(std::numeric_limits<size_t>::max() - 1,
                                std::numeric_limits<size_t>::max(), 1, 480,
                                std::numeric_limits<size_t>::max(), 2048));
    // Every accepted fragment must fit both its own slot and the destination.
    for (size_t total = 0; total < 40; ++total)
        for (size_t index = 0; index < 40; ++index)
            for (size_t size = 0; size < 520; ++size)
                if (pigeon::validFragment(index, total, size, 480, 32, 8192)) {
                    assert(total > 0 && total <= 32 && index < total);
                    assert(size <= 480 && index * 480 + size <= 8192);
                }
}
