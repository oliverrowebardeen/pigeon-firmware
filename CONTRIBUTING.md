# Contributing

Build all environments with `pio run` using PlatformIO 6.1.19. The production target is `pigeon`; the other three targets are radio development tools. The platform and direct library versions are pinned in `platformio.ini`.

Run host-side input validation tests before submitting changes:

```sh
clang++ -std=c++11 -Wall -Wextra -Werror -fsanitize=address,undefined -Iinclude tests/protocol_validation_test.cpp -o /tmp/pigeon-protocol-tests
/tmp/pigeon-protocol-tests
```

Describe the hardware, radio mode, phones, and reproduction steps used for device testing. Host tests and successful compilation do not establish radio interoperability, range, power consumption, or reliable delivery. Never commit WiFi credentials, private identity keys, or device dumps. Report security issues through [SECURITY.md](SECURITY.md).
