# Contributing

Build all environments with `pio run` using PlatformIO 6.1.19. The main experimental target is `pigeon`; the other three targets are radio development tools. The platform and direct library versions are pinned in `platformio.ini`.

Run host-side input validation tests before submitting changes:

```sh
clang++ -std=c++11 -Wall -Wextra -Werror -fsanitize=address,undefined -Iinclude tests/protocol_validation_test.cpp -o /tmp/pigeon-protocol-tests
/tmp/pigeon-protocol-tests
```

Describe the hardware, radio mode, phones, and reproduction steps used for device testing. Host tests and successful compilation do not establish radio interoperability, range, power consumption, or reliable delivery. Never commit WiFi credentials, private identity keys, or device dumps. Report security issues through [SECURITY.md](SECURITY.md).

Keep local relay/radio settings in the ignored `include/pigeon_config.local.h` file. The default build leaves internet bridging disabled. Do not commit serial captures or packet dumps; redact identifiers before attaching diagnostic output to an issue.

Use small, focused pull requests with a description of the problem, resulting behavior, and validation. Follow the [Code of Conduct](CODE_OF_CONDUCT.md). Contributions to Pigeon source are under the [MIT license](LICENSE); retain all upstream notices when changing third-party code.
