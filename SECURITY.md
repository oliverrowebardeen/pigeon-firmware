# Security

Report potential vulnerabilities privately using [GitHub private vulnerability reporting](https://github.com/oliverrowebardeen/pigeon-firmware/security/advisories/new). Include the affected commit, reproduction steps, and impact in the private report.

If the form is unavailable, open an issue asking the maintainer to enable private vulnerability reporting. Include no vulnerability details, exploit code, personal information, or credentials in that public request. Wait for a private channel before sending the report.

Only test devices and relay instances you own or are authorized to test. This is experimental software; the code review and automated tests are not an independent cryptographic audit.

Message content stays encrypted by the client, but radio headers, presence, packet sizes, and timing are visible. The default Meshtastic channel key is public; it does not provide confidentiality for Pigeon messages. The client envelope provides that protection.

BLE provisioning/control is currently unauthenticated. A nearby device can change WiFi or radio settings. Provision only in a trusted physical environment; authenticated administration remains necessary before unattended deployment in hostile locations. Encrypted NVS credentials do not protect against extraction from a device whose flash and identity key can be read. Physical security, ESP32 flash encryption, and secure boot require a separate deployment design.

Security fixes target `main`; there are no supported releases. Reports are handled on a best-effort basis without a guaranteed response time.

The default build does not select an internet relay. Operators must configure an authorized endpoint and preserve TLS certificate validation. Bridge status notifications omit the SSID and local IP, but peer discovery advertises public keys/IDs and native LoRa headers contain hardware-derived addresses. The local OLED also shows the node's ID. These are stable, observable identifiers, not an anonymity mechanism. Routine serial tracing is disabled by default; review even redacted diagnostics before publishing them.
