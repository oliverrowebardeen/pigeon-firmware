# Security

Report potential vulnerabilities in the Pigeon mesh firmware privately to **security@example.com**, the existing Pigeon project security contact. Include the affected commit, reproduction steps, and impact. Do not put credentials, private keys, or exploitable details into public issues.

Only test devices and relay instances you own or are authorized to test. This is experimental software; the code review and automated tests are not an independent cryptographic audit.

Message content stays encrypted by the client, but radio headers, presence, packet sizes, and timing are visible. The default Meshtastic channel key is public; it does not provide confidentiality for Pigeon messages. The client envelope provides that protection.

BLE provisioning/control is currently unauthenticated. A nearby device can change WiFi or radio settings. Provision only in a trusted physical environment; authenticated administration remains necessary before unattended deployment in hostile locations. Encrypted NVS credentials do not protect against extraction from a device whose flash and identity key can be read. Physical security, ESP32 flash encryption, and secure boot require a separate deployment design.
