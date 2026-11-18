# ADSBin on-device provisioning — requirements

Status: design and safety constraints; not yet a working provisioning portal.
Branch: `feature/wifi-provisioning`.

## Interface

A password-protected local setup web page must allow the operator to save:

- Wi-Fi: SSID and password.
- WireGuard: enabled checkbox (default **OFF**), client private key, server/peer public key, optional preshared key, endpoint hostname or address, UDP port, and client tunnel address/prefix.
- Beast: receiver hostname or address, TCP port, and a separate explicit option to permit trusted-LAN plaintext for testing only.
- Read-only runtime diagnostics: Wi-Fi connection status, VPN handshake, Beast connection, RF throughput and RF/DSP drops.

Do not pre-populate any network addresses, endpoint hostnames, passwords, or VPN keys in tracked source, project defaults, scripts, tests or documentation. No location-specific settings in Git.

## Provisioning behavior

1. When credentials are absent, start a temporary password-protected provisioning SoftAP on the hosted Wi-Fi coprocessor. Use a unique device setup credential; do not hardcode a shared setup password. Keep the setup HTTP service available only from the isolated setup interface; it must not be publicly exposed.
2. Once a valid form is submitted, validate every field (length, base64 keys, port ranges and address/prefix syntax); store settings in nonvolatile storage on the device and reconnect. Do not print or return saved secrets in status responses.
3. When Wi-Fi credentials exist, reconnect automatically after reboot and transient loss. Re-enter setup mode by a deliberate recovery action or a documented recovery procedure, not by silently exposing the administrator interface to the upstream network.
4. Store settings in NVS. Validate flash/NVS encryption availability on this hardware before describing stored secrets as encrypted. Never commit any exported NVS data, production keys, local settings or populated sdkconfig files.
5. WireGuard is strictly optional at runtime, and OFF by default. If enabled, Beast TCP must fail closed until a real tunnel handshake is confirmed and traffic is confined to the VPN path; verify this on hardware. Enabling trusted-LAN plaintext is a separate, deliberate action and is never the default.
6. Do not assume the ESP32-P4/hosted ESP32-C6 supports concurrent AP+STA provisioning with the currently pinned hosted dependencies without testing. Bring up connectivity before starting USB IQ streaming, preserving the validated DSP and USB paths.

## Development boundaries

- All development stays on `feature/wifi-provisioning`; retain the validated performance branch unchanged.
- Do not commit actual IP addresses or secrets. The remote destination and WireGuard tunnel-address compile-time defaults must remain empty while the runtime provisioning path is developed.
- The existing remote sender is not MLAT qualified (its Beast timestamp is zero). Do not enable it as a trusted MLAT receiver.
- Hardware build, UI security checks, reconnect testing, and field testing are mandatory before merging this branch.
