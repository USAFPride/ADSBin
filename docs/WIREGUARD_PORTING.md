# WireGuard ESP32-P4 port — blocked on compatibility validation

Candidate: https://github.com/trombik/esp_wireguard (BSD-3-Clause).
The upstream README labels it **alpha** and lists ESP-IDF 4.x era targets,
not ESP32-P4 with ESP-IDF 6.0.1. Do not claim production support.

## Installation on a development workstation

From the ADSBin repository root:

```sh
bash tools/install-wireguard-component.sh
idf.py set-target esp32p4
idf.py menuconfig
idf.py build
```

The installer checks out the third-party source into `components/esp_wireguard`.
It does **not** apply an ESP32-P4 compatibility port. It is intentionally
not part of committed source to avoid shipping an unreviewed cryptography fork.

## Intended configuration

- Wi-Fi client on the ESP32-C6 (not SoftAP).
- UDM-Pro WireGuard server as remote endpoint, with a dedicated peer.
- VPN-only Beast TCP toward a *dedicated* readsb instance on DietPi.
- Receiver source IP address must be a dedicated WireGuard /32.
- Keepalive 25 seconds, no public Beast TCP listener.
- Device clock synchronization must complete before attempting WireGuard.
- Never commit `sdkconfig`, private keys, Wi-Fi credentials, or VPN credentials.

## Must test before remote deployment

1. Compile the library with ESP-IDF 6.0.1 for esp32p4.
2. Verify WG handshakes with ESP-hosted Wi-Fi STA.
3. Establish synchronized system time using SNTP (not yet wired).
4. Verify encrypted routing to the DietPi VPN destination.
5. Demonstrate packets cannot escape unencrypted on STA if VPN goes down.
6. Confirm no DSP/USB packet loss under continuous load.
7. Test Wi-Fi disconnect, tunnel recreation, reconnect, and hardware watchdog.
8. Implement rollback-safe remote OTA.

**The firmware is not ready for remote deployment.**
