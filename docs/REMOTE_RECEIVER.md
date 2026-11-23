# Remote ADS-B receiver (development branch)

Hardware: Waveshare ESP32-P4-WIFI6-DEV-KIT, RTL-SDR Blog V3 (1090 MHz), ESP32-C6 hosted Wi-Fi.

This branch is **experimental**. Do not deploy it at a remote site until the SDR data path, TCP feeder, VPN, and OTA recovery have been verified on hardware.

## Milestones

- [x] Independent development branch, preserving main
- [x] Optional Wi-Fi station mode; retain original SoftAP mode for non-remote builds
- [ ] Beast TCP output of validated raw Mode-S frames
- [ ] WireGuard client on ESP32-P4 over hosted ESP32-C6 Wi-Fi
- [ ] Fail-closed VPN-only data routing
- [ ] Watchdog, telemetry, OTA rollback, and end-to-end bench testing

Do **not** push `sdkconfig`, flash dumps, passwords or WireGuard private keys to GitHub.

A geographically distant receiver must have a separate readsb station identity. Do not merge its data into the local PiAware/MLAT feeder. For initial TCP tests use a trusted LAN only.
