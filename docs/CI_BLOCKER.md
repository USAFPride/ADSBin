# CI blocker: ESP-IDF 6.0.1 component-manager resolution

Status as of 2026-11-08: CI fails *before C compilation* at `idf.py set-target esp32p4`.

Error:
```
ESP_HOSTED_HOST_USB_CDC_ACM_MANIFEST
ESP_HOSTED_HOST_USB_CHERRYUSB_MANIFEST
ESP_HOSTED_HOST_USB_RNDIS_MANIFEST
CMake Error: Missing required kconfig option after retry.
```

These `*_MANIFEST` options arise in dependency rules from the ESP-Hosted registry integration; they are not the RTL-SDR USB host driver. ADSBin uses ESP-Hosted over SDIO.

Tests performed (all failed with same configuration error):
- ESP-Hosted 2.13.1
- ESP-Hosted 2.12.2
- ESP-Hosted 2.10.0
- App Kconfig definitions of the three symbols

Next candidate to investigate: use a reviewed, version-pinned local ESP-Hosted component (upstream espressif/esp-hosted-mcu tag v2.13.1), replacing the registry dependency. This requires modifying the build manifest and CI checkout together, so do not add a dangling override_path. Alternatively report issue with the upstream component manager.

This issue blocks verifying the Wi-Fi STA/Beast C code, and the independent WireGuard ESP32-P4 port remains unverified.

Other assessed foundations:
- John-ODell/esp32-p4-rtl-sdr: working embedded SDR and ADS-B with display, but would require removal of UI dependencies and addition of network transport.
- hardcoreerik/esp-rtl-sdr: suitable RTL-SDR USB driver, but no full ADS-B pipeline.
- Kemerd/ADSBin: still best application-layer starting point; its decode/network split fits our target.

Before remote deployment, validate the actual chip revision selection: upstream sdkconfig.defaults targets pre-v3 ESP32-P4 silicon and may not match newly purchased Waveshare hardware. Also verify non-MLAT Beast output, VPN-only routing, watchdog and secure rollback OTA.
