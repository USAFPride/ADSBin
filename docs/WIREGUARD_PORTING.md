# ESP32-P4 WireGuard integration — PR #2

Target: Waveshare ESP32-P4-WIFI6-DEV-KIT, hosted ESP32-C6 Wi-Fi STA,
RTL-SDR Blog V3 at 1090 MHz. This is a **development-only** integration.

This PR is stacked on PR #1 (`feature/remote-adsb-wireguard`).
Do not merge/deploy to a remote unattended station until the checks below pass.

## Component

The ESP-IDF component manager fetches **trombik/esp_wireguard 0.9.0** from
the Espressif component registry. The original `tools/install-wireguard-component.sh`
manual clone procedure is no longer required and should not be used.
The library is BSD-3-Clause, alpha status, and has not documented ESP-IDF 6.0.1
or ESP32-P4 support.

## Local build check

```bash
. /opt/esp/idf/export.sh
python -m pip install --upgrade 'idf-component-manager==2.5.2'
idf.py set-target esp32p4
idf.py menuconfig
idf.py build
```

Under `Remote ADS-B receiver`, enable the remote STA and WireGuard options.
The remote test build in GitHub Actions uses placeholder SSID with empty keys,
so it checks compilation only; it cannot contact the UDM-Pro.

## Network plan

- Join the remote site's 2.4 GHz WPA2 Wi-Fi network as STA.
- Obtain time through SNTP before starting any WireGuard handshake.
- Dial the UDM-Pro's public hostname on its configured WireGuard UDP port.
- Configure a **dedicated WireGuard peer** with a tunnel /32 for the ESP32.
- Start Beast TCP only once `esp_wireguardif_peer_is_up()` reports a handshake
  and `esp_wireguard_set_default()` successfully installs the VPN route.
- Bind outbound Beast TCP to the tunnel /32 and stop the sender on peer loss.
- Use a **separate readsb instance** on DietPi; never feed this remote
  station's data into the local PiAware MLAT station.

In this alpha library, the configuration fields
`allowed_ip` and `allowed_ip_mask` describe the **local WireGuard interface
address** rather than a peer AllowedIPs destination policy. The library's
peer currently allows any IPv4 address; a route and controlled destination
are essential. That behavior requires review before a production deployment.

## Secrets

Never commit WireGuard private keys or Wi-Fi passphrases. The current
menuconfig approach embeds secrets in the firmware image and is appropriate
for **development only**. Use encrypted provisioning or carefully controlled
NVS storage, flash-encryption/security review, and key rotation before
unattended deployment. Do not upload personalized `sdkconfig` or flash images.

## Remaining acceptance tests

- [ ] All three GitHub Actions builds pass (upstream, remote-lan, wireguard)
- [ ] Inspect/port esp_wireguard for ESP-IDF 6 P4 lwIP and threading compatibility
- [ ] UDM-Pro handshake confirmed with a dedicated peer and NTP clock
- [ ] Verify Beast packets reach DietPi through the VPN
- [ ] Verify **no plaintext TCP** when VPN is down or Wi-Fi changes
- [ ] Verify behavior if remote Wi-Fi subnet overlaps home 192.168.107.0/24
- [ ] Verify peer lifetime/reconnect after extended outages without heap leaks
- [ ] Test SSL/OTA recovery, watchdog, and power-cycle at the physical board

Do not interpret a successful CI build as proof of VPN traffic isolation.
