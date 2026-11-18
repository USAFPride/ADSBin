# ADSBin AP+STA HTTP Wi-Fi bench test

**Bench only.** The ADSBin SoftAP remains open at `http://192.168.4.1/`.
Wi-Fi SSID and password can be saved via plain HTTP and ordinary, unencrypted
NVS. This is intentionally insecure and must ONLY be used with a disposable
test-network password. Never use credentials from a production network.
WireGuard private-key provisioning remains disabled.

## Test sequence
1. Flash this branch to ESP32-P4 using COM5.
2. Join Wi-Fi `ADSBin`; browse to `http://192.168.4.1/`.
3. In **Network**, enter the target router's WPA2-compatible Wi-Fi SSID and
   disposable test password (8–63 characters), and press **Save settings**.
4. Confirm the UI responds `Saved in NVS (server confirmed)`.
5. Press **Test Wi-Fi connection**. This requests an asynchronous connection
   on the hosted ESP32-C6 while leaving the ADSBin SoftAP enabled.
6. Watch `Wi-Fi station` in the dashboard for DHCP IPv4, RSSI, retry count,
   disconnect count, and last disconnect reason. The password is not returned
   from `/api/config`; it only reports `wifi_password_configured`.
7. Reboot: saved station settings will be retried automatically before SDR
   streaming begins; verify the dashboard remains available at 192.168.4.1.
8. Observe aircraft decoding, USB drops, and sample rate during Wi-Fi traffic.

ESP-Hosted AP+STA support is hardware/firmware-version dependent. If the
setup AP disappears, Wi-Fi setup fails, or USB reception degrades, flash
the previous proven `feature/http-config-bench-20261118` branch using COM5.

## Beast TCP destination – next stage

Default remote Beast destination is 192.168.107.20 port **30004** (readsb Beast
INPUT by default). Port 30005 is typically Beast OUTPUT. Verify how Docker
publishes readsb's 30004 on your DietPi host before testing connectivity.

On DietPi:
```bash
clear
cd /opt/adsb
docker compose ps
docker exec ultrafeeder sh -c 'ss -lnt 2>/dev/null | grep -E ":30004|:30005" || true'
```

If port 30004 is only exposed inside Docker rather than on host 192.168.107.20,
publish 30004/tcp on the ultrafeeder service (or use another deliberate
forwarding/connection architecture). Do not change your existing live feeds
until the network path is confirmed.

This branch tests AP+STA and persistent Wi-Fi first; Beast forwarding in
remote-only mode is still controlled by the existing remote receiver build
options. Do not turn on remote WireGuard or transmit frames over an insecure
untrusted remote path as part of this initial connection test.
