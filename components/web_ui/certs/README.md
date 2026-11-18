# ADSBin HTTP bench configuration (no OpenSSL required)

This branch uses the existing `ADSBin` open access point and HTTP page at
`http://192.168.4.1/`. It requires no TLS keys, certificates, or OpenSSL.

**WARNING:** The access point is OPEN and the configuration API has NO
authentication. Anyone able to join the ADSBin AP can view or change the
non-secret fields. This mode is ONLY for isolated bench testing and must
not be used on an untrusted network or exposed to the Internet.

Enabled by default for bench builds with
`CONFIG_ADSBIN_WEB_HTTP_CONFIG=y` in menuconfig. If disabled, the
dashboard remains available but GET/POST /api/config is not registered.

Editable and persisted in NVS namespace `web_cfg`:
- `wifi_ssid` (non-secret)
- `beast_host` (IPv4) and `beast_port`
- `wg_public` (WireGuard peer PUBLIC key)
- `wg_endpoint`, `wg_ip`, `wg_port`

**Optional isolated bench password test:** Enable
`ADSBIN_BENCH_ALLOW_WIFI_PASSWORD_HTTP=y` in `idf.py menuconfig`.
This allows a disposable 8–63-character test Wi-Fi password in POST
`/api/config`. The secret is stored under `wifi_pass` in ordinary NVS,
never returned by GET, and loaded only when remote STA mode starts.
The UI reports whether a password is present without revealing it.
**HTTP, the AP, and NVS are unencrypted. Do not use production Wi-Fi
credentials.** Disable this feature and erase any stored test password
before field deployment. WireGuard PRIVATE keys and other credentials
remain blocked. Unknown JSON fields are rejected.

Application behavior:
- Beast destination/port override is loaded when a new TCP connection is made
  (only in remote mode when remote transport is already enabled).
- Wi-Fi SSID override is loaded when station mode starts; it does **not**
  enable station mode and it does **not** set a Wi-Fi password.
- WireGuard public fields are **staged only** and do not yet modify the active
  VPN; private key remains configured locally at build time.
- The UI Save action is a persistence operation, not a full dynamic Apply.
- USB and DSP firmware paths are unchanged.

To test, build and flash the branch to COM5, join ADSBin AP, visit the
dashboard, select Network, edit `beast_host` and `beast_port`, click
Save, refresh page, and verify persistence. Reboot and verify persistence
again. Inspect `http://192.168.4.1/api/config` if debugging.

Do not merge until build succeeds and 1090 MHz RF throughput/aircraft
decoding remain stable during HTTP operations. When secure provisioning is
available, disable this open HTTP configuration endpoint.

## Confirm Save works

On the bench page, enter a harmless non-secret Beast host/port and press Save.
The status text should state `Saved in NVS (server confirmed)`.
Reload the page and confirm the same fields reappear, then reboot the board
and check once more. Directly visit `http://192.168.4.1/api/config` to
inspect saved non-secret fields. The Wi-Fi password is never included.
