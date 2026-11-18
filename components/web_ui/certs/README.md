# ADSBin HTTPS configuration – bench provisioning

**Experimental draft.** Normal HTTP port 80 remains a read-only receiver dashboard.
Configuration writes are only available on HTTPS port 443 with a short-lived admin
token printed to UART0. Never send sensitive data over port 80.

## Certificate creation on the development computer

Generate a unique, local-only certificate; do **not** commit these PEM files.

In an ESP-IDF PowerShell terminal with OpenSSL available:

```powershell
cd C:\esp\projects\ADSBin
New-Item -ItemType Directory -Force components\web_ui\certs | Out-Null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 365 `
  -keyout components\web_ui\certs\serverkey.pem `
  -out components\web_ui\certs\servercert.pem `
  -subj "/CN=192.168.4.1" -addext "subjectAltName=IP:192.168.4.1"
openssl x509 -in components\web_ui\certs\servercert.pem -noout -fingerprint -sha256
```

Validate the SHA-256 certificate fingerprint in the browser using the local
terminal output (self-signed certificates are not publicly trusted). Do not
upload the PEM private key or share it as part of console logs.

Enable **ADSBin web management > Enable authenticated HTTPS configuration
service** using `idf.py menuconfig`, then `idf.py build` and flash COM5.

The firmware prints a fresh 32-character ADMIN TOKEN in the serial console
for each boot. Treat it as a password; redact it from shared logs.
Join the ADSBin access point and browse to **https://192.168.4.1/**.

The open HTTP dashboard will continue to run at http://192.168.4.1/.
Only the HTTPS page can load/save settings. This is a developer-only admin
interface: no session persistence, no rate limiting, no password recovery.

## Storage and apply behavior

- Editable now: Wi-Fi SSID; Beast IPv4 and port; WireGuard peer PUBLIC key,
  endpoint, tunnel IPv4 and port.
- Values persist in the existing NVS namespace `web_cfg`. Beast destination
  overrides are read on the next TCP connection, including after reboot.
  An SSID override is read when STA starts; STA mode itself still requires the
  existing build-time remote-enable flag. Wi-Fi password remains compiled/local.
- **Not supported yet:** Wi-Fi password and WireGuard client PRIVATE key.
  They are deliberately blocked even on HTTPS because the current ordinary
  NVS partition has no verified NVS-encryption provisioning. Flash encryption
  alone does not prove NVS encryption was initialized. Do not provision real
  secrets to this revision.
- VPN public settings are staged only; WireGuard currently reads compiled
  settings until NVS runtime integration is implemented.
- No automatic reboot or Wi-Fi mode change on Save. These are follow-up features.

Do not merge or deploy the feature branch until a successful device build and
aircraft reception test verifies that HTTPS does not starve the RF pipeline.
