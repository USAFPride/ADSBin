#!/usr/bin/env bash
set -euo pipefail
# Development only: source integration is NOT an ESP32-P4/IDF-6 compatibility claim.
cd "$(dirname "$0")/.."
if [[ -e components/esp_wireguard ]]; then
  echo "components/esp_wireguard already exists; refusing to overwrite" >&2
  exit 1
fi
git clone https://github.com/trombik/esp_wireguard.git components/esp_wireguard
echo "Inspect and port this third-party component for ESP-IDF 6.0.1 / ESP32-P4 before building."
echo "Do NOT commit secrets, sdkconfig or private keys."
