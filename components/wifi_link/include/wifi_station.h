#pragma once
#include "esp_err.h"
#include <stdbool.h>

/* Remote-receiver Wi-Fi client on the P4's hosted ESP32-C6. */
esp_err_t wifi_station_start(void);
bool wifi_station_is_connected(void);
