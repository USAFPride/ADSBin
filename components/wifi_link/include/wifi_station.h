#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Keep the setup SoftAP alive while testing the upstream station connection.
 * Must run after AP startup and before USB streaming, wherever possible. */
esp_err_t wifi_station_start_apsta(void);
/* Existing remote-only STA path (used by remote receiver mode). */
esp_err_t wifi_station_start(void);
/* Non-blocking request: schedules Wi-Fi credentials reload + reconnect on Core 1. */
esp_err_t wifi_station_request_test(void);
bool wifi_station_is_connected(void);

typedef struct {
    bool initialized;
    bool connected;
    bool connecting;
    char ip[16];
    int rssi;
    uint32_t disconnects;
    uint32_t last_reason;
    uint32_t attempts;
} wifi_station_snapshot_t;
void wifi_station_get_snapshot(wifi_station_snapshot_t *out);
