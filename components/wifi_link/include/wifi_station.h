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

/* Asynchronous network discovery and transactional station provisioning. */
typedef struct {
    char ssid[33];
    int rssi;
    uint8_t authmode;
} wifi_station_ap_t;
typedef struct {
    bool scanning;
    bool complete;
    esp_err_t error;
    size_t count;
    wifi_station_ap_t aps[20];
} wifi_station_scan_t;
typedef enum {
    WIFI_PROVISION_IDLE=0,
    WIFI_PROVISION_CONNECTING,
    WIFI_PROVISION_SAVED,
    WIFI_PROVISION_FAILED
} wifi_station_provision_state_t;
typedef struct {
    wifi_station_provision_state_t state;
    char message[80];
} wifi_station_provision_t;
esp_err_t wifi_station_scan_request(void);
void wifi_station_scan_snapshot(wifi_station_scan_t *out);
esp_err_t wifi_station_provision(const char *ssid,const char *password);
void wifi_station_provision_snapshot(wifi_station_provision_t *out);
