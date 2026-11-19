/* ADSBin Wi-Fi station and AP+STA bench test over hosted ESP32-C6.
 * USB/DSP never call this component. The SoftAP remains available as a
 * recovery path while a test station connection is attempted.
 *
 * BENCH SECURITY: NVS-stored passwords are plaintext without NVS encryption.
 * Do not use production Wi-Fi credentials on the open ADSBin AP.
 */
#include "wifi_station.h"
#include <string.h>
#include <stdio.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_ip_addr.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "wifi_station";
static volatile bool s_initialized;
static volatile bool s_connected;
static volatile bool s_connecting;
static volatile bool s_test_running;
static volatile bool s_reconfiguring;
static volatile int s_rssi;
static volatile uint32_t s_disconnects, s_last_reason, s_attempts;
static char s_ip[16];

static bool read_credentials(wifi_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
#ifdef CONFIG_ADSBIN_REMOTE_ENABLE
    const char *default_ssid = CONFIG_ADSBIN_REMOTE_WIFI_SSID;
    const char *default_pass = CONFIG_ADSBIN_REMOTE_WIFI_PASSWORD;
#else
    const char *default_ssid = "";
    const char *default_pass = "";
#endif
    size_t n = strlen(default_ssid);
    if (n > sizeof(cfg->sta.ssid)) n = sizeof(cfg->sta.ssid);
    memcpy(cfg->sta.ssid, default_ssid, n);
    n = strlen(default_pass);
    if (n > sizeof(cfg->sta.password)) n = sizeof(cfg->sta.password);
    memcpy(cfg->sta.password, default_pass, n);
    nvs_handle_t prefs;
    if (nvs_open("web_cfg", NVS_READONLY, &prefs) == ESP_OK) {
        char ssid[33] = {0};
        char pass[65] = {0};
        size_t size = sizeof(ssid);
        if (nvs_get_str(prefs, "wifi_ssid", ssid, &size) == ESP_OK && ssid[0]) {
            memset(cfg->sta.ssid, 0, sizeof(cfg->sta.ssid));
            memcpy(cfg->sta.ssid, ssid, strnlen(ssid, sizeof(cfg->sta.ssid)));
        }
        size = sizeof(pass);
        if (nvs_get_str(prefs, "wifi_pass", pass, &size) == ESP_OK && pass[0]) {
            memset(cfg->sta.password, 0, sizeof(cfg->sta.password));
            memcpy(cfg->sta.password, pass, strnlen(pass, sizeof(cfg->sta.password)));
        }
        memset(pass, 0, sizeof(pass));
        nvs_close(prefs);
    }
    cfg->sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    return cfg->sta.ssid[0] != 0;
}

static void try_connect(void)
{
    if (++s_attempts > 10) {
        s_connecting = false;
        ESP_LOGW(TAG, "10 connection attempts exhausted; use Test Wi-Fi to retry");
        return;
    }
    s_connecting = true;
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK) {
        s_connecting = false;
        ESP_LOGW(TAG, "Wi-Fi connect request #%lu failed: %s",
                 (unsigned long)s_attempts, esp_err_to_name(err));
    }
}

static void station_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
        s_connecting = true; /* Link associated, DHCP still required. */
        ESP_LOGI(TAG, "Associated; waiting for DHCP");
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        s_ip[0] = 0;
        s_disconnects++;
        const wifi_event_sta_disconnected_t *info = (const wifi_event_sta_disconnected_t *)data;
        s_last_reason = info ? info->reason : 0;
        ESP_LOGW(TAG, "STA disconnected reason=%lu, count=%lu",
                 (unsigned long)s_last_reason, (unsigned long)s_disconnects);
        if (s_initialized && !s_reconfiguring) try_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_STOP) {
        s_connected = false;
        s_connecting = false;
        s_ip[0] = 0;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) {
        s_connected = false;
        s_ip[0] = 0;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *got = (const ip_event_got_ip_t *)data;
        if (got) snprintf(s_ip, sizeof(s_ip), IPSTR, IP2STR(&got->ip_info.ip));
        s_connected = true;
        s_connecting = false;
        wifi_ap_record_t ap = {0};
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) s_rssi = ap.rssi;
        ESP_LOGI(TAG, "STA DHCP IPv4=%s RSSI=%d dBm", s_ip, (int)s_rssi);
    }
}

static esp_err_t register_station_events(void)
{
    if (s_initialized) return ESP_OK;
    if (!esp_netif_create_default_wifi_sta()) return ESP_FAIL;
    esp_err_t err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, station_event, NULL);
    if (err != ESP_OK) return err;
    err = esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, station_event, NULL);
    if (err != ESP_OK) return err;
    err = esp_event_handler_register(IP_EVENT, IP_EVENT_STA_LOST_IP, station_event, NULL);
    return err;
}

esp_err_t wifi_station_start_apsta(void)
{
    if (s_initialized) return ESP_OK;
    esp_err_t err = register_station_events();
    if (err != ESP_OK) return err;
    /* Called AFTER the existing SoftAP has started, BEFORE USB reception.
     * Do NOT reinitialize the esp-hosted Wi-Fi driver or stop the AP. */
    err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (err != ESP_OK) return err;
    s_initialized = true;
    wifi_config_t cfg;
    if (!read_credentials(&cfg)) {
        ESP_LOGI(TAG, "AP+STA ready. Save test credentials and select Test Wi-Fi.");
        return ESP_OK;
    }
    err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    memset(&cfg, 0, sizeof(cfg));
    if (err == ESP_OK) {
        s_attempts = 0;
        try_connect();
    }
    return err;
}

esp_err_t wifi_station_start(void)
{
#ifdef CONFIG_ADSBIN_REMOTE_ENABLE
    if (s_initialized) return ESP_OK;
    esp_err_t err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    err = register_station_events();
    if (err != ESP_OK) return err;
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    if ((err = esp_wifi_init(&init)) != ESP_OK) return err;
    if ((err = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) return err;
    wifi_config_t cfg;
    if (!read_credentials(&cfg)) return ESP_ERR_INVALID_ARG;
    if ((err = esp_wifi_set_config(WIFI_IF_STA, &cfg)) != ESP_OK) {
        memset(&cfg, 0, sizeof(cfg)); return err;
    }
    memset(&cfg, 0, sizeof(cfg));
    s_initialized = true;
    err = esp_wifi_start(); /* STA_START event may arrive; connect explicitly too. */
    if (err == ESP_OK) { s_attempts = 0; try_connect(); }
    return err;
#else
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

static void station_test_worker(void *arg)
{
    (void)arg;
    wifi_config_t cfg;
    if (!read_credentials(&cfg)) {
        ESP_LOGW(TAG, "Test rejected: no Wi-Fi SSID saved");
    } else {
        s_reconfiguring = true;
        s_connecting = true;
        s_connected = false;
        s_ip[0] = 0;
        s_attempts = 0;
        (void)esp_wifi_disconnect();
        esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
        memset(&cfg, 0, sizeof(cfg));
        s_reconfiguring = false;
        if (err == ESP_OK) try_connect();
        else {
            s_connecting = false;
            ESP_LOGW(TAG, "STA credentials apply failed: %s", esp_err_to_name(err));
        }
    }
    s_test_running = false;
    vTaskDelete(NULL);
}

esp_err_t wifi_station_request_test(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    if (s_test_running) return ESP_ERR_INVALID_STATE;
    s_test_running = true;
    if (xTaskCreatePinnedToCore(station_test_worker, "wifi_test", 4096, NULL, 4,
                                NULL, 1) != pdPASS) {
        s_test_running = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

bool wifi_station_is_connected(void) { return s_connected; }

void wifi_station_get_snapshot(wifi_station_snapshot_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->initialized = s_initialized;
    out->connected = s_connected;
    out->connecting = s_connecting || s_test_running;
    out->disconnects = s_disconnects;
    out->last_reason = s_last_reason;
    out->attempts = s_attempts;
    memcpy(out->ip, s_ip, sizeof(out->ip));
    out->rssi = s_rssi;
}
