/* Wi-Fi station support for ADSBin remote receivers.
 * Uses the ESP32-C6 hosted Wi-Fi driver on Waveshare ESP32-P4-WIFI6-DEV-KIT.
 * No secrets should be committed via sdkconfig files.
 */
#include "wifi_station.h"
#include <string.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "esp_netif_ip_addr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if defined(CONFIG_ADSBIN_REMOTE_ENABLE)
static const char *TAG = "wifi_station";
static volatile bool s_connected = false;
static bool s_started = false;
static uint32_t s_disconnect_count = 0;

/* Runs in the normal ESP event task, not in the USB or DSP hot path.
 * Only mark the link usable once DHCP has supplied an address. */
static void station_event(void *ctx, esp_event_base_t base, int32_t event, void *data)
{
    (void)ctx;
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_START) {
        esp_err_t err = esp_wifi_connect();
        if (err != ESP_OK) ESP_LOGW(TAG, "Initial connect request failed: %s", esp_err_to_name(err));
    } else if (base == WIFI_EVENT && event == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI(TAG, "Associated with access point; awaiting DHCP");
    } else if (base == WIFI_EVENT && event == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        ++s_disconnect_count;
        const wifi_event_sta_disconnected_t *info = (const wifi_event_sta_disconnected_t *)data;
        unsigned reason = info ? (unsigned)info->reason : 0u;
        ESP_LOGW(TAG, "Disconnected reason=%u count=%lu; requesting reconnect",
                 reason, (unsigned long)s_disconnect_count);
        esp_err_t err = esp_wifi_connect();
        if (err != ESP_OK) ESP_LOGW(TAG, "Reconnect request failed: %s", esp_err_to_name(err));
    } else if (base == WIFI_EVENT && event == WIFI_EVENT_STA_STOP) {
        s_connected = false;
        ESP_LOGW(TAG, "Wi-Fi station stopped");
    } else if (base == IP_EVENT && event == IP_EVENT_STA_LOST_IP) {
        s_connected = false;
        ESP_LOGW(TAG, "Station lost IPv4 address");
    } else if (base == IP_EVENT && event == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *ip = (const ip_event_got_ip_t *)data;
        s_connected = true;
        if (ip) {
            ESP_LOGI(TAG, "DHCP IPv4=" IPSTR " gateway=" IPSTR " mask=" IPSTR,
                     IP2STR(&ip->ip_info.ip), IP2STR(&ip->ip_info.gw),
                     IP2STR(&ip->ip_info.netmask));
        }
        wifi_ap_record_t ap = {0};
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            ESP_LOGI(TAG, "Connected SSID=%s RSSI=%d dBm channel=%u",
                     (const char *)ap.ssid, (int)ap.rssi, (unsigned)ap.primary);
        }
        ESP_LOGI(TAG, "Wi-Fi ready; reconnect count=%lu", (unsigned long)s_disconnect_count);
    }
}

esp_err_t wifi_station_start(void)
{
    if (s_started) return ESP_OK;
    /* Read saved SSID, and bench password if explicitly permitted.
     * Credentials remain in ordinary NVS without encryption: bench only. */
    char station_ssid[33] = CONFIG_ADSBIN_REMOTE_WIFI_SSID;
    char station_password[65] = CONFIG_ADSBIN_REMOTE_WIFI_PASSWORD;
    nvs_handle_t prefs;
    if (nvs_open("web_cfg", NVS_READONLY, &prefs) == ESP_OK) {
        size_t length = sizeof(station_ssid);
        char saved_ssid[33] = {0};
        if (nvs_get_str(prefs, "wifi_ssid", saved_ssid, &length) == ESP_OK &&
            saved_ssid[0] != '\0') {
            memcpy(station_ssid, saved_ssid, sizeof(station_ssid));
        }
#ifdef CONFIG_ADSBIN_BENCH_ALLOW_WIFI_PASSWORD_HTTP
        size_t pw_length = sizeof(station_password);
        char saved_password[65] = {0};
        if (nvs_get_str(prefs, "wifi_pass", saved_password, &pw_length) == ESP_OK &&
            saved_password[0] != '\0') {
            memcpy(station_password, saved_password, sizeof(station_password));
        }
        memset(saved_password, 0, sizeof(saved_password));
#endif
        nvs_close(prefs);
    }
    if (station_ssid[0] == '\0') {
        ESP_LOGE(TAG, "Set remote Wi-Fi SSID in menuconfig or web settings");
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    if (!esp_netif_create_default_wifi_sta()) return ESP_FAIL;
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    if ((err = esp_wifi_init(&init)) != ESP_OK) return err;
    if ((err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, station_event, NULL)) != ESP_OK) return err;
    if ((err = esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, station_event, NULL)) != ESP_OK) return err;
    if ((err = esp_event_handler_register(IP_EVENT, IP_EVENT_STA_LOST_IP, station_event, NULL)) != ESP_OK) return err;
    if ((err = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) return err;
    wifi_config_t cfg = {0};
    /* Copy fixed-length credentials without logging them. */
    size_t ssid_len = strnlen(station_ssid, sizeof(cfg.sta.ssid));
    size_t password_len = strnlen(station_password, sizeof(cfg.sta.password));
    memcpy(cfg.sta.ssid, station_ssid, ssid_len);
    memcpy(cfg.sta.password, station_password, password_len);
    memset(station_password, 0, sizeof(station_password));
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    if ((err = esp_wifi_set_config(WIFI_IF_STA, &cfg)) != ESP_OK) return err;
    if ((err = esp_wifi_start()) != ESP_OK) return err;
    s_started = true;
    ESP_LOGI(TAG, "Remote Wi-Fi station started");
    return ESP_OK;
}

bool wifi_station_is_connected(void) { return s_connected; }
#else
esp_err_t wifi_station_start(void) { return ESP_ERR_NOT_SUPPORTED; }
bool wifi_station_is_connected(void) { return false; }
#endif
