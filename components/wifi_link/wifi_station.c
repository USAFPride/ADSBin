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
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if defined(CONFIG_ADSBIN_REMOTE_ENABLE)
static const char *TAG = "wifi_station";
static volatile bool s_connected = false;
static bool s_started = false;

static void station_event(void *ctx, esp_event_base_t base, int32_t event, void *data)
{
    (void)ctx; (void)data;
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && event == WIFI_EVENT_STA_DISCONNECTED) {
        s_connected = false;
        ESP_LOGW(TAG, "Wi-Fi disconnected; reconnecting");
        esp_wifi_connect();
    } else if (base == IP_EVENT && event == IP_EVENT_STA_GOT_IP) {
        s_connected = true;
        ESP_LOGI(TAG, "Wi-Fi station received IP address");
    }
}

esp_err_t wifi_station_start(void)
{
    if (s_started) return ESP_OK;
    if (CONFIG_ADSBIN_REMOTE_WIFI_SSID[0] == '\0') {
        ESP_LOGE(TAG, "Set remote Wi-Fi SSID in menuconfig");
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
    if ((err = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) return err;
    wifi_config_t cfg = {0};
    strncpy((char *)cfg.sta.ssid, CONFIG_ADSBIN_REMOTE_WIFI_SSID, sizeof(cfg.sta.ssid));
    strncpy((char *)cfg.sta.password, CONFIG_ADSBIN_REMOTE_WIFI_PASSWORD, sizeof(cfg.sta.password));
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
