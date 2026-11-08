/* Prototype WireGuard adapter.
 * Requires the separately installed esp_wireguard component.
 * WARNING: trombik/esp_wireguard has not been validated on ESP32-P4/IDF 6.0.
 */
#include "remote_wireguard.h"
#include "wifi_station.h"
#include "sdkconfig.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <time.h>
#ifdef CONFIG_ADSBIN_REMOTE_WIREGUARD
#include "esp_wireguard.h"
static const char *TAG = "remote_wg";
static wireguard_ctx_t s_ctx;
static volatile bool s_running;
static void wg_task(void *arg)
{
    (void)arg;
    for (;;) {
        if (!wifi_station_is_connected() || time(NULL) < 1700000000) {
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
        wireguard_config_t cfg = ESP_WIREGUARD_CONFIG_DEFAULT();
        cfg.private_key = CONFIG_ADSBIN_WG_PRIVATE_KEY;
        cfg.public_key = CONFIG_ADSBIN_WG_PEER_PUBLIC_KEY;
        cfg.allowed_ip = CONFIG_ADSBIN_WG_LOCAL_IP;
        cfg.allowed_ip_mask = "255.255.255.255";
        cfg.endpoint = CONFIG_ADSBIN_WG_ENDPOINT;
        cfg.port = CONFIG_ADSBIN_WG_PORT;
        cfg.persistent_keepalive = 25;
        if (esp_wireguard_init(&cfg, &s_ctx) == ESP_OK &&
            esp_wireguard_connect(&s_ctx) == ESP_OK) {
            s_running = true;
            ESP_LOGI(TAG, "WireGuard initiated");
            while (wifi_station_is_connected()) vTaskDelay(pdMS_TO_TICKS(2000));
        }
        s_running = false;
        esp_wireguard_disconnect(&s_ctx);
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}
esp_err_t remote_wireguard_start(void)
{
    if (!CONFIG_ADSBIN_WG_PRIVATE_KEY[0] || !CONFIG_ADSBIN_WG_PEER_PUBLIC_KEY[0]
        || !CONFIG_ADSBIN_WG_ENDPOINT[0]) return ESP_ERR_INVALID_ARG;
    return xTaskCreatePinnedToCore(wg_task, "remote_wg", 7168, NULL, 4, NULL, 1) == pdPASS
        ? ESP_OK : ESP_ERR_NO_MEM;
}
bool remote_wireguard_peer_up(void)
{
    return s_running && wifi_station_is_connected() &&
        esp_wireguardif_peer_is_up(&s_ctx) == ESP_OK;
}
#else
esp_err_t remote_wireguard_start(void) { return ESP_ERR_NOT_SUPPORTED; }
bool remote_wireguard_peer_up(void) { return false; }
#endif
