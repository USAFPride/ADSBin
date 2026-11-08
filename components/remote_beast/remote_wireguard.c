/* Experimental ESP32-P4 / hosted-C6 WireGuard integration.
 *
 * The upstream trombik/esp_wireguard implementation is alpha and does not
 * guarantee compatibility with ESP-IDF 6.0.1 on an ESP32-P4. This source is
 * intentionally compiled only when CONFIG_ADSBIN_REMOTE_WIREGUARD is enabled.
 */
#include "remote_wireguard.h"
#include "wifi_station.h"
#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef CONFIG_ADSBIN_REMOTE_WIREGUARD

#include <time.h>
#include <string.h>
#include "esp_netif_sntp.h"
#include "esp_wireguard.h"
#include "lwip/netif.h"

static const char *TAG = "remote_wg";
static wireguard_ctx_t s_ctx;
static wireguard_config_t s_cfg;
static volatile bool s_tunnel_ready;
static bool s_ntp_started;

static void wg_monitor_task(void *arg)
{
    (void)arg;
    for (;;) {
        if (!wifi_station_is_connected()) {
            s_tunnel_ready = false;
            vTaskDelay(pdMS_TO_TICKS(1500));
            continue;
        }

        /* WireGuard's replay protection depends on UTC. Clock synchronization
         * needs to be established using the ordinary Wi-Fi route first. */
        if (!s_ntp_started) {
            esp_sntp_config_t ntp = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
            if (esp_netif_sntp_init(&ntp) == ESP_OK) {
                s_ntp_started = true;
            } else {
                ESP_LOGW(TAG, "SNTP initialization failed");
            }
        }
        if (time(NULL) < 1700000000) {
            vTaskDelay(pdMS_TO_TICKS(1500));
            continue;
        }

        /* Context and configuration MUST outlive the VPN session: the library
         * stores a pointer to s_cfg, not a copy of a stack-local struct. */
        memset(&s_ctx, 0, sizeof(s_ctx));
        esp_err_t err = esp_wireguard_init(&s_cfg, &s_ctx);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "WireGuard init: %s", esp_err_to_name(err));
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        err = esp_wireguard_connect(&s_ctx);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "WireGuard connect: %s", esp_err_to_name(err));
            /* Upstream disconnect() may assume a successfully created netif.
             * Do not call it on an unsuccessful connect until that behavior is
             * validated on ESP-IDF 6. */
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        /* esp_wireguard_connect() only begins negotiation. Never send Beast
         * frames until a real handshake and VPN default route are established. */
        bool route_installed = false;
        int elapsed = 0;
        for (;;) {
            if (!wifi_station_is_connected()) break;
            bool peer = (esp_wireguardif_peer_is_up(&s_ctx) == ESP_OK);
            if (peer && !route_installed) {
                if (esp_wireguard_set_default(&s_ctx) == ESP_OK) {
                    route_installed = true;
                    s_tunnel_ready = true;
                    ESP_LOGI(TAG, "VPN handshake complete; VPN route installed");
                }
            } else if (route_installed && !peer) {
                ESP_LOGW(TAG, "VPN peer lost; closing remote feed");
                break;
            }
            if (!route_installed && ++elapsed >= 20) {
                ESP_LOGW(TAG, "WireGuard handshake timed out");
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(1000));
        }

        s_tunnel_ready = false;
        /* Tear down the interface and restore its saved default route. */
        (void)esp_wireguard_disconnect(&s_ctx);
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

esp_err_t remote_wireguard_start(void)
{
    if (CONFIG_ADSBIN_WG_PRIVATE_KEY[0] == '\0' ||
        CONFIG_ADSBIN_WG_PEER_PUBLIC_KEY[0] == '\0' ||
        CONFIG_ADSBIN_WG_ENDPOINT[0] == '\0') {
        ESP_LOGE(TAG, "WireGuard keys/endpoint not provisioned");
        return ESP_ERR_INVALID_ARG;
    }
    wireguard_config_t cfg = ESP_WIREGUARD_CONFIG_DEFAULT();
    cfg.private_key = CONFIG_ADSBIN_WG_PRIVATE_KEY;
    cfg.public_key = CONFIG_ADSBIN_WG_PEER_PUBLIC_KEY;
    cfg.address = CONFIG_ADSBIN_WG_LOCAL_IP;
    cfg.netmask = "255.255.255.255";
    cfg.endpoint = CONFIG_ADSBIN_WG_ENDPOINT;
    cfg.port = CONFIG_ADSBIN_WG_PORT;
    cfg.persistent_keepalive = 25;
    s_cfg = cfg;
    return xTaskCreatePinnedToCore(wg_monitor_task, "remote_wg", 8192, NULL, 4,
                                   NULL, 1) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
bool remote_wireguard_peer_up(void)
{
    /* The sender must additionally bind to its tunnel source address. */
    return s_tunnel_ready && wifi_station_is_connected() &&
        s_ctx.netif != NULL &&
        (esp_wireguardif_peer_is_up(&s_ctx) == ESP_OK);
}

#else

esp_err_t remote_wireguard_start(void) { return ESP_ERR_NOT_SUPPORTED; }
bool remote_wireguard_peer_up(void) { return false; }

#endif
