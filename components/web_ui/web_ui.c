/* ADSBin v1 embedded status web server.
 * Deliberately READ-ONLY: credentials and private keys cannot be submitted over
 * plaintext HTTP. All reads run on networking tasks, away from the USB/DSP path.
 */
#include "web_ui.h"
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include "esp_http_server.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "usb_rtlsdr.h"
#include "demod1090.h"
#include "status.h"
#include "wifi_link.h"
#include "wifi_station.h"
#include "remote_beast.h"

static const char *TAG = "web_ui";
static httpd_handle_t s_server = NULL;
static size_t (*s_aircraft_count)(void) = NULL;
#ifdef CONFIG_ADSBIN_WEB_HTTP_CONFIG
extern esp_err_t web_ui_http_config_register(httpd_handle_t server);
#endif
extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[] asm("_binary_index_html_end");

static esp_err_t page_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, index_html_start, (int)(index_html_end - index_html_start));
}

esp_err_t web_ui_status_get(httpd_req_t *req)
{
    usb_rtlsdr_status_t receiver = {0};
    usb_rtlsdr_stats_t usb = {0};
    demod1090_stats_t demod = {0};
    bool present = usb_rtlsdr_get_status(&receiver) == ESP_OK && receiver.device_present;
    (void)usb_rtlsdr_get_stats(&usb);
    demod1090_get_stats(&demod);
    float temp_c = NAN;
    (void)status_get_temperature(&temp_c);
    char temp_json[28];
    if (isfinite(temp_c)) {
        snprintf(temp_json, sizeof(temp_json), "%.1f", (double)temp_c);
    } else {
        snprintf(temp_json, sizeof(temp_json), "null");
    }

    wifi_station_snapshot_t station = {0};
    wifi_station_get_snapshot(&station);
    remote_beast_stats_t beast = {0};
    remote_beast_get_stats(&beast);
    char out[1100];
    int n = snprintf(out, sizeof(out),
       "{\"uptime_s\":%llu,\"aircraft\":%u,\"sample_sps\":%lu,"
       "\"usb_present\":%s,\"streaming\":%s,"
       "\"usb_drops\":%llu,\"dsp_drops\":%llu,"
       "\"usb_stalls\":%lu,\"usb_resets\":%lu,"
       "\"usb_bytes\":%llu,\"usb_urbs\":%llu,"
       "\"preambles\":%llu,\"frames\":%llu,"
       "\"temperature_c\":%s,\"access_point\":%s,\"station_connected\":%s,"
       "\"station_connecting\":%s,\"station_ip\":\"%s\",\"station_rssi\":%d,"
       "\"wifi_attempts\":%lu,\"wifi_disconnects\":%lu,\"wifi_last_reason\":%lu,"
       "\"beast_enabled\":%s,\"beast_connected\":%s,\"beast_sent\":%lu,"
       "\"beast_dropped\":%lu,\"beast_attempts\":%lu,\"beast_failures\":%lu}",
       (unsigned long long)(esp_timer_get_time() / 1000000),
       (unsigned)(s_aircraft_count ? s_aircraft_count() : 0u),
       (unsigned long)usb.measured_sps,
       present ? "true" : "false",
       receiver.streaming ? "true" : "false",
       (unsigned long long)usb.overflow_drops,
       (unsigned long long)demod.iq_blocks_dropped,
       (unsigned long)usb.usb_stall_count,
       (unsigned long)usb.reset_count,
       (unsigned long long)usb.total_bytes,
       (unsigned long long)usb.urb_completions,
       (unsigned long long)demod.preambles_detected,
       (unsigned long long)demod.frames_emitted,
       temp_json,
       wifi_link_is_up() ? "true" : "false",
       station.connected ? "true" : "false",
       station.connecting ? "true" : "false",
       station.ip, station.rssi,
       (unsigned long)station.attempts,
       (unsigned long)station.disconnects,
       (unsigned long)station.last_reason,
       beast.enabled ? "true" : "false", beast.connected ? "true" : "false",
       (unsigned long)beast.sent, (unsigned long)beast.dropped,
       (unsigned long)beast.connect_attempts, (unsigned long)beast.failures);
    if (n < 0 || (size_t)n >= sizeof(out)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Snapshot overflow");
    }
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    return httpd_resp_send(req, out, n);
}

esp_err_t web_ui_start(size_t (*aircraft_count)(void))
{
    if (s_server) return ESP_OK;
    s_aircraft_count = aircraft_count;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 6144;
    config.max_uri_handlers = 8;
    config.lru_purge_enable = true;
    esp_err_t err = httpd_start(&s_server, &config);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "HTTP server start failed: %s", esp_err_to_name(err));
        return err;
    }
    const httpd_uri_t root = {.uri="/", .method=HTTP_GET, .handler=page_get};
    const httpd_uri_t api = {.uri="/api/status", .method=HTTP_GET, .handler=web_ui_status_get};
    err = httpd_register_uri_handler(s_server, &root);
    if (err == ESP_OK) err = httpd_register_uri_handler(s_server, &api);
    if (err != ESP_OK) {
        httpd_stop(s_server);
        s_server = NULL;
        ESP_LOGE(TAG, "HTTP route setup failed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "Read-only receiver dashboard available on HTTP port 80");
#ifdef CONFIG_ADSBIN_WEB_HTTP_CONFIG
    esp_err_t secure_err=web_ui_http_config_register(s_server);
    if(secure_err!=ESP_OK)ESP_LOGE(TAG,"HTTP bench configuration unavailable: %s",esp_err_to_name(secure_err));
#endif
    return ESP_OK;
}
