/* ADSBin v1 embedded status web server.
 * Deliberately READ-ONLY: credentials and private keys cannot be submitted over
 * plaintext HTTP. All reads run on networking tasks, away from the USB/DSP path.
 */
#include "web_ui.h"
#include "web_auth.h"
#include "device_security.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include "esp_http_server.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "cJSON.h"
#include <string.h>
#include "usb_rtlsdr.h"
#include "demod1090.h"
#include "status.h"
#include "wifi_link.h"
#include "wifi_station.h"
#include "remote_beast.h"

static const char *TAG = "web_ui";
static httpd_handle_t s_server = NULL;
static size_t (*s_aircraft_count)(void) = NULL;
static traffic_handle_t s_traffic = NULL;
#ifdef CONFIG_ADSBIN_WEB_HTTP_CONFIG
extern esp_err_t web_ui_http_config_register(httpd_handle_t server);
#endif
extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[] asm("_binary_index_html_end");

static esp_err_t page_get(httpd_req_t *req)
{
    if(!web_auth_local(req,false)) { httpd_resp_set_status(req,"403 Forbidden"); return httpd_resp_sendstr(req,"Local management only"); }
    web_auth_headers(req);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, index_html_start, (int)(index_html_end - index_html_start));
}

esp_err_t web_ui_status_get(httpd_req_t *req)
{
    if(!web_auth_require(req)) return ESP_OK;
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
       "\"beast_dropped\":%lu,\"beast_attempts\":%lu,\"beast_failures\":%lu,"
       "\"beast_reconnects\":%lu,\"beast_discarded_offline\":%lu,"
       "\"beast_last_send_uptime_s\":%lu,\"beast_queued\":%lu,\"beast_last_socket_error\":%d}",
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
       (unsigned long)beast.connect_attempts, (unsigned long)beast.failures,
       (unsigned long)beast.reconnects, (unsigned long)beast.discarded_offline,
       (unsigned long)beast.last_send_uptime_s, (unsigned long)beast.queued,
       beast.last_socket_error);
    if (n < 0 || (size_t)n >= sizeof(out)) {
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Snapshot overflow");
    }
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    return httpd_resp_send(req, out, n);
}


/* Snapshot only lightweight identifiers. This callback executes under the
 * traffic lock, so it must never allocate, log, or perform network I/O. */
#define WEB_AIRCRAFT_LIMIT 64
typedef struct {
    uint32_t icao;
    bool has_callsign;
    char callsign[ADSB_CALLSIGN_LEN];
} web_aircraft_t;
typedef struct {
    web_aircraft_t items[WEB_AIRCRAFT_LIMIT];
    size_t count;
} web_aircraft_list_t;
static bool collect_aircraft(const traffic_target_t *target, void *ctx)
{
    web_aircraft_list_t *list=(web_aircraft_list_t *)ctx;
    if(list->count>=WEB_AIRCRAFT_LIMIT) return false;
    web_aircraft_t *item=&list->items[list->count++];
    item->icao=target->icao & 0x00FFFFFFu;
    item->has_callsign=target->has_callsign;
    memcpy(item->callsign,target->callsign,sizeof(item->callsign));
    item->callsign[sizeof(item->callsign)-1]='\\0';
    return list->count<WEB_AIRCRAFT_LIMIT;
}
static esp_err_t aircraft_get(httpd_req_t *req)
{
    if(!web_auth_require(req))return ESP_OK;
    if(!s_traffic)return httpd_resp_send_err(req,HTTPD_503_SERVICE_UNAVAILABLE,"Traffic unavailable");
    web_aircraft_list_t *list=calloc(1,sizeof(*list));
    if(!list)return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"Out of memory");
    size_t total=traffic_count(s_traffic);
    esp_err_t err=traffic_iterate(s_traffic,collect_aircraft,list,NULL);
    if(err!=ESP_OK){free(list);return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"Traffic snapshot failed");}
    cJSON *root=cJSON_CreateObject();
    cJSON *planes=root?cJSON_AddArrayToObject(root,"aircraft"):NULL;
    if(!planes){cJSON_Delete(root);free(list);return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"Out of memory");}
    cJSON_AddNumberToObject(root,"total",(double)total);
    cJSON_AddBoolToObject(root,"truncated",total>list->count);
    for(size_t i=0;i<list->count;i++){
        const web_aircraft_t *item=&list->items[i];
        cJSON *entry=cJSON_CreateObject();
        if(!entry){err=ESP_ERR_NO_MEM;break;}
        char icao[7];
        snprintf(icao,sizeof(icao),"%06lX",(unsigned long)item->icao);
        cJSON_AddStringToObject(entry,"icao",icao);
        /* The identification field originates in RF data. Accept only the
         * expected flight-id alphabet to avoid rendering control characters. */
        char ident[ADSB_CALLSIGN_LEN]={0};
        if(item->has_callsign){
            for(unsigned j=0;j<ADSB_CALLSIGN_LEN-1 && item->callsign[j];j++){
                char c=item->callsign[j];
                if((c>='A'&&c<='Z')||(c>='0'&&c<='9')||c==' '||c=='-')
                    ident[j]=c;
                else
                    ident[j]=' ';
            }
        }
        cJSON_AddStringToObject(entry,"callsign",ident);
        cJSON_AddItemToArray(planes,entry);
    }
    free(list);
    char *json=err==ESP_OK?cJSON_PrintUnformatted(root):NULL;
    cJSON_Delete(root);
    if(!json)return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"JSON generation failed");
    httpd_resp_set_type(req,"application/json; charset=utf-8");
    httpd_resp_set_hdr(req,"Cache-Control","no-store");
    httpd_resp_set_hdr(req,"X-Content-Type-Options","nosniff");
    esp_err_t sent=httpd_resp_sendstr(req,json);
    free(json);
    return sent;
}

esp_err_t web_ui_start(size_t (*aircraft_count)(void), traffic_handle_t traffic)
{
    if (s_server) return ESP_OK;
    if (!device_security_ready()) return ESP_ERR_INVALID_STATE;
    s_aircraft_count = aircraft_count;
    s_traffic = traffic;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 12288;
    config.max_uri_handlers = 16;
    config.recv_wait_timeout = 5;
    config.send_wait_timeout = 5;
    config.lru_purge_enable = true;
    esp_err_t err = httpd_start(&s_server, &config);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "HTTP server start failed: %s", esp_err_to_name(err));
        return err;
    }
    const httpd_uri_t root = {.uri="/", .method=HTTP_GET, .handler=page_get};
    const httpd_uri_t api = {.uri="/api/status", .method=HTTP_GET, .handler=web_ui_status_get};
    const httpd_uri_t aircraft = {.uri="/api/aircraft", .method=HTTP_GET, .handler=aircraft_get};
    err = httpd_register_uri_handler(s_server, &root);
    if (err == ESP_OK) err = httpd_register_uri_handler(s_server, &api);
    if (err == ESP_OK) err = httpd_register_uri_handler(s_server, &aircraft);
    if (err != ESP_OK) {
        httpd_stop(s_server);
        s_server = NULL;
        ESP_LOGE(TAG, "HTTP route setup failed: %s", esp_err_to_name(err));
        return err;
    }
    err=web_auth_register(s_server);
    if(err!=ESP_OK) { httpd_stop(s_server); s_server=NULL; return err; }
    ESP_LOGI(TAG, "Authenticated local receiver dashboard on HTTP port 80");
#ifdef CONFIG_ADSBIN_WEB_HTTP_CONFIG
    esp_err_t secure_err=web_ui_http_config_register(s_server);
    if(secure_err!=ESP_OK) { httpd_stop(s_server); s_server=NULL; return secure_err; }
#endif
    return ESP_OK;
}
