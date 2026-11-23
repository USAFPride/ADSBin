/* ADSBin Wi-Fi station and AP+STA bench test over hosted ESP32-C6.
 * USB/DSP never call this component. The SoftAP remains available as a
 * recovery path while a test station connection is attempted.
 *
 * BENCH SECURITY: credentials use the reversible development vault; HTTP
 * over the open AP does not protect credentials in transit.
 */
#include "wifi_station.h"
#include "device_security.h"
#include "esp_timer.h"
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
#include "freertos/semphr.h"

static const char *TAG = "wifi_station";
static volatile bool s_initialized;
static volatile bool s_connected;
static volatile bool s_connecting;
static volatile bool s_test_running;
static volatile bool s_reconfiguring;
static volatile int s_rssi;
static volatile uint32_t s_disconnects, s_last_reason, s_attempts;
static char s_ip[16];
static volatile bool s_credentials_ready;
static volatile uint32_t s_last_try_ms;
static volatile uint32_t s_consecutive_attempts;
static volatile bool s_retry_task_started;
static volatile bool s_scan_busy;
static volatile bool s_provision_busy;
static portMUX_TYPE s_scan_lock = portMUX_INITIALIZER_UNLOCKED;
static wifi_station_scan_t s_scan={0};
static wifi_station_provision_t s_provision={.state=WIFI_PROVISION_IDLE};
static char s_candidate_ssid[33], s_candidate_pass[64];
static void provision_status(wifi_station_provision_state_t state,const char *message) {
    portENTER_CRITICAL(&s_scan_lock);
    s_provision.state=state;
    snprintf(s_provision.message,sizeof(s_provision.message),"%s",message?message:"");
    portEXIT_CRITICAL(&s_scan_lock);
}

static bool read_credentials(wifi_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    if (!device_security_ready() || !device_security_configured()) return false;
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
        if (device_security_get_secret("wifi_pass", pass, sizeof(pass)) == ESP_OK && pass[0]) {
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
    if (!s_credentials_ready || device_security_reset_pending()) return;
    s_attempts++;
    s_last_try_ms = (uint32_t)(esp_timer_get_time()/1000);
    if(s_consecutive_attempts<1000) s_consecutive_attempts++;
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
        s_connecting = false;
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_STOP) {
        s_connected = false;
        s_connecting = false;
        s_ip[0] = 0;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) {
        s_connected = false;
        s_ip[0] = 0;
        s_connecting = false;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *got = (const ip_event_got_ip_t *)data;
        if (got) snprintf(s_ip, sizeof(s_ip), IPSTR, IP2STR(&got->ip_info.ip));
        s_connected = true;
        s_connecting = false;
        s_consecutive_attempts=0;
        wifi_ap_record_t ap = {0};
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) s_rssi = ap.rssi;
        ESP_LOGI(TAG, "STA DHCP IPv4=%s RSSI=%d dBm", s_ip, (int)s_rssi);
    }
}

static void retry_worker(void *arg) {
    (void)arg;
    for (;;) {
        uint32_t now=(uint32_t)(esp_timer_get_time()/1000);
        uint32_t failures=s_consecutive_attempts;
        uint32_t wait_ms=s_connecting?30000u:(failures<=1?5000u:failures<=3?15000u:failures<=6?30000u:60000u);
        if(s_initialized && s_credentials_ready && !s_connected &&
           !s_test_running && !s_reconfiguring && !s_scan_busy && !device_security_reset_pending() &&
           (uint32_t)(now-s_last_try_ms) >= wait_ms) {
            /* A stalled DHCP/association attempt is also recoverable. */
            if(s_connecting) {
                (void)esp_wifi_disconnect(); s_connecting=false;
                vTaskDelay(pdMS_TO_TICKS(500));
            }
            if(!s_test_running && !s_reconfiguring && !device_security_reset_pending() && !s_connected) try_connect();
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
static esp_err_t start_retry_worker(void) {
    if(s_retry_task_started) return ESP_OK;
    if(xTaskCreatePinnedToCore(retry_worker,"wifi_retry",4096,NULL,4,NULL,1)!=pdPASS) return ESP_ERR_NO_MEM;
    s_retry_task_started=true;
    return ESP_OK;
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
    err=start_retry_worker();
    if(err!=ESP_OK) return err;
    wifi_config_t cfg;
    if (!read_credentials(&cfg)) {
        ESP_LOGI(TAG, "AP+STA ready. Save test credentials and select Test Wi-Fi.");
        return ESP_OK;
    }
    err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    memset(&cfg, 0, sizeof(cfg));
    if (err == ESP_OK) {
        s_credentials_ready = true;
        s_attempts = 0; s_consecutive_attempts=0;
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
    if ((err = esp_wifi_set_storage(WIFI_STORAGE_RAM)) != ESP_OK) return err;
    if ((err = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) return err;
    wifi_config_t cfg;
    if (!read_credentials(&cfg)) return ESP_ERR_INVALID_ARG;
    if ((err = esp_wifi_set_config(WIFI_IF_STA, &cfg)) != ESP_OK) {
        memset(&cfg, 0, sizeof(cfg)); return err;
    }
    memset(&cfg, 0, sizeof(cfg));
    s_initialized = true;
    err = esp_wifi_start(); /* STA_START event may arrive; connect explicitly too. */
    if (err == ESP_OK) { s_credentials_ready=true; err=start_retry_worker(); if(err==ESP_OK) { s_attempts = 0; s_consecutive_attempts=0; try_connect(); } }
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
        s_attempts = 0; s_consecutive_attempts=0;
        (void)esp_wifi_disconnect();
        esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
        memset(&cfg, 0, sizeof(cfg));
        s_reconfiguring = false;
        if (err == ESP_OK) { s_credentials_ready=true; try_connect(); }
        else {
            s_credentials_ready=false;
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

/* Wi-Fi scan is an asynchronous worker: never scan on an HTTP or DSP task. */
static void scan_worker(void *arg) {
    (void)arg;
    wifi_station_scan_t result={0};
    result.error=esp_wifi_scan_start(NULL,true);
    if(result.error==ESP_OK) {
        uint16_t count=0;
        result.error=esp_wifi_scan_get_ap_num(&count);
        if(result.error==ESP_OK) {
            if(count>20)count=20;
            wifi_ap_record_t records[20]={0};
            result.error=esp_wifi_scan_get_ap_records(&count,records);
            if(result.error==ESP_OK) {
                for(uint16_t i=0;i<count;i++) {
                    if(!records[i].ssid[0]) continue; /* hidden SSIDs can still be entered manually */
                    bool duplicate=false;
                    for(size_t j=0;j<result.count;j++) {
                        if(strcmp(result.aps[j].ssid,(const char*)records[i].ssid)==0) {
                            if(records[i].rssi>result.aps[j].rssi) {
                                result.aps[j].rssi=records[i].rssi;
                                result.aps[j].authmode=(uint8_t)records[i].authmode;
                            }
                            duplicate=true;break;
                        }
                    }
                    if(duplicate)continue;
                    wifi_station_ap_t *ap=&result.aps[result.count++];
                    snprintf(ap->ssid,sizeof(ap->ssid),"%.*s",32,(const char*)records[i].ssid);
                    ap->rssi=records[i].rssi;
                    ap->authmode=(uint8_t)records[i].authmode;
                }
            }
        }
    }
    result.complete=true;result.scanning=false;
    portENTER_CRITICAL(&s_scan_lock);
    s_scan=result;
    s_scan_busy=false;
    portEXIT_CRITICAL(&s_scan_lock);
    ESP_LOGI(TAG,"Scan completed: %u SSIDs, result=%s",(unsigned)result.count,esp_err_to_name(result.error));
    vTaskDelete(NULL);
}
esp_err_t wifi_station_scan_request(void) {
    if(!s_initialized || s_test_running || s_reconfiguring || s_provision_busy || s_scan_busy ||
       device_security_reset_pending())return ESP_ERR_INVALID_STATE;
    portENTER_CRITICAL(&s_scan_lock);
    s_scan_busy=true;
    memset(&s_scan,0,sizeof(s_scan));s_scan.scanning=true;
    portEXIT_CRITICAL(&s_scan_lock);
    if(xTaskCreatePinnedToCore(scan_worker,"wifi_scan",6144,NULL,4,NULL,1)!=pdPASS) {
        portENTER_CRITICAL(&s_scan_lock);
        s_scan_busy=false;s_scan.scanning=false;s_scan.complete=true;s_scan.error=ESP_ERR_NO_MEM;
        portEXIT_CRITICAL(&s_scan_lock);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
void wifi_station_scan_snapshot(wifi_station_scan_t *out) {
    if(!out)return;
    portENTER_CRITICAL(&s_scan_lock);
    *out=s_scan;
    portEXIT_CRITICAL(&s_scan_lock);
}

/* Validate candidate on the live STA interface BEFORE committing to NVS.
 * The AP remains open throughout, including unsuccessful attempts.
 * The saved Wi-Fi network is restored if validation or persistence fails. */
static void provision_worker(void *arg) {
    (void)arg;
    wifi_config_t previous={0},candidate={0};
    bool had_previous=esp_wifi_get_config(WIFI_IF_STA,&previous)==ESP_OK;
    snprintf((char*)candidate.sta.ssid,sizeof(candidate.sta.ssid),"%s",s_candidate_ssid);
    snprintf((char*)candidate.sta.password,sizeof(candidate.sta.password),"%s",s_candidate_pass);
    candidate.sta.threshold.authmode=s_candidate_pass[0]?WIFI_AUTH_WPA2_PSK:WIFI_AUTH_OPEN;
    s_reconfiguring=true;
    s_connecting=false;
    (void)esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(350));
    esp_err_t e=esp_wifi_set_config(WIFI_IF_STA,&candidate);
    if(e==ESP_OK) {
        s_connected=false;s_ip[0]=0;
        e=esp_wifi_connect();
        if(e==ESP_OK) {
            bool connected=false;
            for(unsigned i=0;i<125;i++) {
                if(s_connected) {connected=true;break;}
                vTaskDelay(pdMS_TO_TICKS(200));
            }
            if(!connected)e=ESP_ERR_TIMEOUT;
        }
    }
    if(e==ESP_OK) {
        /* Commit the SSID and encrypted secret only after successful DHCP. */
        nvs_handle_t n;
        e=nvs_open("web_cfg",NVS_READWRITE,&n);
        if(e==ESP_OK) {
            e=device_security_set_secret("wifi_pass",s_candidate_pass);
            if(e==ESP_OK)e=nvs_set_str(n,"wifi_ssid",s_candidate_ssid);
            if(e==ESP_OK)e=nvs_commit(n);
            nvs_close(n);
        }
    }
    if(e!=ESP_OK) {
        ESP_LOGW(TAG,"Candidate Wi-Fi failed (%s); restoring previous station",esp_err_to_name(e));
        (void)esp_wifi_disconnect();
        if(had_previous) {
            (void)esp_wifi_set_config(WIFI_IF_STA,&previous);
            s_credentials_ready=previous.sta.ssid[0]!=0;
            if(s_credentials_ready)(void)esp_wifi_connect();
        } else {
            s_credentials_ready=false;
        }
        provision_status(WIFI_PROVISION_FAILED,"Connection failed. Previous network restored.");
    } else {
        s_credentials_ready=true;s_consecutive_attempts=0;
        provision_status(WIFI_PROVISION_SAVED,"Connected. Credentials securely saved.");
        ESP_LOGI(TAG,"New upstream Wi-Fi verified and saved");
    }
    memset(&previous,0,sizeof(previous));
    memset(&candidate,0,sizeof(candidate));
    memset(s_candidate_pass,0,sizeof(s_candidate_pass));
    s_reconfiguring=false;
    s_provision_busy=false;
    vTaskDelete(NULL);
}
esp_err_t wifi_station_provision(const char *ssid,const char *password) {
    if(!ssid || !password || !ssid[0] || strlen(ssid)>32 || strlen(password)>63 ||
       (password[0] && strlen(password)<8))return ESP_ERR_INVALID_ARG;
    if(!s_initialized || !device_security_configured() || s_scan_busy || s_provision_busy ||
       s_test_running || s_reconfiguring || device_security_reset_pending())
        return ESP_ERR_INVALID_STATE;
    s_provision_busy=true;
    snprintf(s_candidate_ssid,sizeof(s_candidate_ssid),"%s",ssid);
    snprintf(s_candidate_pass,sizeof(s_candidate_pass),"%s",password);
    provision_status(WIFI_PROVISION_CONNECTING,"Connecting to selected network...");
    if(xTaskCreatePinnedToCore(provision_worker,"wifi_provision",6144,NULL,4,NULL,1)!=pdPASS) {
        memset(s_candidate_pass,0,sizeof(s_candidate_pass));
        s_provision_busy=false;
        provision_status(WIFI_PROVISION_FAILED,"Unable to start Wi-Fi provisioning.");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
void wifi_station_provision_snapshot(wifi_station_provision_t *out) {
    if(!out)return;
    portENTER_CRITICAL(&s_scan_lock);
    *out=s_provision;
    portEXIT_CRITICAL(&s_scan_lock);
}
