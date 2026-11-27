#include "remote_beast.h"
#include "device_security.h"
#include "wifi_station.h"
#include "remote_wireguard.h"
#include "sdkconfig.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/tcp.h"
#include "nvs.h"
#include "esp_timer.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#if defined(CONFIG_ADSBIN_REMOTE_ENABLE) || defined(CONFIG_ADSBIN_WEB_HTTP_CONFIG)
static const char *TAG = "remote_beast";
static QueueHandle_t s_frames;
static volatile uint32_t s_dropped;
static volatile uint32_t s_sent, s_attempts, s_failures, s_reconnects, s_discarded;
static volatile uint32_t s_last_send_uptime_s;
static volatile int s_last_socket_error;
static volatile bool s_connected;
static volatile bool s_was_connected;
static bool bench_enabled(void) {
    if(!device_security_ready() || !device_security_configured()) return false;
#ifdef CONFIG_ADSBIN_REMOTE_ENABLE
    return true;
#else
    /* Cache NVS lookup for one second; never touch flash for every frame. */
    static int64_t checked_us = 0;
    static bool cached = false;
    int64_t now = esp_timer_get_time();
    if (checked_us && now - checked_us < 1000000) return cached;
    nvs_handle_t prefs;
    char value[3] = {0};
    size_t len = sizeof(value);
    bool enabled = false;
    if (nvs_open("web_cfg", NVS_READONLY, &prefs) == ESP_OK) {
        enabled = nvs_get_str(prefs, "beast_enabled", value, &len) == ESP_OK && value[0] == '1';
        nvs_close(prefs);
    }
    cached = enabled;
    checked_us = now;
    return enabled;
#endif
}
#ifndef CONFIG_ADSBIN_REMOTE_ENABLE
#define CONFIG_ADSBIN_REMOTE_HOST "192.168.107.20"
#define CONFIG_ADSBIN_REMOTE_PORT 30004
#define CONFIG_ADSBIN_REMOTE_QUEUE 256
#endif
/* Beast payload: escape every 0x1a; type '2' for 56-bit and '3' for 112-bit frames.
 * Sample-derived 12 MHz timestamps are experimental and disabled by default.
 * They are not MLAT-qualified until RF sample continuity is field-verified.
 * RSSI magnitude is not calibrated; set zero rather than fabricate it.
 */
static size_t encode(const modes_frame_t *f, uint8_t *out, size_t cap)
{
    if (f->len_bytes != 7 && f->len_bytes != 14) return 0;
    uint8_t raw[21] = {0};
    const size_t n = 7 + f->len_bytes; // 6 timestamp bytes, 1 signal, 7/14 payload
    memcpy(raw + 7, f->data, f->len_bytes);
#if defined(CONFIG_ADSBIN_MLAT_EXPERIMENTAL)
    if (f->beast_clock_valid) {
        for (unsigned i = 0; i < 6; ++i) {
            raw[i] = (uint8_t)(f->beast_ticks >> (40u - 8u * i));
        }
    }
#endif
    size_t pos = 0;
    if (cap < 2) return 0;
    out[pos++] = 0x1a;
    out[pos++] = f->len_bytes == 7 ? '2' : '3';
    for (size_t i = 0; i < n; i++) {
        if (pos + 2 > cap) return 0;
        out[pos++] = raw[i];
        if (raw[i] == 0x1a) out[pos++] = 0x1a;
    }
    return pos;
}
static void sender(void *arg)
{
    (void)arg;
    modes_frame_t frame;
    uint8_t buf[44];
    for (;;) {
        if (!wifi_station_is_connected() || !bench_enabled()) {
            s_connected = false;
            if (s_frames) {
                UBaseType_t stale = uxQueueMessagesWaiting(s_frames);
                if (stale) {
                    __atomic_fetch_add(&s_discarded, (uint32_t)stale, __ATOMIC_RELAXED);
                    xQueueReset(s_frames);
                }
            }
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
#if defined(CONFIG_ADSBIN_REMOTE_ENABLE) && !defined(CONFIG_ADSBIN_REMOTE_ALLOW_UNENCRYPTED_LAN) && !defined(CONFIG_ADSBIN_REMOTE_WIREGUARD)
        /* No transport authorized: fail closed. */
        vTaskDelay(pdMS_TO_TICKS(2000));
        continue;
#else
#ifdef CONFIG_ADSBIN_REMOTE_WIREGUARD
        if (!remote_wireguard_peer_up()) {
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
#endif
        /* Read validated, non-secret destination overrides once per connection.
         * Existing Kconfig defaults remain in effect if nothing was saved.
         * A reboot or reconnect applies a newly saved destination. */
        char beast_host[48] = CONFIG_ADSBIN_REMOTE_HOST;
        uint16_t beast_port = CONFIG_ADSBIN_REMOTE_PORT;
        nvs_handle_t prefs;
        if (nvs_open("web_cfg", NVS_READONLY, &prefs) == ESP_OK) {
            char saved_host[48] = {0};
            size_t host_len = sizeof(saved_host);
            if (nvs_get_str(prefs, "beast_host", saved_host, &host_len) == ESP_OK &&
                saved_host[0] != '\0') {
                struct in_addr probe;
                if (inet_pton(AF_INET, saved_host, &probe) == 1) {
                    memcpy(beast_host, saved_host, sizeof(beast_host));
                }
            }
            char saved_port[8] = {0};
            size_t port_len = sizeof(saved_port);
            if (nvs_get_str(prefs, "beast_port", saved_port, &port_len) == ESP_OK) {
                char *end = NULL;
                long port = strtol(saved_port, &end, 10);
                if (end && *end == '\0' && port >= 1 && port <= 65535)
                    beast_port = (uint16_t)port;
            }
            nvs_close(prefs);
        }
        struct sockaddr_in target = { .sin_family = AF_INET,
            .sin_port = htons(beast_port) };
        if (inet_pton(AF_INET, beast_host, &target.sin_addr) != 1) {
            ESP_LOGE(TAG, "Destination must be an IPv4 address");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
#ifndef CONFIG_ADSBIN_REMOTE_ENABLE
        /* Bench forwarding is trusted private-LAN ONLY, never arbitrary public IP. */
        uint32_t addr = ntohl(target.sin_addr.s_addr);
        bool private_ip = (addr >> 24 == 10) ||
                          ((addr >> 20) == 0xAC1) ||
                          ((addr >> 16) == 0xC0A8);
        if (!private_ip) {
            ESP_LOGW(TAG, "Bench forwarding requires a private RFC1918 IPv4 destination");
            vTaskDelay(pdMS_TO_TICKS(3000));
            continue;
        }
#endif
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            s_last_socket_error = errno;
            __atomic_fetch_add(&s_failures, 1, __ATOMIC_RELAXED);
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
        int on = 1;
        (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
        int idle = 30, interval = 10, count = 3;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
        (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
        (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#ifdef CONFIG_ADSBIN_REMOTE_WIREGUARD
        /* Source-binding is a second guard against an unintended plaintext
         * route if the remote Wi-Fi network overlaps the DietPi subnet.
         * Field tests must still verify no outbound TCP packet leaks. */
        struct sockaddr_in source = { .sin_family = AF_INET };
        if (inet_pton(AF_INET, CONFIG_ADSBIN_WG_LOCAL_IP,
                      &source.sin_addr) != 1 ||
            bind(fd, (struct sockaddr *)&source, sizeof(source)) != 0) {
            ESP_LOGW(TAG, "Could not bind TCP to tunnel source address");
            close(fd);
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
#endif
        struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        __atomic_fetch_add(&s_attempts, 1, __ATOMIC_RELAXED);
        if (connect(fd, (struct sockaddr *)&target, sizeof(target)) != 0) {
            s_last_socket_error = errno;
            __atomic_fetch_add(&s_failures, 1, __ATOMIC_RELAXED);
            close(fd);
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
        s_connected = true;
        s_last_socket_error = 0;
        if (s_was_connected) __atomic_fetch_add(&s_reconnects, 1, __ATOMIC_RELAXED);
        s_was_connected = true;
        ESP_LOGI(TAG, "Connected to Beast TCP receiver %s:%u", beast_host, (unsigned)beast_port);
        /* Drop queued frames from the disconnected period, never replay stale aircraft. */
        UBaseType_t stale = uxQueueMessagesWaiting(s_frames);
        if (stale) {
            __atomic_fetch_add(&s_discarded, (uint32_t)stale, __ATOMIC_RELAXED);
            xQueueReset(s_frames);
        }
        while (wifi_station_is_connected() && bench_enabled()
#ifdef CONFIG_ADSBIN_REMOTE_WIREGUARD
               && remote_wireguard_peer_up()
#endif
               ) {
            if (xQueueReceive(s_frames, &frame, pdMS_TO_TICKS(1000)) != pdTRUE) continue;
            size_t n = encode(&frame, buf, sizeof(buf));
            if (!n) continue;
            size_t offset = 0;
            while (offset < n) {
#ifdef CONFIG_ADSBIN_REMOTE_WIREGUARD
                if (!remote_wireguard_peer_up()) break;
#endif
                int written = send(fd, buf + offset, n - offset, 0);
                if (written <= 0) {
                    s_last_socket_error = errno;
                    break;
                }
                offset += (size_t)written;
            }
            if (offset != n) { __atomic_fetch_add(&s_failures, 1, __ATOMIC_RELAXED); break; }
            __atomic_fetch_add(&s_sent, 1, __ATOMIC_RELAXED);
            s_last_send_uptime_s = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        }
        s_connected = false;
        close(fd);
        vTaskDelay(pdMS_TO_TICKS(500));
#endif
    }
}
esp_err_t remote_beast_start(void)
{
    if (s_frames) return ESP_OK;
    s_frames = xQueueCreate(CONFIG_ADSBIN_REMOTE_QUEUE, sizeof(modes_frame_t));
    if (!s_frames) return ESP_ERR_NO_MEM;
    if (xTaskCreatePinnedToCore(sender, "beast_tcp", 4096, NULL, 4, NULL, 1) != pdPASS)
        return ESP_ERR_NO_MEM;
    return ESP_OK;
}
void remote_beast_offer(const modes_frame_t *f)
{
    if (!f || !s_frames) return;
    /* Never build a backlog while the link is offline or forwarding disabled.
     * The decode task must remain non-blocking regardless of network state. */
    if (!wifi_station_is_connected() || !s_connected) {
        __atomic_fetch_add(&s_discarded, 1, __ATOMIC_RELAXED);
        return;
    }
    if (xQueueSend(s_frames, f, 0) != pdTRUE) __atomic_fetch_add(&s_dropped, 1, __ATOMIC_RELAXED);
}
#else
esp_err_t remote_beast_start(void) { return ESP_ERR_NOT_SUPPORTED; }
void remote_beast_offer(const modes_frame_t *f) { (void)f; }
#endif

void remote_beast_get_stats(remote_beast_stats_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
#if defined(CONFIG_ADSBIN_REMOTE_ENABLE) || defined(CONFIG_ADSBIN_WEB_HTTP_CONFIG)
    out->enabled = bench_enabled();
    out->connected = s_connected;
    out->sent = __atomic_load_n(&s_sent, __ATOMIC_RELAXED);
    out->dropped = __atomic_load_n(&s_dropped, __ATOMIC_RELAXED);
    out->connect_attempts = __atomic_load_n(&s_attempts, __ATOMIC_RELAXED);
    out->failures = __atomic_load_n(&s_failures, __ATOMIC_RELAXED);
    out->reconnects = __atomic_load_n(&s_reconnects, __ATOMIC_RELAXED);
    out->discarded_offline = __atomic_load_n(&s_discarded, __ATOMIC_RELAXED);
    out->last_send_uptime_s = s_last_send_uptime_s;
    out->last_socket_error = s_last_socket_error;
    out->queued = s_frames ? (uint32_t)uxQueueMessagesWaiting(s_frames) : 0;
#endif
}

