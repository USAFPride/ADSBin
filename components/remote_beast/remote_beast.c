#include "remote_beast.h"
#include "wifi_station.h"
#include "sdkconfig.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifdef CONFIG_ADSBIN_REMOTE_ENABLE
static const char *TAG = "remote_beast";
static QueueHandle_t s_frames;
static volatile uint32_t s_dropped;
/* Beast payload: escape every 0x1a; type '2' for 56-bit and '3' for 112-bit frames.
 * 48-bit timestamp is deliberately zero: ADSBin's rx_time_us is monotonic,
 * not an MLAT-qualified 12 MHz SDR timestamp. This remote feed is NOT for MLAT.
 * RSSI magnitude is not calibrated; set zero rather than fabricate it.
 */
static size_t encode(const modes_frame_t *f, uint8_t *out, size_t cap)
{
    if (f->len_bytes != 7 && f->len_bytes != 14) return 0;
    uint8_t raw[21] = {0};
    const size_t n = 7 + f->len_bytes; // 6 timestamp bytes, 1 signal, 7/14 payload
    memcpy(raw + 7, f->data, f->len_bytes);
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
        if (!wifi_station_is_connected()) {
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
#ifndef CONFIG_ADSBIN_REMOTE_ALLOW_UNENCRYPTED_LAN
        /* Fail closed: WireGuard gating will be integrated after port is verified. */
        vTaskDelay(pdMS_TO_TICKS(2000));
        continue;
#else
        struct sockaddr_in target = { .sin_family = AF_INET,
            .sin_port = htons(CONFIG_ADSBIN_REMOTE_PORT) };
        if (inet_pton(AF_INET, CONFIG_ADSBIN_REMOTE_HOST, &target.sin_addr) != 1) {
            ESP_LOGE(TAG, "Destination must be an IPv4 address");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) { vTaskDelay(pdMS_TO_TICKS(2000)); continue; }
        struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (connect(fd, (struct sockaddr *)&target, sizeof(target)) != 0) {
            close(fd);
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }
        ESP_LOGI(TAG, "Connected to Beast TCP receiver (LAN test mode)");
        xQueueReset(s_frames); // no stale frames after reconnect
        while (wifi_station_is_connected() &&
               xQueueReceive(s_frames, &frame, pdMS_TO_TICKS(2000)) == pdTRUE) {
            size_t n = encode(&frame, buf, sizeof(buf));
            if (!n) continue;
            size_t offset = 0;
            while (offset < n) {
                int written = send(fd, buf + offset, n - offset, 0);
                if (written <= 0) break;
                offset += (size_t)written;
            }
            if (offset != n) break;
        }
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
    if (xQueueSend(s_frames, f, 0) != pdTRUE) s_dropped++;
}
#else
esp_err_t remote_beast_start(void) { return ESP_ERR_NOT_SUPPORTED; }
void remote_beast_offer(const modes_frame_t *f) { (void)f; }
#endif
