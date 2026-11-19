#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include "adsbin_types.h"
esp_err_t remote_beast_start(void);
/* Only enqueue validated 1090 MHz Mode-S frames; never block demod/decode. */
void remote_beast_offer(const modes_frame_t *frame);

/* Read-only, lock-free counters for the web dashboard. */
typedef struct {
    bool enabled;
    bool connected;
    uint32_t sent;
    uint32_t dropped;
    uint32_t connect_attempts;
    uint32_t failures;
    uint32_t reconnects;
    uint32_t discarded_offline;
    uint32_t last_send_uptime_s;
    uint32_t queued;
    int last_socket_error;
} remote_beast_stats_t;
void remote_beast_get_stats(remote_beast_stats_t *out);
