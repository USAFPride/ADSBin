#pragma once
#include "esp_err.h"
#include "adsbin_types.h"
esp_err_t remote_beast_start(void);
/* Only enqueue validated 1090 MHz Mode-S frames; never block demod/decode. */
void remote_beast_offer(const modes_frame_t *frame);
