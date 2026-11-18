#pragma once
#include <stddef.h>
#include "esp_err.h"

/* Lightweight web server: operates only on Core-1 networking tasks and
 * retrieves read-only counter snapshots; no USB/DSP hot-path hooks. */
esp_err_t web_ui_start(size_t (*aircraft_count)(void));
