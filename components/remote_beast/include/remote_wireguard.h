#pragma once
#include <stdbool.h>
#include "esp_err.h"
esp_err_t remote_wireguard_start(void);
bool remote_wireguard_peer_up(void);
