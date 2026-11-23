#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

esp_err_t device_security_init(void);
bool device_security_ready(void);
bool device_security_configured(void);
bool device_security_valid_password(const char *password);
esp_err_t device_security_set_password(const char *password);
bool device_security_check_password(const char *password);
esp_err_t device_security_get_secret(const char *name, char *out, size_t size);
esp_err_t device_security_set_secret(const char *name, const char *value);
bool device_security_has_secret(const char *name);
void device_security_start_reset_button(void);
bool device_security_reset_pending(void);
void device_security_schedule_restart(void);
