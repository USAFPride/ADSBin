#pragma once
#include <stdbool.h>
#include "esp_http_server.h"

bool web_auth_local(httpd_req_t *req, bool ap_only);
bool web_auth_require(httpd_req_t *req);
esp_err_t web_auth_register(httpd_handle_t server);
void web_auth_headers(httpd_req_t *req);
