idf_component_register(
    SRCS "web_ui.c" "web_secure.c" "web_auth.c"
    INCLUDE_DIRS "include"
    EMBED_TXTFILES "index.html"
    REQUIRES esp_http_server esp_timer usb_rtlsdr demod1090 status wifi_link traffic ownship
    PRIV_REQUIRES nvs_flash remote_beast device_security esp_netif lwip
)
