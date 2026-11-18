idf_component_register(
    SRCS "web_ui.c"
    INCLUDE_DIRS "include"
    EMBED_TXTFILES "index.html"
    REQUIRES esp_http_server esp_timer nvs_flash esp_hw_support
             usb_rtlsdr demod1090 status wifi_link
    PRIV_REQUIRES json
)
