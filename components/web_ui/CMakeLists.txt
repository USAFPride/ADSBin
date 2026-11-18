set(web_extra_sources "")
set(web_extra_embeds "")
if(CONFIG_ADSBIN_WEB_HTTPS_CONFIG)
    list(APPEND web_extra_sources "web_secure.c")
    list(APPEND web_extra_embeds "servercert.pem" "serverkey.pem")
endif()
idf_component_register(
    SRCS "web_ui.c" ${web_extra_sources}
    INCLUDE_DIRS "include"
    EMBED_TXTFILES "index.html" ${web_extra_embeds}
    REQUIRES esp_http_server esp_timer
             usb_rtlsdr demod1090 status wifi_link
    PRIV_REQUIRES nvs_flash json esp_https_server esp_hw_support
)
