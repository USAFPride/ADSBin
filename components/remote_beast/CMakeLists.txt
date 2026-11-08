# Kconfig symbols may not be resolved during ESP-IDF's initial component
# dependency enumeration; keep this managed component in REQUIRES even when
# CONFIG_ADSBIN_REMOTE_WIREGUARD is disabled. The source's #ifdef still
# determines whether the VPN is enabled at runtime.
idf_component_register(
    SRCS "remote_beast.c" "remote_wireguard.c"
    INCLUDE_DIRS "include"
    REQUIRES common freertos lwip wifi_link esphome__wireguard
)
