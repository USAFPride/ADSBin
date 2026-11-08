set(remote_reqs common freertos lwip wifi_link)
if(CONFIG_ADSBIN_REMOTE_WIREGUARD)
  list(APPEND remote_reqs wireguard)
endif()
idf_component_register(SRCS "remote_beast.c" "remote_wireguard.c"
    INCLUDE_DIRS "include" REQUIRES ${remote_reqs})
