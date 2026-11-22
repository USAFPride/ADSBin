idf_component_register(SRCS "device_security.c" INCLUDE_DIRS "include"
    REQUIRES nvs_flash mbedtls esp_timer esp_driver_gpio esp_system esp_wifi esp_netif lwip freertos esp_hw_support)
