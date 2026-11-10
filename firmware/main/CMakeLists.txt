idf_component_register(SRCS "loopshield_controller.c" "sg_control.c" "sg_detect.c" "sg_mac.c"
                            "sg_msg.c" "sg_net.c" "sg_proto.c"
                       INCLUDE_DIRS "."
                       REQUIRES esp_event esp_netif esp_timer esp_wifi freertos mbedtls mqtt nvs_flash)
