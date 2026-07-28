idf_component_register(
    SRCS "keemash_mesh_core.c"
         "keemash_log_time_vprintf.c"
         "keemash_mesh_hooks.c"
         "keemash_mesh_root.c"
         "keemash_mesh_node.c"
         "keemash_mesh_log_stream.c"
         "keemash_mesh_time.c"
         "keemash_mesh_ota_receiver.c"
         "keemash_mesh_tx_broker.c"
         "keemash_mesh_event_outbox.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_system esp_timer log heap app_update esp_app_format spi_flash bootloader_support mbedtls nvs_flash
)
