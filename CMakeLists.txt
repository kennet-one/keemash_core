idf_component_register(
    SRCS "keemash_mesh_core.c"
         "keemash_mesh_hooks.c"
         "keemash_mesh_root.c"
         "keemash_mesh_node.c"
         "keemash_mesh_ota_receiver.c"
         "keemash_mesh_tx_broker.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_system esp_timer heap app_update esp_app_format spi_flash bootloader_support mbedtls nvs_flash
)
