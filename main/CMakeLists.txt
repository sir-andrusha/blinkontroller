idf_component_register(SRC_DIRS "."
                       INCLUDE_DIRS ".")

if(CONFIG_BLINKER_ENABLE)
    set(WEB_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../front/web")
    if(EXISTS ${WEB_SRC_DIR}/site)
        spiffs_create_partition_image(www ${WEB_SRC_DIR}/site FLASH_IN_PROJECT)
    else()
        message(FATAL_ERROR "${WEB_SRC_DIR}/site doesn't exit. Please add index.html there.")
    endif()
endif()