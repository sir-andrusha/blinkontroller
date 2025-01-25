/*
 * SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <cJSON.h>

#include "nvs.h"
#include "nvs_flash.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_event.h"

#include "esp_bridge.h"
#if defined(CONFIG_APP_BRIDGE_USE_WEB_SERVER)
#include "web_server.h"
#endif
#include "iot_button.h"
#if defined(CONFIG_APP_BRIDGE_USE_WIFI_PROVISIONING_OVER_BLE)
#include "wifi_prov_mgr.h"
#endif

#define BUTTON_NUM            1
#define BUTTON_SW1            CONFIG_APP_GPIO_BUTTON_SW1
#define BUTTON_PRESS_TIME     5000000
#define BUTTON_REPEAT_TIME    5

static const char* TAG = "main";


static esp_err_t esp_storage_init(void)
{
    esp_err_t ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // NVS partition was truncated and needs to be erased
        // Retry nvs_flash_init
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    return ret;
}

#include "esp_http_server.h"
#include "esp_vfs.h"
#include "esp_spiffs.h"

#define SCRATCH_BUFSIZE (10240)

typedef struct rest_server_context {
    char base_path[ESP_VFS_PATH_MAX + 1];
    char scratch[SCRATCH_BUFSIZE];
} rest_server_context_t;

#define REST_CHECK(a, str, goto_tag, ...)                                              \
    do                                                                                 \
    {                                                                                  \
        if (!(a))                                                                      \
        {                                                                              \
            ESP_LOGE(TAG, "%s(%d): " str, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            goto goto_tag;                                                             \
        }                                                                              \
    } while (0)


#include "lwip/apps/netbiosns.h"
#include "mdns.h"
#include <string.h>
#include <fcntl.h>
#include "esp_chip_info.h"
#include "esp_random.h"
#include "esp_log.h"
#include "cJSON.h"

#include <inttypes.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include <sys/socket.h>
#include "esp_mac.h" 
#include "esp_netif_ip_addr.h"

#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + 128)

#define CHECK_FILE_EXTENSION(filename, ext) (strcasecmp(&filename[strlen(filename) - strlen(ext)], ext) == 0)

/* Set HTTP response content type according to file extension */
static esp_err_t set_content_type_from_file(httpd_req_t* req, const char* filepath)
{
    const char* type = "text/plain";
    if (CHECK_FILE_EXTENSION(filepath, ".html")) {
        type = "text/html";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".js")) {
        type = "application/javascript";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".css")) {
        type = "text/css";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".png")) {
        type = "image/png";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".ico")) {
        type = "image/x-icon";
    }
    else if (CHECK_FILE_EXTENSION(filepath, ".svg")) {
        type = "text/xml";
    }
    return httpd_resp_set_type(req, type);
}

/* Send HTTP response with the contents of the requested file */
static esp_err_t rest_common_get_handler(httpd_req_t* req)
{
    char filepath[FILE_PATH_MAX];

    rest_server_context_t* rest_context = (rest_server_context_t*)req->user_ctx;
    strlcpy(filepath, rest_context->base_path, sizeof(filepath));
    if (req->uri[strlen(req->uri) - 1] == '/') {
        strlcat(filepath, "/index.html", sizeof(filepath));
    }
    else {
        strlcat(filepath, req->uri, sizeof(filepath));
    }
    int fd = open(filepath, O_RDONLY, 0);
    if (fd == -1) {
        ESP_LOGE(TAG, "Failed to open file : %s", filepath);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read existing file");
        return ESP_FAIL;
    }

    set_content_type_from_file(req, filepath);

    char* chunk = rest_context->scratch;
    ssize_t read_bytes;
    do {
        /* Read file in chunks into the scratch buffer */
        read_bytes = read(fd, chunk, SCRATCH_BUFSIZE);
        if (read_bytes == -1) {
            ESP_LOGE(TAG, "Failed to read file : %s", filepath);
        }
        else if (read_bytes > 0) {
            /* Send the buffer contents as HTTP response chunk */
            if (httpd_resp_send_chunk(req, chunk, read_bytes) != ESP_OK) {
                close(fd);
                ESP_LOGE(TAG, "File sending failed!");
                /* Abort sending file */
                httpd_resp_sendstr_chunk(req, NULL);
                /* Respond with 500 Internal Server Error */
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to send file");
                return ESP_FAIL;
            }
        }
    } while (read_bytes > 0);
    /* Close file after sending complete */
    close(fd);
    ESP_LOGI(TAG, "File sending complete");
    /* Respond with an empty chunk to signal HTTP response completion */
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Simple handler for getting system handler */
static esp_err_t system_info_get_handler(httpd_req_t* req)
{
    httpd_resp_set_type(req, "application/json");
    cJSON* root = cJSON_CreateObject();
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    cJSON_AddStringToObject(root, "version", IDF_VER);
    cJSON_AddNumberToObject(root, "cores", chip_info.cores);
    const char* sys_info = cJSON_Print(root);
    httpd_resp_sendstr(req, sys_info);
    free((void*)sys_info);
    cJSON_Delete(root);
    return ESP_OK;
}


#define ETH_HWADDR_LEN       6
#define CONFIG_MESH_LITE_REPORT_INTERVAL 300
#define MESH_LITE_REPORT_INTERVAL_BUFFER            10
#define ESP_ERR_DUPLICATE_ADDITION    0x110   /*!< Duplicate addition */

typedef struct  esp_mesh_lite_node_info {
    uint8_t level;
    uint8_t red;
    uint8_t green;
    uint8_t blue;
    uint32_t ip_addr;
    uint8_t mac_addr[ETH_HWADDR_LEN];
} esp_mesh_lite_node_info_t;

typedef struct node_info_list {
    struct node_info_list* next;
    esp_mesh_lite_node_info_t* node;
    uint32_t ttl;
} node_info_list_t;

static uint32_t nodes_num = 0;
static node_info_list_t* node_info_list = NULL;
static SemaphoreHandle_t node_info_mutex;

const node_info_list_t* esp_mesh_lite_get_nodes_list(uint32_t* size)
{
    if (size) {
        *size = nodes_num;
    }
    return node_info_list;
}

static esp_err_t esp_mesh_lite_node_info_update(uint8_t red, uint8_t green, uint8_t blue, uint8_t* mac, uint32_t ip_addr, uint8_t level, bool updateColor, bool updateAddress)
{
    xSemaphoreTake(node_info_mutex, portMAX_DELAY);
    node_info_list_t* new = node_info_list;
    node_info_list_t* prev = NULL;

    while (new) {
        if (!memcmp(new->node->mac_addr, mac, ETH_HWADDR_LEN)) {
            new->ttl = (CONFIG_MESH_LITE_REPORT_INTERVAL + MESH_LITE_REPORT_INTERVAL_BUFFER);
            if (updateColor && (new->node->red != red || new->node->green != green || new->node->blue != blue)) {
                ESP_LOGI(TAG, "Update color");
                new->node->red = red;
                new->node->green = green;
                new->node->blue = blue;
            }

            if (updateAddress && (new->node->ip_addr != ip_addr || new->node->level != level)) {
                ESP_LOGI(TAG, "Update address");
                new->node->ip_addr = ip_addr;
                new->node->level = level;
            }
            else if (updateAddress) {
                ESP_LOGI(TAG, "Data is not changed");
                xSemaphoreGive(node_info_mutex);
                return ESP_ERR_DUPLICATE_ADDITION;
            }
            xSemaphoreGive(node_info_mutex);
            return ESP_OK;
        }
        else {
            if (new->ttl <= MESH_LITE_REPORT_INTERVAL_BUFFER) {
                if (node_info_list == new) {
                    node_info_list = new->next;
                    free(new->node);
                    free(new);
                    new = node_info_list;
                }
                else {
                    prev->next = new->next;
                    free(new->node);
                    free(new);
                    new = prev->next;
                }
                nodes_num--;
            }
            prev = new;
        }
        new = new->next;
    }

    /* not found, create a new */
    new = (node_info_list_t*)malloc(sizeof(node_info_list_t));
    if (new == NULL) {
        ESP_LOGE(TAG, "node info add fail(no mem)");
        xSemaphoreGive(node_info_mutex);
        return ESP_ERR_NO_MEM;
    }

    new->node = (esp_mesh_lite_node_info_t*)malloc(sizeof(esp_mesh_lite_node_info_t));
    if (new->node == NULL) {
        free(new);
        ESP_LOGE(TAG, "node info add fail(no mem)");
        xSemaphoreGive(node_info_mutex);
        return ESP_ERR_NO_MEM;
    }

    memcpy(new->node->mac_addr, mac, ETH_HWADDR_LEN);
    new->node->red = red;
    new->node->green = green;
    new->node->blue = blue;
    new->node->ip_addr = ip_addr;
    new->node->level = level;
    new->ttl = (CONFIG_MESH_LITE_REPORT_INTERVAL + MESH_LITE_REPORT_INTERVAL_BUFFER);

    new->next = node_info_list;
    node_info_list = new;
    nodes_num++;

    xSemaphoreGive(node_info_mutex);
    return ESP_OK;
}

static esp_mesh_lite_node_info_t* esp_mesh_lite_get_node(uint8_t* mac)
{
    xSemaphoreTake(node_info_mutex, portMAX_DELAY);
    node_info_list_t* new = node_info_list;

    while (new) {
        if (!memcmp(new->node->mac_addr, mac, ETH_HWADDR_LEN)) {
            xSemaphoreGive(node_info_mutex);
            return new->node;
        }
        new = new->next;
    }

    return NULL;
}

static esp_err_t names_get_handler(httpd_req_t* req)
{
    httpd_resp_set_type(req, "application/json");
    cJSON* root = cJSON_CreateArray();

    uint32_t size = 0;
    const node_info_list_t* node = esp_mesh_lite_get_nodes_list(&size);

    for (uint32_t loop = 0; (loop < size) && (node != NULL); loop++) {
        uint8_t red = node->node->red;
        uint8_t green = node->node->green;
        uint8_t blue = node->node->blue;
        uint8_t lvl = node->node->level;

        struct in_addr ip_struct;
        ip_struct.s_addr = node->node->ip_addr;

        char mac_str[19] = { 0 };
        sprintf(mac_str, MACSTR, MAC2STR(node->node->mac_addr));

        cJSON* item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "mac", mac_str);
        cJSON_AddStringToObject(item, "ip", inet_ntoa(ip_struct));
        cJSON_AddNumberToObject(item, "level", lvl);
        cJSON_AddNumberToObject(item, "red", red);
        cJSON_AddNumberToObject(item, "green", green);
        cJSON_AddNumberToObject(item, "blue", blue);

        cJSON_AddItemToArray(root, item);

        node = node->next;
    }

    const char* names = cJSON_Print(root);

    httpd_resp_sendstr(req, names);
    free((void*)names);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t str2mac(const char* str, uint8_t* mac_addr)
{
    unsigned int mac_tmp[ETH_HWADDR_LEN];
    if (ETH_HWADDR_LEN != sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x%*c",
        &mac_tmp[0], &mac_tmp[1], &mac_tmp[2],
        &mac_tmp[3], &mac_tmp[4], &mac_tmp[5])) {
        return ESP_ERR_INVALID_MAC;
    }
    for (int i = 0; i < ETH_HWADDR_LEN; i++) {
        mac_addr[i] = (uint8_t)mac_tmp[i];
    }
    return ESP_OK;
}

static esp_err_t registry_post_handler(httpd_req_t* req)
{
    int total_len = req->content_len;
    int cur_len = 0;
    char* buf = ((rest_server_context_t*)(req->user_ctx))->scratch;
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE) {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0) {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';
    //ESP_LOGI(TAG, "buf %s", buf);

    cJSON* root = cJSON_Parse(buf);
    char* mac_str = cJSON_GetObjectItem(root, "mac")->valuestring;
    uint32_t ip_addr = cJSON_GetObjectItem(root, "ip")->valueint;
    uint8_t lvl = cJSON_GetObjectItem(root, "level")->valueint;
    uint8_t red = cJSON_GetObjectItem(root, "red")->valueint; // currently is not used
    red = 255;
    uint8_t green = cJSON_GetObjectItem(root, "green")->valueint; // currently is not used
    green = 255;
    uint8_t blue = cJSON_GetObjectItem(root, "blue")->valueint; // currently is not used
    blue = 255;

    ESP_LOGI(TAG, "Registration of node with mac %s, and ip %" PRIu32, mac_str, ip_addr);

    uint8_t mac_addr[ETH_HWADDR_LEN];
    str2mac(mac_str, mac_addr);
    esp_mesh_lite_node_info_update(-1, -1, -1, mac_addr, ip_addr, lvl, false, true);
    cJSON_Delete(root);

    esp_mesh_lite_node_info_t* node = esp_mesh_lite_get_node(mac_addr);
    if (node != NULL) {
        red = node->red;
        green = node->green;
        blue = node->blue;

        ESP_LOGI(TAG, "Loaded from memory node with mac="MACSTR" red=%d green=%d blue=%d", MAC2STR(mac_addr), red, green, blue);
    }

    cJSON* item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "red", red);
    cJSON_AddNumberToObject(item, "green", green);
    cJSON_AddNumberToObject(item, "blue", blue);
    const char* resp = cJSON_Print(item);
    cJSON_Delete(item);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);

    return ESP_OK;
}

static esp_err_t light_brightness_post_handler(httpd_req_t* req)
{
    int total_len = req->content_len;
    int cur_len = 0;
    char* buf = ((rest_server_context_t*)(req->user_ctx))->scratch;
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE) {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len) {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0) {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';

    cJSON* root = cJSON_Parse(buf);
    char* mac_str = cJSON_GetObjectItem(root, "mac")->valuestring;
    uint8_t red = cJSON_GetObjectItem(root, "red")->valueint;
    uint8_t green = cJSON_GetObjectItem(root, "green")->valueint;
    uint8_t blue = cJSON_GetObjectItem(root, "blue")->valueint;

    ESP_LOGI(TAG, "Light control: mac=%s, red = %d, green = %d, blue = %d", mac_str, red, green, blue);

    uint8_t mac_addr[ETH_HWADDR_LEN];
    str2mac(mac_str, mac_addr);
    esp_mesh_lite_node_info_update(red, green, blue, mac_addr, -1, -1, true, false);

    cJSON_Delete(root);

    httpd_resp_sendstr(req, "{}");
    return ESP_OK;
}

void init_handlers(httpd_handle_t server, rest_server_context_t* rest_context)
{
    /* URI handler for fetching system info */
    httpd_uri_t system_info_get_uri = {
        .uri = "/api/v1/system/info",
        .method = HTTP_GET,
        .handler = system_info_get_handler,
        .user_ctx = rest_context
    };
    httpd_register_uri_handler(server, &system_info_get_uri);

    httpd_uri_t light_brightness_post_uri = {
    .uri = "/api/v1/light/brightness",
    .method = HTTP_POST,
    .handler = light_brightness_post_handler,
    .user_ctx = rest_context
    };

    httpd_register_uri_handler(server, &light_brightness_post_uri);

    httpd_uri_t registry_post_uri = {
    .uri = "/api/v1/registry",
    .method = HTTP_POST,
    .handler = registry_post_handler,
    .user_ctx = rest_context
    };

    httpd_register_uri_handler(server, &registry_post_uri);

    httpd_uri_t names_get_uri = {
        .uri = "/api/v1/names",
        .method = HTTP_GET,
        .handler = names_get_handler,
        .user_ctx = rest_context
    };
    httpd_register_uri_handler(server, &names_get_uri);

    /* URI handler for getting web server files */
    httpd_uri_t common_get_uri = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = rest_common_get_handler,
        .user_ctx = rest_context
    };
    httpd_register_uri_handler(server, &common_get_uri);
}


esp_err_t init_fs(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = CONFIG_EXAMPLE_WEB_MOUNT_POINT,
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = false
    };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        }
        else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        }
        else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return ESP_FAIL;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
    }
    else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }
    return ESP_OK;
}

#define MDNS_INSTANCE "swarm drone web server"

static void initialise_mdns(void)
{
    mdns_init();
    mdns_hostname_set(CONFIG_EXAMPLE_MDNS_HOST_NAME);
    mdns_instance_name_set(MDNS_INSTANCE);

    mdns_txt_item_t serviceTxtData[] = {
        {"board", "esp32"},
        {"path", "/"}
    };

    ESP_ERROR_CHECK(mdns_service_add("SwarmDronWebServer", "_http", "_tcp", 80, serviceTxtData,
        sizeof(serviceTxtData) / sizeof(serviceTxtData[0])));
}

httpd_handle_t start_rest_server(const char* base_path)
{

    REST_CHECK(base_path, "wrong base path", err);

    rest_server_context_t* rest_context = calloc(1, sizeof(rest_server_context_t));
    REST_CHECK(rest_context, "No memory for rest context", err);
    strlcpy(rest_context->base_path, base_path, sizeof(rest_context->base_path));

    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;

    ESP_LOGI(TAG, "Starting HTTP Server");
    REST_CHECK(httpd_start(&server, &config) == ESP_OK, "Start server failed", err_start);

    init_handlers(server, rest_context);

    return server;
err_start:
    free(rest_context);
err:
    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

void app_main(void)
{
    esp_log_level_set("*", ESP_LOG_INFO);

    node_info_mutex = xSemaphoreCreateMutex();

    esp_storage_init();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_bridge_create_all_netif();

#if defined(CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP)
    wifi_config_t wifi_cfg = {
        .ap = {
            .ssid = CONFIG_BRIDGE_SOFTAP_SSID,
            .password = CONFIG_BRIDGE_SOFTAP_PASSWORD,
        }
    };
    esp_bridge_wifi_set_config(WIFI_IF_AP, &wifi_cfg);
#endif
#if defined(CONFIG_BRIDGE_EXTERNAL_NETIF_STATION)
    esp_wifi_connect();
#endif

    initialise_mdns();
    netbiosns_init();
    netbiosns_set_name(CONFIG_EXAMPLE_MDNS_HOST_NAME);

    ESP_ERROR_CHECK(init_fs());

#if defined(CONFIG_APP_BRIDGE_USE_WEB_SERVER)
    // StartWebServer();
#endif /* CONFIG_APP_BRIDGE_USE_WEB_SERVER */
#if defined(CONFIG_APP_BRIDGE_USE_WIFI_PROVISIONING_OVER_BLE)
    esp_bridge_wifi_prov_mgr();
#endif /* CONFIG_APP_BRIDGE_USE_WIFI_PROVISIONING_OVER_BLE */

    /* Start the server for the first time */
    httpd_handle_t server = start_rest_server(CONFIG_EXAMPLE_WEB_MOUNT_POINT);

    while (server) {
        sleep(5);
    }
}
