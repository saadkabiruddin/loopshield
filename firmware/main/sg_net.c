#include "sg_net.h"

#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "mqtt_client.h"
#include "nvs_flash.h"

#include "sg_config.h"

static const char *TAG = "sg_net";

#define WIFI_CONNECTED_BIT BIT0

static EventGroupHandle_t s_wifi_events;
static esp_mqtt_client_handle_t s_client;
static volatile bool s_mqtt_up;
static sg_rx_cb_t s_on_rx;

static void wifi_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
        ESP_LOGW(TAG, "Wi-Fi disconnected, retrying");
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *ev = data;
        ESP_LOGI(TAG, "Wi-Fi up, IP " IPSTR, IP2STR(&ev->ip_info.ip));
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

static void wifi_connect_blocking(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    s_wifi_events = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                        wifi_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                        wifi_handler, NULL, NULL));

    wifi_config_t cfg = {
        .sta = {
            .ssid = SG_WIFI_SSID,
            .password = SG_WIFI_PASSWORD,
            .channel = SG_WIFI_CHANNEL,
            .threshold.authmode = WIFI_AUTH_OPEN,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    /* Default modem sleep wakes only every DTIM (~300-400 ms here), adding
     * large, variable receive latency to a 100 ms control loop. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_LOGI(TAG, "Connecting to %s ...", SG_WIFI_SSID);
    xEventGroupWaitBits(s_wifi_events, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
}

static bool topic_is(const esp_mqtt_event_t *ev, const char *t)
{
    return ev->topic_len == (int)strlen(t) && memcmp(ev->topic, t, ev->topic_len) == 0;
}

static void mqtt_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    esp_mqtt_event_handle_t ev = data;

    switch ((esp_mqtt_event_id_t)id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected to %s", SG_BROKER_URI);
        esp_mqtt_client_subscribe(s_client, SG_TOPIC_SENSOR, 0);
        esp_mqtt_client_subscribe(s_client, SG_TOPIC_CONFIG, 1);
        s_mqtt_up = true;
        break;
    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected");
        s_mqtt_up = false;
        break;
    case MQTT_EVENT_DATA:
        /* All our messages fit in one MQTT buffer; fragments are dropped. */
        if (ev->current_data_offset != 0 || ev->data_len != ev->total_data_len) {
            break;
        }
        if (topic_is(ev, SG_TOPIC_SENSOR)) {
            s_on_rx(SG_RX_SENSOR, (const uint8_t *)ev->data, ev->data_len);
        } else if (topic_is(ev, SG_TOPIC_CONFIG)) {
            s_on_rx(SG_RX_CONFIG, (const uint8_t *)ev->data, ev->data_len);
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGW(TAG, "MQTT error");
        break;
    default:
        break;
    }
}

void sg_net_start(sg_rx_cb_t on_rx)
{
    s_on_rx = on_rx;
    wifi_connect_blocking();

    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = SG_BROKER_URI,
        .credentials.client_id = SG_CLIENT_ID,
        .network.reconnect_timeout_ms = SG_RECONNECT_MS,
        .buffer.size = 2048,
        .buffer.out_size = 4096,    /* a telemetry batch is ~2 KB */
    };
    s_client = esp_mqtt_client_init(&cfg);
    ESP_ERROR_CHECK(esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, mqtt_handler, NULL));
    ESP_ERROR_CHECK(esp_mqtt_client_start(s_client));
}

bool sg_net_publish(const char *topic, const void *data, size_t len)
{
    if (!s_mqtt_up) {
        return false;
    }
    /* Direct publish: writes to the socket from the calling task. (Enqueueing
     * instead hands the message to esp-mqtt's task, which sends only one
     * queued message per loop pass and fell behind at 20 msg/s.) */
    return esp_mqtt_client_publish(s_client, topic, data, (int)len, 0, 0) >= 0;
}
