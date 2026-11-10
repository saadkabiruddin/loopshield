#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SG_RX_SENSOR,
    SG_RX_CONFIG,
} sg_rx_topic_t;

/* Called from the MQTT task for every message on a subscribed topic. */
typedef void (*sg_rx_cb_t)(sg_rx_topic_t topic, const uint8_t *data, size_t len);

/* Connects Wi-Fi (blocking) and starts the MQTT client. */
void sg_net_start(sg_rx_cb_t on_rx);

/* Publishes directly from the calling task (QoS 0). It can block on the
 * socket and the client lock, so the control task never calls it; the tx
 * and stats tasks and the MQTT task (config ack) do. */
bool sg_net_publish(const char *topic, const void *data, size_t len);
