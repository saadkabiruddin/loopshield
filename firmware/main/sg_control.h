#pragma once
#include <stdbool.h>

#include "sg_net.h"

/* Starts the control, detector, tx and stats tasks. mac_ok is the result of
 * the HMAC self-test; if it failed, MAC checks reject everything. */
void sg_control_start(bool mac_ok);

/* MQTT receive callback (runs in the MQTT task). Sensor messages go through
 * the protocol-layer checks here, so their cost under flooding lands on the
 * network core, not on the control task. */
void sg_control_on_rx(sg_rx_topic_t topic, const uint8_t *data, size_t len);
