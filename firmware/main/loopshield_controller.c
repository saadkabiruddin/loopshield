#include "sg_control.h"
#include "sg_mac.h"
#include "sg_net.h"

void app_main(void)
{
    bool mac_ok = sg_mac_init();

    /* Queues and tasks exist before MQTT can deliver anything. */
    sg_control_start(mac_ok);
    sg_net_start(sg_control_on_rx);
}
