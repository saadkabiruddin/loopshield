#pragma once
/* Compile-time constants. Everything that differs between experiment
 * configurations (which defenses are on, CUSUM thresholds) is set at runtime
 * through sg/config instead, so one firmware image covers the whole matrix. */

/* ---- Network ---------------------------------------------------------- */
/* Wokwi's simulated access point. Channel 6 skips the scan and connects faster. */
#define SG_WIFI_SSID        "Wokwi-GUEST"
#define SG_WIFI_PASSWORD    ""
#define SG_WIFI_CHANNEL     6

/* host.wokwi.internal resolves to the machine running the simulator. Port
 * 1883 is the attacker's on-path proxy (transparent when no attack runs);
 * the real broker sits behind it on 1884. */
#define SG_BROKER_URI       "mqtt://host.wokwi.internal:1883"
#define SG_CLIENT_ID        "sg-controller"
#define SG_RECONNECT_MS     500

#define SG_TOPIC_SENSOR     "sg/sensor"
#define SG_TOPIC_ACTUATOR   "sg/actuator"
#define SG_TOPIC_STATS      "sg/stats"
#define SG_TOPIC_TELEM      "sg/telem"
#define SG_TOPIC_CONFIG     "sg/config"
#define SG_TOPIC_CFGACK     "sg/cfgack"

/* Shared HMAC-SHA256 key (plant and controller; the attacker does not have
 * it). Must match shared/SgKeys.cs. A lab key, not a secret. */
#define SG_HMAC_KEY { \
    0x53, 0x70, 0x6f, 0x6f, 0x66, 0x47, 0x75, 0x61, 0x72, 0x64, 0x2d, 0x6c, 0x61, 0x62, 0x2d, 0x6b, \
    0x65, 0x79, 0x2d, 0x30, 0x31, 0x9a, 0x3c, 0x7e, 0x11, 0xd4, 0x58, 0xb2, 0x06, 0xef, 0x83, 0x2d }

/* ---- Tasks ------------------------------------------------------------ */
/* Core 1: control (10) and detector (8). Core 0: Wi-Fi (23), lwIP (18),
 * MQTT + protocol checks (5), tx (4), stats (2). Change SG_CONTROL_CORE to 0
 * to study flooding interference on a shared core. */
#define SG_CONTROL_PERIOD_MS    100      /* implicit deadline = period */
#define SG_CONTROL_PRIORITY     10
#define SG_CONTROL_CORE         1
#define SG_DETECT_PRIORITY      8
#define SG_DETECT_CORE          1
#define SG_TX_PRIORITY          4
#define SG_TX_CORE              0

/* ---- Control ---------------------------------------------------------- */
#define SG_SETPOINT_C           22.0f
#define SG_KP                   0.5f            /* duty per degC */
#define SG_KI                   (SG_KP / 60.0f) /* Ti = plant time constant */

/* No accepted sample for this many periods = sensor lost: hold the heater
 * at its last output and stop integrating. */
#define SG_STALE_LIMIT          5

/* ---- Nominal plant model (used by the physics detector) ---------------- */
#define SG_MODEL_TAMB           15.0f   /* degC */
#define SG_MODEL_GAIN           20.0f   /* degC at full duty */
#define SG_MODEL_TAU            60.0f   /* s */

/* ---- Reporting -------------------------------------------------------- */
#define SG_STATS_PERIOD_MS      10000
