/*
 * Task layout (see sg_config.h for priorities/cores):
 *
 *   MQTT task ──sensor──▶ protocol checks ──accepted──▶ [latest sample]
 *                                                             │ peek
 *   control task (100 ms) ◀───────────────────────────────────┘
 *     PI (or safe mode) ──▶ [tx queue] ──▶ tx task ──▶ sg/actuator
 *                       └─▶ [detector queue] ──▶ detector task
 *                                                  observer, CUSUM, invariant
 *                                                  ──▶ [tx queue] ──▶ sg/telem
 *
 * The control task never touches the network, so its execution time
 * measures control + defense work only.
 */
#include "sg_control.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "sg_config.h"
#include "sg_detect.h"
#include "sg_mac.h"
#include "sg_msg.h"
#include "sg_pi.h"
#include "sg_proto.h"

static const char *TAG = "sg_ctl";

#define PERIOD_US ((int64_t)SG_CONTROL_PERIOD_MS * 1000)
#define DT_S      (SG_CONTROL_PERIOD_MS / 1000.0f)

/* ---- Runtime configuration (set via sg/config) ------------------------ */

typedef struct {
    uint32_t run;
    sg_proto_opts_t proto;
    bool phys;
    bool mitigate;
    float cusum_k, cusum_h;
    float integ0;
} sg_cfg_t;

static sg_cfg_t s_cfg = { .mitigate = true, .cusum_k = 0.05f, .cusum_h = 4.0f };
static volatile uint32_t s_epoch;   /* bumped on every config; tasks reset on change */
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static bool s_mac_ok;

static sg_cfg_t cfg_snapshot(uint32_t *epoch)
{
    portENTER_CRITICAL(&s_lock);
    sg_cfg_t c = s_cfg;
    *epoch = s_epoch;
    portEXIT_CRITICAL(&s_lock);
    return c;
}

/* ---- Shared state ----------------------------------------------------- */

typedef struct {
    float    y;
    uint32_t id;        /* accept counter, distinguishes new samples */
    uint32_t epoch;
} sample_t;

static QueueHandle_t s_latest;      /* length 1: overwrite / peek */

typedef struct {
    uint32_t k, epoch;
    int64_t  release_us;
    float    y, u_prev, u;
    bool     fresh;
    uint8_t  mode;
    int32_t  ctl_exec_us, ctl_rt_us;
} det_in_t;

static QueueHandle_t s_det_q;

typedef enum { MODE_NORMAL = 0, MODE_HOLD = 1, MODE_SAFE = 2 } ctl_mode_t;

/* Detector -> control (read once per job; 32-bit stores are atomic). */
static volatile uint8_t s_phys_alarm;
static volatile float s_t_hat;

/* ---- Tx queue ---------------------------------------------------------- */

typedef enum { TX_ACT, TX_TELEM } tx_kind_t;

typedef struct {
    det_in_t in;
    sg_det_out_t out;
    int32_t det_exec_us;
    uint32_t rx[SG_VERDICT_COUNT];
    uint32_t proto_n;
    int32_t proto_sum_us, proto_max_us;
} telem_t;

typedef struct {
    tx_kind_t kind;
    union {
        struct { float u; uint32_t seq; int64_t enq_us; } act;
        telem_t telem;
    };
} tx_item_t;

static QueueHandle_t s_tx_q;

/* ---- Statistics (cumulative since the last config) --------------------- */

typedef struct {
    uint32_t jobs, misses, stale_jobs, hold_jobs, safe_jobs;
    int64_t  wcrt_us, exec_max_us, exec_sum_us;
    uint32_t det_jobs, det_misses;
    int64_t  det_exec_max_us, det_exec_sum_us;
    uint32_t rx[SG_VERDICT_COUNT];
    uint32_t proto_n;
    int64_t  proto_sum_us, proto_max_us;
    /* per-telemetry-period proto timing, swapped out by the detector task */
    uint32_t pp_n;
    int64_t  pp_sum_us, pp_max_us;
    int64_t  tx_lat_max_us;
    uint32_t tx_drops;
} stats_t;

static stats_t s_stats;

/* ======================================================================= */
/* Receive path (MQTT task)                                                */
/* ======================================================================= */

static sg_proto_state_t s_proto;
static uint32_t s_rx_id;

static bool mac_verify(const uint8_t *data, size_t len, const uint8_t *mac)
{
    return s_mac_ok && sg_mac_verify(data, len, mac);
}

static void on_sensor(const uint8_t *data, size_t len)
{
    uint32_t epoch;
    sg_cfg_t cfg = cfg_snapshot(&epoch);

    const int64_t t0 = esp_timer_get_time();
    sg_msg_t m;
    sg_verdict_t v = sg_proto_check(&s_proto, &cfg.proto, data, len, t0, mac_verify, &m);
    if (v == SG_ACCEPT) {
        sample_t s = { .y = m.value, .id = ++s_rx_id, .epoch = epoch };
        xQueueOverwrite(s_latest, &s);
    }
    const int64_t dt = esp_timer_get_time() - t0;

    portENTER_CRITICAL(&s_lock);
    s_stats.rx[v]++;
    s_stats.proto_n++;
    s_stats.proto_sum_us += dt;
    if (dt > s_stats.proto_max_us) s_stats.proto_max_us = dt;
    s_stats.pp_n++;
    s_stats.pp_sum_us += dt;
    if (dt > s_stats.pp_max_us) s_stats.pp_max_us = dt;
    portEXIT_CRITICAL(&s_lock);
}

/* "run=7 seq=1 fresh=1 mac=1 phys=1 mitigate=1 k=0.05 h=4 integ=0.35" */
static void on_config(const uint8_t *data, size_t len)
{
    char buf[160];
    if (len >= sizeof buf) return;
    memcpy(buf, data, len);
    buf[len] = 0;

    sg_cfg_t c = { .mitigate = true, .cusum_k = 0.05f, .cusum_h = 4.0f };
    char *save = NULL;
    for (char *tok = strtok_r(buf, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
        char *eq = strchr(tok, '=');
        if (!eq) continue;
        *eq = 0;
        const char *key = tok, *val = eq + 1;
        if (!strcmp(key, "run")) c.run = strtoul(val, NULL, 10);
        else if (!strcmp(key, "seq")) c.proto.seq = atoi(val);
        else if (!strcmp(key, "fresh")) c.proto.fresh = atoi(val);
        else if (!strcmp(key, "mac")) c.proto.mac = atoi(val);
        else if (!strcmp(key, "phys")) c.phys = atoi(val);
        else if (!strcmp(key, "mitigate")) c.mitigate = atoi(val);
        else if (!strcmp(key, "k")) c.cusum_k = strtof(val, NULL);
        else if (!strcmp(key, "h")) c.cusum_h = strtof(val, NULL);
        else if (!strcmp(key, "integ")) c.integ0 = strtof(val, NULL);
    }

    sg_proto_reset(&s_proto);
    xQueueReset(s_latest);

    portENTER_CRITICAL(&s_lock);
    s_cfg = c;
    s_epoch++;
    memset(&s_stats, 0, sizeof s_stats);
    portEXIT_CRITICAL(&s_lock);
    s_phys_alarm = 0;

    char ack[96];
    int n = snprintf(ack, sizeof ack, "run=%" PRIu32 " epoch=%" PRIu32 " mac_ok=%d", c.run, s_epoch, s_mac_ok);
    sg_net_publish(SG_TOPIC_CFGACK, ack, n);
    ESP_LOGI(TAG, "config run=%" PRIu32 ": seq=%d fresh=%d mac=%d phys=%d mitigate=%d k=%.3f h=%.2f integ=%.3f",
             c.run, c.proto.seq, c.proto.fresh, c.proto.mac, c.phys, c.mitigate, c.cusum_k, c.cusum_h, c.integ0);
}

void sg_control_on_rx(sg_rx_topic_t topic, const uint8_t *data, size_t len)
{
    if (topic == SG_RX_SENSOR) on_sensor(data, len);
    else if (topic == SG_RX_CONFIG) on_config(data, len);
}

/* ======================================================================= */
/* Control task                                                            */
/* ======================================================================= */

static void control_task(void *arg)
{
    uint32_t epoch = UINT32_MAX;
    sg_cfg_t cfg = { 0 };
    sg_pi_t pi = { 0 };
    float u = 0;
    uint32_t act_seq = 0, last_id = 0;
    bool have = false;
    int stale = 0;

    /* Align to a tick boundary; job k is released at t0 + k*P. Response time
     * is measured from that nominal release, so delayed wake-ups count. */
    vTaskDelay(1);
    TickType_t last_wake = xTaskGetTickCount();
    const int64_t t0_us = esp_timer_get_time();

    for (uint32_t k = 1;; k++) {
        xTaskDelayUntil(&last_wake, pdMS_TO_TICKS(SG_CONTROL_PERIOD_MS));
        const int64_t release_us = t0_us + (int64_t)k * PERIOD_US;
        const int64_t start_us = esp_timer_get_time();

        if (s_epoch != epoch) {
            cfg = cfg_snapshot(&epoch);
            pi = (sg_pi_t){ .kp = SG_KP, .ki = SG_KI, .integ = cfg.integ0 };
            u = cfg.integ0;
            have = false;
            stale = 0;
        }

        sample_t s;
        bool fresh = false;
        if (xQueuePeek(s_latest, &s, 0) == pdTRUE && s.epoch == epoch && s.id != last_id) {
            last_id = s.id;
            fresh = true;
            have = true;
        }
        stale = fresh ? 0 : stale + 1;

        const float u_prev = u;
        ctl_mode_t mode = MODE_NORMAL;
        if (cfg.phys && cfg.mitigate && s_phys_alarm) {
            /* Sensor judged untrustworthy: control on the model estimate. */
            mode = MODE_SAFE;
            u = sg_pi_step(&pi, SG_SETPOINT_C, s_t_hat, DT_S);
        } else if (fresh) {
            u = sg_pi_step(&pi, SG_SETPOINT_C, s.y, DT_S);
        } else if (have && stale >= SG_STALE_LIMIT) {
            mode = MODE_HOLD;   /* sensor lost: keep u, do not integrate */
        }

        tx_item_t act = { .kind = TX_ACT };
        act.act.u = u;
        act.act.seq = ++act_seq;
        act.act.enq_us = esp_timer_get_time();
        bool act_ok = xQueueSend(s_tx_q, &act, 0) == pdTRUE;

        const int64_t end_us = esp_timer_get_time();
        const int64_t exec_us = end_us - start_us;
        const int64_t rt_us = end_us - release_us;

        det_in_t din = {
            .k = k, .epoch = epoch, .release_us = release_us,
            .y = fresh ? s.y : NAN, .u_prev = u_prev, .u = u, .fresh = fresh, .mode = mode,
            .ctl_exec_us = (int32_t)exec_us, .ctl_rt_us = (int32_t)rt_us,
        };
        bool det_ok = xQueueSend(s_det_q, &din, 0) == pdTRUE;

        portENTER_CRITICAL(&s_lock);
        s_stats.jobs++;
        if (rt_us > PERIOD_US) s_stats.misses++;
        if (!fresh) s_stats.stale_jobs++;
        if (mode == MODE_HOLD) s_stats.hold_jobs++;
        if (mode == MODE_SAFE) s_stats.safe_jobs++;
        if (rt_us > s_stats.wcrt_us) s_stats.wcrt_us = rt_us;
        if (exec_us > s_stats.exec_max_us) s_stats.exec_max_us = exec_us;
        s_stats.exec_sum_us += exec_us;
        if (!act_ok) s_stats.tx_drops++;
        if (!det_ok) s_stats.det_misses++;   /* detector fell a whole queue behind */
        portEXIT_CRITICAL(&s_lock);
    }
}

/* ======================================================================= */
/* Physics detector task                                                   */
/* ======================================================================= */

static void detector_task(void *arg)
{
    sg_det_params_t p;
    sg_det_t det;
    uint32_t epoch = UINT32_MAX;
    sg_cfg_t cfg = { 0 };
    det_in_t in;

    for (;;) {
        xQueueReceive(s_det_q, &in, portMAX_DELAY);
        const int64_t t0 = esp_timer_get_time();

        if (in.epoch != epoch) {
            cfg = cfg_snapshot(&epoch);
            sg_det_default_params(&p, DT_S);
            p.tau = SG_MODEL_TAU;
            p.gain = SG_MODEL_GAIN;
            p.tamb_nom = SG_MODEL_TAMB;
            p.cusum_k = cfg.cusum_k;
            p.cusum_h = cfg.cusum_h;
            sg_det_reset(&det);
            s_phys_alarm = 0;
        }
        if (in.epoch != epoch) {
            continue;   /* stale job from before a config change */
        }

        tx_item_t item = { .kind = TX_TELEM };
        telem_t *t = &item.telem;
        t->in = in;

        if (cfg.phys) {
            sg_det_step(&det, &p, in.y, in.fresh, in.u_prev, &t->out);
            s_t_hat = t->out.t_hat;
            s_phys_alarm = t->out.alarm;
        } else {
            t->out = (sg_det_out_t){ .r = NAN, .t_hat = NAN, .s_pos = NAN, .s_neg = NAN,
                                     .slope = NAN, .lo = NAN, .hi = NAN };
        }

        const int64_t end = esp_timer_get_time();
        t->det_exec_us = (int32_t)(end - t0);

        portENTER_CRITICAL(&s_lock);
        s_stats.det_jobs++;
        if (end - in.release_us > PERIOD_US) s_stats.det_misses++;
        if (end - t0 > s_stats.det_exec_max_us) s_stats.det_exec_max_us = end - t0;
        s_stats.det_exec_sum_us += end - t0;
        memcpy(t->rx, s_stats.rx, sizeof t->rx);
        t->proto_n = s_stats.pp_n;
        t->proto_sum_us = (int32_t)s_stats.pp_sum_us;
        t->proto_max_us = (int32_t)s_stats.pp_max_us;
        s_stats.pp_n = 0;
        s_stats.pp_sum_us = 0;
        s_stats.pp_max_us = 0;
        portEXIT_CRITICAL(&s_lock);

        if (xQueueSend(s_tx_q, &item, 0) != pdTRUE) {
            portENTER_CRITICAL(&s_lock);
            s_stats.tx_drops++;
            portEXIT_CRITICAL(&s_lock);
        }
    }
}

/* ======================================================================= */
/* Tx task: the only task that publishes per-period traffic                */
/* ======================================================================= */

/* Telemetry is batched: one sg/telem message carries TELEM_BATCH rows
 * (newline-separated). esp-mqtt's own task sends at most one queued message
 * per loop pass, so 10 small messages per second backed up without bound;
 * batching plus direct publishing from this task keeps the link clear. */
#define TELEM_BATCH     10
#define TELEM_BUF       (TELEM_BATCH * 330)

static void tx_task(void *arg)
{
    tx_item_t it;
    static char batch[TELEM_BUF];
    size_t used = 0;
    int rows = 0;

    for (;;) {
        if (xQueueReceive(s_tx_q, &it, pdMS_TO_TICKS(500)) != pdTRUE) {
            if (rows) {     /* stream paused: flush what we have */
                sg_net_publish(SG_TOPIC_TELEM, batch, used);
                used = 0;
                rows = 0;
            }
            continue;
        }

        if (it.kind == TX_ACT) {
            sg_msg_t m = {
                .version = SG_MSG_VERSION, .type = SG_MSG_ACTUATOR,
                .seq = it.act.seq, .ts_ms = (uint64_t)(it.act.enq_us / 1000), .value = it.act.u,
            };
            uint8_t buf[SG_MSG_LEN];
            sg_msg_encode(&m, buf);
            sg_net_publish(SG_TOPIC_ACTUATOR, buf, sizeof buf);

            int64_t lat = esp_timer_get_time() - it.act.enq_us;
            portENTER_CRITICAL(&s_lock);
            if (lat > s_stats.tx_lat_max_us) s_stats.tx_lat_max_us = lat;
            portEXIT_CRITICAL(&s_lock);
            continue;
        }

        const telem_t *t = &it.telem;
        const sg_det_out_t *o = &t->out;
        /* Column order is the contract with eval/ (see TELEM_COLUMNS there). */
        int n = snprintf(batch + used, sizeof batch - used,
            "%" PRId64 ",%" PRIu32 ",%.3f,%d,%.4f,%.4f,%d,%.3f,%.4f,%.3f,%.3f,%.4f,%.4f,%.4f,%u,"
            "%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ","
            "%" PRId32 ",%" PRId32 ",%" PRId32 ",%" PRIu32 ",%" PRId32 ",%" PRId32,
            t->in.release_us / 1000, t->in.k, t->in.y, t->in.fresh, t->in.u_prev, t->in.u, t->in.mode,
            o->t_hat, o->r, o->s_pos, o->s_neg, o->slope, o->lo, o->hi, o->alarm,
            t->rx[SG_ACCEPT], t->rx[SG_REJ_MAC], t->rx[SG_REJ_SEQ], t->rx[SG_REJ_FRESH], t->rx[SG_REJ_PARSE],
            t->in.ctl_exec_us, t->in.ctl_rt_us, t->det_exec_us,
            t->proto_n, t->proto_sum_us, t->proto_max_us);
        if (n > 0 && (size_t)n < sizeof batch - used - 1) {
            used += n;
            batch[used++] = '\n';
            rows++;
        }
        if (rows >= TELEM_BATCH || sizeof batch - used < 340) {
            sg_net_publish(SG_TOPIC_TELEM, batch, used - 1);   /* drop the trailing newline */
            used = 0;
            rows = 0;
        }
    }
}

/* ======================================================================= */
/* Stats task: 10 s summary on UART and sg/stats                           */
/* ======================================================================= */

static void stats_task(void *arg)
{
    char json[512];
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(SG_STATS_PERIOD_MS));

        uint32_t epoch;
        sg_cfg_t c = cfg_snapshot(&epoch);
        portENTER_CRITICAL(&s_lock);
        stats_t s = s_stats;
        portEXIT_CRITICAL(&s_lock);

        int n = snprintf(json, sizeof json,
            "{\"t_ms\":%" PRId64 ",\"run\":%" PRIu32 ",\"mac_ok\":%d"
            ",\"jobs\":%" PRIu32 ",\"misses\":%" PRIu32 ",\"stale\":%" PRIu32
            ",\"hold\":%" PRIu32 ",\"safe\":%" PRIu32
            ",\"wcrt_us\":%" PRId64 ",\"exec_max_us\":%" PRId64 ",\"exec_avg_us\":%" PRId64
            ",\"det_jobs\":%" PRIu32 ",\"det_misses\":%" PRIu32
            ",\"det_exec_max_us\":%" PRId64 ",\"det_exec_avg_us\":%" PRId64
            ",\"rx_accept\":%" PRIu32 ",\"rej_mac\":%" PRIu32 ",\"rej_seq\":%" PRIu32
            ",\"rej_fresh\":%" PRIu32 ",\"rej_parse\":%" PRIu32
            ",\"proto_n\":%" PRIu32 ",\"proto_max_us\":%" PRId64 ",\"proto_avg_us\":%" PRId64
            ",\"tx_lat_max_us\":%" PRId64 ",\"tx_drops\":%" PRIu32
            ",\"free_heap\":%" PRIu32 "}",
            esp_timer_get_time() / 1000, c.run, s_mac_ok,
            s.jobs, s.misses, s.stale_jobs, s.hold_jobs, s.safe_jobs,
            s.wcrt_us, s.exec_max_us, s.jobs ? s.exec_sum_us / s.jobs : 0,
            s.det_jobs, s.det_misses, s.det_exec_max_us, s.det_jobs ? s.det_exec_sum_us / s.det_jobs : 0,
            s.rx[SG_ACCEPT], s.rx[SG_REJ_MAC], s.rx[SG_REJ_SEQ], s.rx[SG_REJ_FRESH], s.rx[SG_REJ_PARSE],
            s.proto_n, s.proto_max_us, s.proto_n ? s.proto_sum_us / s.proto_n : 0,
            s.tx_lat_max_us, s.tx_drops, (uint32_t)esp_get_free_heap_size());

        if (n > 0 && n < (int)sizeof json) {
            printf("SGSTATS %s\n", json);
            sg_net_publish(SG_TOPIC_STATS, json, n);
        }
    }
}

void sg_control_start(bool mac_ok)
{
    s_mac_ok = mac_ok;
    s_latest = xQueueCreate(1, sizeof(sample_t));
    s_det_q = xQueueCreate(4, sizeof(det_in_t));
    s_tx_q = xQueueCreate(16, sizeof(tx_item_t));
    configASSERT(s_latest && s_det_q && s_tx_q);

    xTaskCreatePinnedToCore(control_task, "control", 4096, NULL, SG_CONTROL_PRIORITY, NULL, SG_CONTROL_CORE);
    xTaskCreatePinnedToCore(detector_task, "detector", 4096, NULL, SG_DETECT_PRIORITY, NULL, SG_DETECT_CORE);
    xTaskCreatePinnedToCore(tx_task, "tx", 4096, NULL, SG_TX_PRIORITY, NULL, SG_TX_CORE);
    xTaskCreatePinnedToCore(stats_task, "stats", 4096, NULL, 2, NULL, 0);
    ESP_LOGI(TAG, "period %d ms, setpoint %.1f C, Kp %.3f, Ki %.5f, mac_ok=%d",
             SG_CONTROL_PERIOD_MS, SG_SETPOINT_C, SG_KP, SG_KI, mac_ok);
}
