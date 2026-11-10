/* Thin C ABI over the firmware's portable modules, so the host stand-in
 * controller (firmware/test/hostctl) runs the exact same defense code as the
 * ESP32. Build: make -C firmware/test hostlib */
#include <stdlib.h>

#include "sg_detect.h"
#include "sg_pi.h"
#include "sg_proto.h"

static int s_mac_valid;
static bool mac_cb(const uint8_t *d, size_t n, const uint8_t *m) { (void)d; (void)n; (void)m; return s_mac_valid; }

void *sgw_proto_new(void) { sg_proto_state_t *s = malloc(sizeof *s); sg_proto_reset(s); return s; }
void sgw_proto_reset(void *s) { sg_proto_reset(s); }
void sgw_free(void *p) { free(p); }

/* mac_valid: result of the caller's own HMAC check (the host has no PSA). */
int sgw_proto_check(void *st, int seq, int fresh, int mac, const uint8_t *buf, int len,
                    int64_t now_us, int mac_valid, float *value)
{
    sg_proto_opts_t o = { .seq = seq, .fresh = fresh, .mac = mac };
    sg_msg_t m;
    s_mac_valid = mac_valid;
    sg_verdict_t v = sg_proto_check(st, &o, buf, (size_t)len, now_us, mac_cb, &m);
    if (v == SG_ACCEPT) *value = m.value;
    return (int)v;
}

typedef struct { sg_det_t d; sg_det_params_t p; } det_box_t;

void *sgw_det_new(float dt, float k, float h)
{
    det_box_t *b = malloc(sizeof *b);
    sg_det_default_params(&b->p, dt);
    b->p.cusum_k = k;
    b->p.cusum_h = h;
    sg_det_reset(&b->d);
    return b;
}

/* out: r, t_hat, s_pos, s_neg, slope, lo, hi ; returns latched alarm bits */
int sgw_det_step(void *box, float y, int fresh, float u_prev, float *out)
{
    det_box_t *b = box;
    sg_det_out_t o;
    sg_det_step(&b->d, &b->p, y, fresh, u_prev, &o);
    out[0] = o.r; out[1] = o.t_hat; out[2] = o.s_pos; out[3] = o.s_neg;
    out[4] = o.slope; out[5] = o.lo; out[6] = o.hi;
    return o.alarm;
}

float sgw_pi_step(float *integ, float kp, float ki, float sp, float y, float dt)
{
    sg_pi_t pi = { .kp = kp, .ki = ki, .integ = *integ };
    float u = sg_pi_step(&pi, sp, y, dt);
    *integ = pi.integ;
    return u;
}
