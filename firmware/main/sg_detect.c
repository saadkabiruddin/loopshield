#include "sg_detect.h"

#include <math.h>
#include <string.h>

void sg_det_default_params(sg_det_params_t *p, float dt)
{
    p->dt = dt;
    p->tau = 60.0f;
    p->gain = 20.0f;
    p->tamb_nom = 15.0f;
    p->l = 0.01f;           /* ~10 s correction time constant at 10 Hz */
    p->cusum_k = 0.05f;     /* ~1 sigma of sensor noise; tuned in test/sim.c */
    p->cusum_h = 4.0f;
    p->tamb_min = 5.0f;
    p->tamb_max = 25.0f;
    p->slope_tol = 0.06f;   /* ~3 sigma of the 20-sample slope estimate */
    p->inv_persist = 3;
}

void sg_det_reset(sg_det_t *d)
{
    memset(d, 0, sizeof *d);
}

/* Least-squares slope of buf over the window, oldest sample at d->idx. */
static float window_slope(const sg_det_t *d, float dt)
{
    const int n = SG_DET_WIN;
    const float xm = (n - 1) / 2.0f;
    float ym = 0;
    for (int i = 0; i < n; i++) ym += d->ybuf[i];
    ym /= n;

    float sxy = 0, sxx = 0;
    for (int i = 0; i < n; i++) {
        float x = i - xm;
        float y = d->ybuf[(d->idx + i) % n] - ym;
        sxy += x * y;
        sxx += x * x;
    }
    return sxy / sxx / dt;
}

void sg_det_step(sg_det_t *d, const sg_det_params_t *p, float y, bool fresh,
                 float u_prev, sg_det_out_t *out)
{
    const uint8_t before = d->alarm;

    out->r = NAN;
    out->slope = out->lo = out->hi = NAN;
    out->inv_violation = false;

    if (!d->init) {
        if (fresh) {
            d->t_hat = y;
            d->init = true;
        }
        goto done;
    }

    /* Model prediction for this step. */
    float t_pred = d->t_hat + p->dt / p->tau * ((p->tamb_nom - d->t_hat) + p->gain * u_prev);

    if (!fresh) {
        d->t_hat = t_pred;
        goto done;
    }

    /* Observer + CUSUM. */
    float r = y - t_pred;
    out->r = r;
    d->t_hat = d->alarm ? t_pred : t_pred + p->l * r;

    d->s_pos = fmaxf(0.0f, d->s_pos + r - p->cusum_k);
    d->s_neg = fmaxf(0.0f, d->s_neg - r - p->cusum_k);
    if (d->s_pos > p->cusum_h || d->s_neg > p->cusum_h) {
        d->alarm |= SG_ALARM_CUSUM;
    }

    /* Invariant over the sliding window. */
    d->ybuf[d->idx] = y;
    d->ubuf[d->idx] = u_prev;
    d->idx = (d->idx + 1) % SG_DET_WIN;
    if (d->n < SG_DET_WIN) d->n++;

    if (d->n == SG_DET_WIN) {
        float ym = 0, um = 0;
        for (int i = 0; i < SG_DET_WIN; i++) { ym += d->ybuf[i]; um += d->ubuf[i]; }
        ym /= SG_DET_WIN;
        um /= SG_DET_WIN;

        float slope = window_slope(d, p->dt);
        float lo = ((p->tamb_min - ym) + p->gain * um) / p->tau - p->slope_tol;
        float hi = ((p->tamb_max - ym) + p->gain * um) / p->tau + p->slope_tol;
        out->slope = slope;
        out->lo = lo;
        out->hi = hi;

        if (slope < lo || slope > hi) {
            out->inv_violation = true;
            if (++d->inv_run >= p->inv_persist) d->alarm |= SG_ALARM_INV;
        } else {
            d->inv_run = 0;
        }
    }

done:
    out->t_hat = d->t_hat;
    out->s_pos = d->s_pos;
    out->s_neg = d->s_neg;
    out->alarm = d->alarm;
    out->new_alarm = d->alarm & ~before;
}
