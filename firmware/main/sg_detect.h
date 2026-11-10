#pragma once
/*
 * Physics-layer defense. Pure C (host-testable, see firmware/test/).
 *
 * Plant model (first-order room):   dT/dt = ((T_amb - T) + K u) / tau
 *
 * 1. Observer. T_hat follows the model driven by the heater command u, with
 *    a small correction toward the measurement y:
 *        T_hat <- T_hat + dt/tau ((T_amb - T_hat) + K u) + l (y - T_hat)
 *    The innovation r = y - T_hat_pred is ~zero-mean noise when the sensor
 *    tells the truth, and is pushed away from zero by spoofing: a bias shifts
 *    it immediately, and a slow ramp produces a persistent offset because the
 *    closed loop drives y to the setpoint while u (which the observer sees)
 *    follows the TRUE temperature.
 *
 * 2. CUSUM on r (two-sided):  S+ = max(0, S+ + r - k),  S- = max(0, S- - r - k).
 *    Alarm when either exceeds h. k sets the smallest shift worth caring
 *    about; h trades detection delay against false alarms (ROC over h).
 *
 * 3. Invariant: the least-squares slope of y over the last window must lie
 *    in the range the physics allows for the observed u and any ambient
 *    temperature in [tamb_min, tamb_max]. "Heater full on but temperature
 *    not rising" or "temperature jumps faster than any heater can" both
 *    violate it. Needs `inv_persist` consecutive violations to alarm.
 *
 * After an alarm the observer stops correcting toward y (it no longer trusts
 * the sensor), so T_hat becomes a pure model prediction the controller can
 * fall back on.
 */
#include <stdbool.h>
#include <stdint.h>

#define SG_DET_WIN 20   /* invariant window, samples (2 s at 10 Hz) */

typedef struct {
    float dt;           /* s per step */
    float tau, gain, tamb_nom;
    float l;            /* observer correction gain per step */
    float cusum_k, cusum_h;
    float tamb_min, tamb_max;
    float slope_tol;    /* degC/s added to each side of the invariant band */
    int   inv_persist;
} sg_det_params_t;

void sg_det_default_params(sg_det_params_t *p, float dt);

enum {
    SG_ALARM_CUSUM = 1 << 0,
    SG_ALARM_INV   = 1 << 1,
};

typedef struct {
    bool  init;
    float t_hat;
    float s_pos, s_neg;
    float ybuf[SG_DET_WIN];
    float ubuf[SG_DET_WIN];
    int   n, idx;
    int   inv_run;      /* consecutive violating steps */
    uint8_t alarm;      /* latched SG_ALARM_* bits */
} sg_det_t;

typedef struct {
    float r;            /* innovation (NAN if no fresh sample) */
    float t_hat;
    float s_pos, s_neg;
    float slope, lo, hi;/* invariant: observed slope and allowed band (NAN until window full) */
    bool  inv_violation;
    uint8_t alarm;      /* latched bits after this step */
    uint8_t new_alarm;  /* bits raised in this step */
} sg_det_out_t;

void sg_det_reset(sg_det_t *d);

/* One step per control period. u_prev is the heater command that acted on
 * the plant during the period that just ended; y is this period's accepted
 * measurement, valid only if `fresh`. */
void sg_det_step(sg_det_t *d, const sg_det_params_t *p, float y, bool fresh,
                 float u_prev, sg_det_out_t *out);
