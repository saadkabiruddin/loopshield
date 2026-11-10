/*
 * Host-side closed-loop simulation for tuning and sanity-checking the
 * physics detector. Runs the firmware's own sg_pi.h and sg_detect.c against
 * the same room model as plant/, with the sensor-level effect of each attack
 * injected directly (as seen by a controller with NO protocol defense).
 *
 * This is not a substitute for the Wokwi runs: no network, no RTOS timing.
 * It answers "is the detector tuned sensibly?" in seconds instead of hours.
 *
 *   ./sim                      default h, all attacks + false-alarm rate
 *   ./sim --roc                sweep CUSUM h, print detection/false-alarm pairs
 *   ./sim --h 4 --k 0.1 --scale 1.022
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sg_detect.h"
#include "sg_pi.h"

#define DT          0.1
#define SP          22.0
#define TAMB        15.0
#define GAIN        20.0
#define TAU         60.0
#define NOISE       0.05
#define DROP_P      0.002   /* fraction of periods with no fresh sample */

#define WARMUP_S    30.0
#define ATTACK_S    120.0
#define RECOVER_S   30.0

/* A_DISTURB is not an attack: the ambient temperature really drops (a window
 * opens). It measures false alarms the physics layer raises on a legitimate
 * change its model does not know about. */
typedef enum { A_NONE, A_BIAS, A_RAMP, A_REPLAY, A_FORGERY, A_FLOOD, A_DISTURB, A_COUNT } attack_t;
static const char *attack_names[] = { "none", "bias", "ramp", "replay", "forgery", "flood", "disturb*" };

static double ramp_rate = -0.01;   /* degC/s */

typedef struct {
    float k, h;
    double scale;       /* plant seconds per controller second (Wokwi ~1.022) */
    int mitigate;
} cfg_t;

typedef struct {
    int detected;
    double t_detect;    /* s after attack start, -1 if none */
    int false_alarm;    /* alarm before attack start */
    double max_dev;     /* max |T_true - SP| from attack start to end */
    uint8_t alarm_bits;
} result_t;

static double gauss(void)
{
    double u1 = (rand() + 1.0) / (RAND_MAX + 2.0), u2 = rand() / (RAND_MAX + 1.0);
    return sqrt(-2 * log(u1)) * cos(2 * M_PI * u2);
}

static result_t run(attack_t atk, const cfg_t *c, unsigned seed)
{
    srand(seed);
    sg_det_params_t p;
    sg_det_default_params(&p, (float)DT);
    p.cusum_k = c->k;
    p.cusum_h = c->h;

    sg_det_t det;
    sg_det_reset(&det);
    sg_pi_t pi = { .kp = 0.5f, .ki = 0.5f / 60.0f, .integ = (float)((SP - TAMB) / GAIN) };

    double T = SP, tamb = TAMB;
    double u = pi.integ;
    float t_hat_prev = (float)SP;
    const double t_a = WARMUP_S, t_end = WARMUP_S + ATTACK_S + RECOVER_S;
    const int rec_n = (int)(30.0 / DT);
    float rec[512];
    int rec_i = 0, rec_w = 0;

    result_t res = { .t_detect = -1 };

    for (int k = 0; k * DT < t_end; k++) {
        double t = k * DT;
        int in_attack = atk != A_NONE && atk != A_DISTURB && t >= t_a && t < t_a + ATTACK_S;

        /* Plant over one control period with constant u (exact solution). */
        if ((atk == A_REPLAY || atk == A_DISTURB) && t >= t_a + 10) tamb = 5.0;   /* window opens */
        double target = tamb + GAIN * u;
        T = target + (T - target) * exp(-DT * c->scale / TAU);

        double y = T + NOISE * gauss();
        int fresh = (rand() / (double)RAND_MAX) > DROP_P;

        /* Replay attacker records the 30 s before the attack. */
        if (t >= t_a - 30.0 && t < t_a && rec_w < rec_n) rec[rec_w++] = (float)y;

        if (in_attack) {
            double ta = t - t_a;
            switch (atk) {
            case A_BIAS:    y += -3.0; break;
            case A_RAMP:    y += ramp_rate * ta; break;
            case A_REPLAY:  y = rec[rec_i++ % rec_w]; break;
            case A_FORGERY: y = 18.0; fresh = 1; break;
            case A_FLOOD:   y = 50.0 * rand() / (double)RAND_MAX; fresh = 1; break;
            default: break;
            }
        }

        sg_det_out_t o;
        sg_det_step(&det, &p, (float)y, fresh, (float)u, &o);

        if (o.new_alarm) {
            if (t < t_a || atk == A_NONE || atk == A_DISTURB) {
                res.false_alarm = 1;
            } else if (!res.detected && t < t_a + ATTACK_S) {
                res.detected = 1;
                res.t_detect = t - t_a;
            }
        }
        res.alarm_bits = o.alarm;

        /* Control: on a physics alarm (with mitigation), trust the model
         * estimate instead of the sensor. The firmware sees the detector's
         * output one period late, so use last period's estimate here too. */
        float meas = (c->mitigate && det.alarm) ? t_hat_prev : (float)y;
        if (fresh || (c->mitigate && det.alarm)) {
            u = sg_pi_step(&pi, (float)SP, meas, (float)DT);
        }
        t_hat_prev = o.t_hat;

        if (t >= t_a && fabs(T - SP) > res.max_dev) res.max_dev = fabs(T - SP);
    }
    return res;
}

/* False alarms per hour of attack-free operation. */
static double false_alarm_rate(const cfg_t *c, int hours)
{
    int alarms = 0;
    const int runs_per_hour = (int)(3600.0 / (WARMUP_S + ATTACK_S + RECOVER_S));
    for (int i = 0; i < hours * runs_per_hour; i++) {
        result_t r = run(A_NONE, c, 1000 + i);
        alarms += r.false_alarm;
    }
    return alarms / (double)hours;
}

int main(int argc, char **argv)
{
    cfg_t c = { .k = 0.05f, .h = 4.0f, .scale = 1.0, .mitigate = 1 };
    int roc = 0, trials = 20;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--roc")) roc = 1;
        else if (!strcmp(argv[i], "--h") && i + 1 < argc) c.h = (float)atof(argv[++i]);
        else if (!strcmp(argv[i], "--k") && i + 1 < argc) c.k = (float)atof(argv[++i]);
        else if (!strcmp(argv[i], "--scale") && i + 1 < argc) c.scale = atof(argv[++i]);
        else if (!strcmp(argv[i], "--no-mitigate")) c.mitigate = 0;
        else if (!strcmp(argv[i], "--ramp") && i + 1 < argc) ramp_rate = atof(argv[++i]);
        else if (!strcmp(argv[i], "--trials") && i + 1 < argc) trials = atoi(argv[++i]);
    }

    if (roc) {
        printf("h,false_alarms_per_hour,detect_rate_ramp,mean_ttd_ramp_s\n");
        const float hs[] = { 0.5f, 1, 1.5f, 2, 3, 4, 6, 8, 12, 16, 24, 32 };
        for (size_t i = 0; i < sizeof hs / sizeof hs[0]; i++) {
            c.h = hs[i];
            int det = 0;
            double ttd = 0;
            for (int s = 0; s < trials; s++) {
                result_t r = run(A_RAMP, &c, 1 + s);
                if (r.detected) { det++; ttd += r.t_detect; }
            }
            printf("%.1f,%.2f,%.2f,%.1f\n", c.h, false_alarm_rate(&c, 10),
                   det / (double)trials, det ? ttd / det : -1);
        }
        return 0;
    }

    printf("k=%.2f h=%.1f scale=%.3f mitigate=%d trials=%d\n", c.k, c.h, c.scale, c.mitigate, trials);
    printf("%-8s %8s %10s %10s %8s  %s\n", "attack", "detect", "ttd_s", "max_dev_C", "fa_pre", "by");
    for (int a = 0; a < A_COUNT; a++) {
        int det = 0, fa = 0;
        double ttd = 0, dev = 0;
        uint8_t bits = 0;
        for (int s = 0; s < trials; s++) {
            result_t r = run((attack_t)a, &c, 1 + s);
            det += r.detected;
            fa += r.false_alarm;
            if (r.detected) ttd += r.t_detect;
            if (r.max_dev > dev) dev = r.max_dev;
            bits |= r.alarm_bits;
        }
        printf("%-8s %5d/%-2d %10.1f %10.2f %8d  %s%s\n", attack_names[a], det, trials,
               det ? ttd / det : -1.0, dev, fa,
               (bits & SG_ALARM_CUSUM) ? "cusum " : "", (bits & SG_ALARM_INV) ? "invariant" : "");
    }
    printf("false alarms per hour (no attack): %.2f\n", false_alarm_rate(&c, 10));
    return 0;
}
