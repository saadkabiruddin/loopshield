#pragma once
/* PI controller with conditional-integration anti-windup. Header-only so the
 * firmware and the host simulation (firmware/test/) run identical code. */
#include <stdbool.h>

typedef struct {
    float kp, ki;
    float integ;
} sg_pi_t;

/* The integrator stops while the output is saturated in the direction the
 * error pushes. It still integrates while unsaturated, which is what the
 * integral-windup attack (stretch goal) exploits. */
static inline float sg_pi_step(sg_pi_t *pi, float setpoint, float y, float dt)
{
    float e = setpoint - y;
    float u = pi->kp * e + pi->integ;

    bool sat_hi = u >= 1.0f && e > 0;
    bool sat_lo = u <= 0.0f && e < 0;
    if (!sat_hi && !sat_lo) {
        pi->integ += pi->ki * e * dt;
    }
    if (u > 1.0f) u = 1.0f;
    if (u < 0.0f) u = 0.0f;
    return u;
}
