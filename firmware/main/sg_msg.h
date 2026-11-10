#pragma once
/*
 * LoopShield wire format. Fixed 28 bytes, little-endian. Must stay in sync
 * with shared/SgMessage.cs.
 *
 *   off size field
 *    0   1   version    (SG_MSG_VERSION)
 *    1   1   type       (sg_msg_type_t)
 *    2   2   flags      (bit0: mac field is valid)
 *    4   4   seq        sender's monotonically increasing counter
 *    8   8   ts_ms      sender's clock, ms
 *   16   4   value      float32: temperature degC (sensor) or duty 0..1 (actuator)
 *   20   8   mac        truncated HMAC-SHA256 over bytes 0..19
 *
 * All fields exist from day one so enabling the protocol defenses later
 * changes only the checking, never the message size or parse cost.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SG_MSG_VERSION   1
#define SG_MSG_LEN       28
#define SG_MSG_MAC_OFF   20
#define SG_MSG_MAC_LEN   8

#define SG_FLAG_MAC      0x0001

typedef enum {
    SG_MSG_SENSOR   = 1,
    SG_MSG_ACTUATOR = 2,
} sg_msg_type_t;

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t seq;
    uint64_t ts_ms;
    float    value;
    uint8_t  mac[SG_MSG_MAC_LEN];
} sg_msg_t;

void sg_msg_encode(const sg_msg_t *m, uint8_t out[SG_MSG_LEN]);
bool sg_msg_decode(const uint8_t *buf, size_t len, sg_msg_t *out);
