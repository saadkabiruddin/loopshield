#pragma once
/*
 * Protocol-layer defense: per-message checks on the sensor link.
 *
 * Pure C with no ESP-IDF dependencies so it can be unit-tested on the host
 * (firmware/test/). The MAC primitive is injected as a callback.
 *
 * Check order: parse -> MAC -> sequence -> freshness. The MAC goes first so
 * that unauthenticated messages can never advance the seq/time state.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sg_msg.h"

typedef struct {
    bool seq;       /* require strictly increasing sequence numbers */
    bool fresh;     /* require timestamps consistent with local elapsed time */
    bool mac;       /* require a valid truncated HMAC */
} sg_proto_opts_t;

/* Freshness without synchronised clocks.
 *
 * offset = local_time - sender_timestamp is the network delay plus the clock
 * offset. Delaying a message can only INCREASE it, so the receiver tracks the
 * smallest offset seen (the least-delayed delivery) and rejects messages whose
 * offset exceeds that minimum by more than SG_FRESH_WINDOW_MS. The minimum is
 * allowed to creep up by SG_FRESH_DRIFT (fraction of elapsed time) to absorb a
 * receiver clock that runs fast; a receiver clock that runs slow (Wokwi, ~2%)
 * just keeps lowering the minimum. Sender timestamps must also strictly
 * increase, which rejects replays and duplicates.
 *
 * An earlier version compared each message only with the LAST accepted one.
 * The protocol search (firmware/test/proto_search.c) showed that this lets
 * an attacker add a little delay per message and grow it without bound. With
 * the minimum-offset reference, the added delay is capped at
 * SG_FRESH_WINDOW_MS + SG_FRESH_DRIFT * (time since the last on-time message). */
#define SG_FRESH_WINDOW_MS  250
#define SG_FRESH_DRIFT      0.01f

typedef enum {
    SG_ACCEPT = 0,
    SG_REJ_PARSE,   /* wrong length/version/type */
    SG_REJ_MAC,
    SG_REJ_SEQ,
    SG_REJ_FRESH,
    SG_VERDICT_COUNT,
} sg_verdict_t;

typedef struct {
    bool     have;
    uint32_t last_seq;
    uint64_t last_ts_ms;
    int64_t  last_local_us;
    int64_t  min_offset_ms;     /* smallest local-minus-sender offset seen */
    int64_t  min_offset_at_ms;  /* local time it was seen (drift allowance origin) */
} sg_proto_state_t;

/* Returns true if mac[0..SG_MSG_MAC_LEN) is valid for data[0..len). */
typedef bool (*sg_mac_verify_fn)(const uint8_t *data, size_t len, const uint8_t *mac);

void sg_proto_reset(sg_proto_state_t *st);

sg_verdict_t sg_proto_check(sg_proto_state_t *st, const sg_proto_opts_t *opts,
                            const uint8_t *buf, size_t len, int64_t now_us,
                            sg_mac_verify_fn mac_verify, sg_msg_t *out);

const char *sg_verdict_name(sg_verdict_t v);
