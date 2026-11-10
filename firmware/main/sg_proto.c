#include "sg_proto.h"

#include <string.h>

void sg_proto_reset(sg_proto_state_t *st)
{
    memset(st, 0, sizeof *st);
}

sg_verdict_t sg_proto_check(sg_proto_state_t *st, const sg_proto_opts_t *opts,
                            const uint8_t *buf, size_t len, int64_t now_us,
                            sg_mac_verify_fn mac_verify, sg_msg_t *out)
{
    if (!sg_msg_decode(buf, len, out) || out->type != SG_MSG_SENSOR) {
        return SG_REJ_PARSE;
    }

    if (opts->mac) {
        if (!(out->flags & SG_FLAG_MAC) || !mac_verify(buf, SG_MSG_MAC_OFF, out->mac)) {
            return SG_REJ_MAC;
        }
    }

    const int64_t now_ms = now_us / 1000;
    const int64_t offset = now_ms - (int64_t)out->ts_ms;
    bool new_min = !st->have;

    if (st->have) {
        if (opts->seq && out->seq <= st->last_seq) {
            return SG_REJ_SEQ;
        }
        if (opts->fresh) {
            /* Old or duplicated timestamps are never fresh. */
            if (out->ts_ms <= st->last_ts_ms) {
                return SG_REJ_FRESH;
            }
            int64_t allowed = st->min_offset_ms + SG_FRESH_WINDOW_MS +
                              (int64_t)(SG_FRESH_DRIFT * (float)(now_ms - st->min_offset_at_ms));
            if (offset > allowed) {
                return SG_REJ_FRESH;
            }
        }
        new_min = offset < st->min_offset_ms;
    }

    st->have = true;
    st->last_seq = out->seq;
    st->last_ts_ms = out->ts_ms;
    st->last_local_us = now_us;
    if (new_min) {
        st->min_offset_ms = offset;
        st->min_offset_at_ms = now_ms;
    }
    return SG_ACCEPT;
}

const char *sg_verdict_name(sg_verdict_t v)
{
    switch (v) {
    case SG_ACCEPT:    return "accept";
    case SG_REJ_PARSE: return "parse";
    case SG_REJ_MAC:   return "mac";
    case SG_REJ_SEQ:   return "seq";
    case SG_REJ_FRESH: return "fresh";
    default:           return "?";
    }
}
