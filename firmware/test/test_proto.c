/* Host unit tests for the protocol-layer checks (sg_proto.c). */
#include <stdio.h>
#include <string.h>

#include "sg_proto.h"

/* Stand-in MAC for host tests: XOR-fold of the data. The real firmware uses
 * truncated HMAC-SHA256; only accept/reject behaviour matters here. */
static void fake_mac(const uint8_t *data, size_t len, uint8_t out[SG_MSG_MAC_LEN])
{
    memset(out, 0xA5, SG_MSG_MAC_LEN);
    for (size_t i = 0; i < len; i++) out[i % SG_MSG_MAC_LEN] ^= (uint8_t)(data[i] + i);
}
static bool fake_verify(const uint8_t *data, size_t len, const uint8_t *mac)
{
    uint8_t m[SG_MSG_MAC_LEN];
    fake_mac(data, len, m);
    return memcmp(m, mac, SG_MSG_MAC_LEN) == 0;
}

static void make(uint8_t buf[SG_MSG_LEN], uint32_t seq, uint64_t ts, float v, bool sign)
{
    sg_msg_t m = { .version = SG_MSG_VERSION, .type = SG_MSG_SENSOR,
                   .flags = sign ? SG_FLAG_MAC : 0, .seq = seq, .ts_ms = ts, .value = v };
    sg_msg_encode(&m, buf);
    if (sign) {
        fake_mac(buf, SG_MSG_MAC_OFF, &buf[SG_MSG_MAC_OFF]);
    }
}

static int failures;
#define EXPECT(got, want, what) do { \
    sg_verdict_t g_ = (got); \
    if (g_ != (want)) { failures++; printf("FAIL %-48s got %s want %s\n", what, sg_verdict_name(g_), sg_verdict_name(want)); } \
    else printf("ok   %s\n", what); } while (0)

int main(void)
{
    uint8_t b[SG_MSG_LEN];
    sg_msg_t out;
    sg_proto_state_t st;
    const sg_proto_opts_t all = { .seq = true, .fresh = true, .mac = true };
    const sg_proto_opts_t none = { 0 };
    const sg_proto_opts_t seq_only = { .seq = true };
    const sg_proto_opts_t fresh_only = { .fresh = true };

    /* Genuine stream: 100 ms apart on both clocks. */
    sg_proto_reset(&st);
    int64_t now = 5000000;
    uint64_t ts = 1762700000000ULL;
    for (uint32_t s = 1; s <= 5; s++, now += 100000, ts += 100) {
        make(b, s, ts, 22.0f, true);
        EXPECT(sg_proto_check(&st, &all, b, sizeof b, now, fake_verify, &out), SG_ACCEPT, "genuine stream accepted");
    }

    /* Replay of an old genuine message. */
    make(b, 3, ts - 300, 22.0f, true);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now, fake_verify, &out), SG_REJ_SEQ, "replayed old message -> seq");
    EXPECT(sg_proto_check(&st, &fresh_only, b, sizeof b, now, fake_verify, &out), SG_REJ_FRESH, "replayed old message, fresh only -> fresh");
    EXPECT(sg_proto_check(&st, &none, b, sizeof b, now, fake_verify, &out), SG_ACCEPT, "replayed old message, no defense -> accepted");

    /* Modified value (bias attack) breaks the MAC. */
    sg_proto_reset(&st);
    make(b, 10, ts, 22.0f, true);
    sg_proto_check(&st, &all, b, sizeof b, now, fake_verify, &out);
    make(b, 11, ts + 100, 22.0f, true);
    float biased = 19.0f;
    memcpy(&b[16], &biased, 4);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + 100000, fake_verify, &out), SG_REJ_MAC, "value modified in flight -> mac");

    /* Forgery without the key: unsigned, or signed with garbage. */
    make(b, 12, ts + 200, 18.0f, false);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + 200000, fake_verify, &out), SG_REJ_MAC, "unsigned forgery -> mac");
    make(b, 12, ts + 200, 18.0f, false);
    b[2] = SG_FLAG_MAC;
    memset(&b[SG_MSG_MAC_OFF], 0x42, SG_MSG_MAC_LEN);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + 200000, fake_verify, &out), SG_REJ_MAC, "garbage-MAC forgery -> mac");

    /* Without MAC, a forged high sequence number wins and then locks out the
     * genuine sender: seq numbers alone do not stop forgery. */
    sg_proto_reset(&st);
    make(b, 20, ts, 22.0f, true);
    sg_proto_check(&st, &seq_only, b, sizeof b, now, fake_verify, &out);
    make(b, 21, ts + 50, 18.0f, false);
    EXPECT(sg_proto_check(&st, &seq_only, b, sizeof b, now + 50000, fake_verify, &out), SG_ACCEPT, "forged seq+1, seq only -> accepted");
    make(b, 21, ts + 100, 22.0f, true);
    EXPECT(sg_proto_check(&st, &seq_only, b, sizeof b, now + 100000, fake_verify, &out), SG_REJ_SEQ, "genuine after forgery, seq only -> seq (lockout)");

    /* Delay attack: a genuine message held back by 1 s. */
    sg_proto_reset(&st);
    make(b, 30, ts, 22.0f, true);
    sg_proto_check(&st, &all, b, sizeof b, now, fake_verify, &out);
    make(b, 31, ts + 100, 22.0f, true);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + 1100000, fake_verify, &out), SG_REJ_FRESH, "message delayed 1 s -> fresh");

    /* Network jitter of 150 ms is tolerated. */
    make(b, 32, ts + 200, 22.0f, true);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + 350000, fake_verify, &out), SG_ACCEPT, "150 ms jitter tolerated");

    /* Receiver clock 2.2% slow (Wokwi) over a 30 s gap is tolerated. */
    sg_proto_reset(&st);
    make(b, 40, ts, 22.0f, true);
    sg_proto_check(&st, &all, b, sizeof b, now, fake_verify, &out);
    make(b, 41, ts + 30000, 22.0f, true);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + (int64_t)(30000 * 0.978) * 1000, fake_verify, &out), SG_ACCEPT, "30 s gap with 2.2% clock skew tolerated");

    /* Incremental delay (found by proto_search.c against the old relative
     * check): each message 200 ms later than the one before. The first is
     * within the window; the accumulated delay must not be. */
    sg_proto_reset(&st);
    for (int i = 0; i < 3; i++) {
        make(b, 60 + i, ts + i * 100, 22.0f, true);
        sg_proto_check(&st, &all, b, sizeof b, now + i * 100000, fake_verify, &out);
    }
    make(b, 63, ts + 300, 22.0f, true);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + 300000 + 200000, fake_verify, &out), SG_ACCEPT, "first message delayed 200 ms tolerated");
    make(b, 64, ts + 400, 22.0f, true);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + 400000 + 400000, fake_verify, &out), SG_REJ_FRESH, "next delayed 400 ms (incremental delay) -> fresh");
    make(b, 65, ts + 500, 22.0f, true);
    EXPECT(sg_proto_check(&st, &all, b, sizeof b, now + 500000 + 600000, fake_verify, &out), SG_REJ_FRESH, "next delayed 600 ms (incremental delay) -> fresh");

    /* Receiver clock 0.5% FAST over 60 s (offset creeps up) is tolerated. */
    sg_proto_reset(&st);
    for (int i = 0; i <= 600; i++) {
        make(b, 100 + i, ts + i * 100, 22.0f, true);
        sg_verdict_t v = sg_proto_check(&st, &all, b, sizeof b, now + (int64_t)(i * 100 * 1.005) * 1000, fake_verify, &out);
        if (v != SG_ACCEPT) { EXPECT(v, SG_ACCEPT, "receiver clock 0.5% fast over 60 s tolerated"); break; }
        if (i == 600) EXPECT(v, SG_ACCEPT, "receiver clock 0.5% fast over 60 s tolerated");
    }

    /* Malformed input. */
    EXPECT(sg_proto_check(&st, &none, b, 27, now, fake_verify, &out), SG_REJ_PARSE, "short message -> parse");
    make(b, 50, ts, 22.0f, true);
    b[1] = SG_MSG_ACTUATOR;
    EXPECT(sg_proto_check(&st, &none, b, sizeof b, now, fake_verify, &out), SG_REJ_PARSE, "wrong type -> parse");

    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures != 0;
}
