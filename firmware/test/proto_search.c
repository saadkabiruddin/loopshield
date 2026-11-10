/*
 * Protocol state-machine search (stretch goal).
 *
 * Systematically explores what an on-path attacker can make the receiver's
 * protocol checks (sg_proto.c, the firmware's own code) ACCEPT, for every
 * combination of {seq, fresh, mac}.
 *
 * Model. Time advances in 50 ms steps. The genuine sender emits message i
 * (seq i, timestamp i*100 ms, signed) at t = i*100 ms. At each step the
 * attacker chooses one action:
 *     - deliver nothing,
 *     - deliver any genuine message emitted so far (on time, delayed,
 *       re-delivered, or out of order),
 *     - forge a message (cannot produce a valid MAC) with seq = last+1 or
 *       last+1000 and the current time as timestamp.
 *
 * A delivery that the receiver ACCEPTS is malicious if it is:
 *     FORGED  a message the sender never produced,
 *     REPLAY  a genuine message older than or equal to one already accepted,
 *     STALE   a genuine message more than STALE_MS old on arrival.
 *
 * The receiver first accepts genuine messages 0..PREFIX-1 on time (a running
 * system, not a cold start), then the attacker takes over. Depth-first
 * search up to MAX_DEPTH steps, memoised on (step, receiver state), finds
 * the shortest attack per (config, violation); it is exhaustive within that
 * bound.
 *
 * Separately, a cold-start receiver (no message accepted yet) accepts
 * whatever comes first, however old: that bootstrap case is reported on its
 * own line.
 */
#include <stdio.h>
#include <string.h>

#include "sg_proto.h"

#define STEP_MS     50
#define SEND_MS     100
#define MAX_DEPTH   28
#define PREFIX      3                   /* genuine msgs accepted on time first */
#define START_STEP  (PREFIX * SEND_MS / STEP_MS - 1)
#define STALE_MS    500
#define T0_MS       1762700000000ULL

enum { V_FORGED, V_REPLAY, V_STALE, V_COUNT };
static const char *vname[] = { "forged", "replay", "stale" };

typedef enum { A_NONE, A_GENUINE, A_FORGE_NEXT, A_FORGE_JUMP } act_t;
typedef struct { act_t a; int msg; } action_t;

static sg_proto_opts_t g_opts;
static int g_best_len[V_COUNT];
static action_t g_best[V_COUNT][MAX_DEPTH];
static action_t g_path[MAX_DEPTH];

/* MAC validity is decided by the attacker model, not by crypto: genuine
 * messages carry a valid MAC, forgeries never do. */
static int g_mac_valid;
static bool mac_cb(const uint8_t *d, size_t n, const uint8_t *m) { (void)d; (void)n; (void)m; return g_mac_valid; }

static void encode(uint8_t b[SG_MSG_LEN], uint32_t seq, uint64_t ts, bool sign)
{
    sg_msg_t m = { .version = SG_MSG_VERSION, .type = SG_MSG_SENSOR, .flags = sign ? SG_FLAG_MAC : 0,
                   .seq = seq, .ts_ms = ts, .value = 22.0f };
    sg_msg_encode(&m, b);
}

static void record(int v, int depth)
{
    if (g_best_len[v] == 0 || depth < g_best_len[v]) {
        g_best_len[v] = depth;
        memcpy(g_best[v], g_path, sizeof(action_t) * depth);
    }
}

/* Visited (step, receiver state, highest accepted) tuples. */
#define VIS_BITS 22
static uint64_t g_vis[1u << VIS_BITS];

static int visit(int depth, const sg_proto_state_t *st, int max_acc)
{
    uint64_t key = (uint64_t)depth
                 | (uint64_t)st->have << 6
                 | (uint64_t)(st->last_seq & 0xFFFF) << 7
                 | (uint64_t)(((st->last_ts_ms - T0_MS) / STEP_MS) & 0xFF) << 23
                 | (uint64_t)((st->last_local_us / 1000 / STEP_MS) & 0xFF) << 31
                 | (uint64_t)((max_acc + 1) & 0x3F) << 39;
    key += 1;   /* 0 marks an empty slot */
    uint64_t h = key * 0x9E3779B97F4A7C15ULL;
    for (uint32_t i = (uint32_t)(h >> (64 - VIS_BITS));; i = (i + 1) & ((1u << VIS_BITS) - 1)) {
        if (g_vis[i] == key) return 0;
        if (g_vis[i] == 0) { g_vis[i] = key; return 1; }
    }
}

/* max_acc: highest genuine index accepted so far (-1 none). */
static void dfs(int depth, sg_proto_state_t st, int max_acc)
{
    if (depth == MAX_DEPTH || !visit(depth, &st, max_acc)) return;

    const int64_t now_ms = (int64_t)depth * STEP_MS;
    const int emitted = (int)(now_ms / SEND_MS);    /* messages 0..emitted exist */

    /* Candidate actions. Genuine messages: only a few recent ones and the
     * oldest matter; others are equivalent for the checks. */
    action_t acts[MAX_DEPTH * STEP_MS / SEND_MS + 4];
    int n = 0;
    acts[n++] = (action_t){ A_NONE, -1 };
    for (int i = emitted; i >= 0; i--) acts[n++] = (action_t){ A_GENUINE, i };
    acts[n++] = (action_t){ A_FORGE_NEXT, -1 };
    acts[n++] = (action_t){ A_FORGE_JUMP, -1 };

    for (int k = 0; k < n; k++) {
        sg_proto_state_t s = st;
        int macc = max_acc;
        g_path[depth] = acts[k];
        if (acts[k].a == A_NONE) {
            dfs(depth + 1, s, macc);
            continue;
        }

        uint8_t b[SG_MSG_LEN];
        int genuine = acts[k].a == A_GENUINE;
        if (genuine) {
            encode(b, (uint32_t)acts[k].msg + 1, T0_MS + (uint64_t)acts[k].msg * SEND_MS, true);
            g_mac_valid = 1;
        } else {
            uint32_t seq = (st.have ? st.last_seq : 0) + (acts[k].a == A_FORGE_NEXT ? 1 : 1000);
            encode(b, seq, T0_MS + (uint64_t)now_ms, true);   /* claims a MAC it cannot have */
            g_mac_valid = 0;
        }

        sg_msg_t out;
        sg_verdict_t v = sg_proto_check(&s, &g_opts, b, sizeof b, now_ms * 1000, mac_cb, &out);
        if (v != SG_ACCEPT) {
            dfs(depth + 1, st, max_acc);    /* rejected: receiver state unchanged */
            continue;
        }
        if (!genuine) {
            record(V_FORGED, depth + 1);
        } else {
            if (acts[k].msg <= max_acc) record(V_REPLAY, depth + 1);
            if (now_ms - (int64_t)acts[k].msg * SEND_MS > STALE_MS) record(V_STALE, depth + 1);
            if (acts[k].msg > macc) macc = acts[k].msg;
        }
        dfs(depth + 1, s, macc);
    }
}

static void print_path(int v)
{
    for (int i = 0; i < g_best_len[v]; i++) {
        const action_t *a = &g_best[v][i];
        switch (a->a) {
        case A_NONE: break;   /* (steps before START_STEP are the honest prefix) */
        case A_GENUINE: printf(" t=%dms:deliver#%d", i * STEP_MS, a->msg); break;
        case A_FORGE_NEXT: printf(" t=%dms:forge(seq+1)", i * STEP_MS); break;
        case A_FORGE_JUMP: printf(" t=%dms:forge(seq+1000)", i * STEP_MS); break;
        }
    }
}

int main(void)
{
    printf("Protocol search: %d ms steps up to t=%d ms, stale = older than %d ms on arrival\n\n",
           STEP_MS, MAX_DEPTH * STEP_MS, STALE_MS);
    printf("%-18s %-8s %-8s %-8s\n", "checks", vname[0], vname[1], vname[2]);

    for (int cfg = 0; cfg < 8; cfg++) {
        g_opts = (sg_proto_opts_t){ .seq = cfg & 1, .fresh = (cfg >> 1) & 1, .mac = (cfg >> 2) & 1 };
        memset(g_best_len, 0, sizeof g_best_len);
        memset(g_vis, 0, sizeof g_vis);
        sg_proto_state_t st;
        sg_proto_reset(&st);
        /* Running system: genuine 0..PREFIX-1 accepted on time. */
        for (int i = 0; i < PREFIX; i++) {
            uint8_t b[SG_MSG_LEN];
            sg_msg_t out;
            encode(b, (uint32_t)i + 1, T0_MS + (uint64_t)i * SEND_MS, true);
            g_mac_valid = 1;
            sg_proto_check(&st, &g_opts, b, sizeof b, (int64_t)i * SEND_MS * 1000, mac_cb, &out);
        }
        for (int d = 0; d <= START_STEP; d++) g_path[d] = (action_t){ A_NONE, -1 };
        dfs(START_STEP + 1, st, PREFIX - 1);

        char name[32];
        snprintf(name, sizeof name, "%s%s%s", g_opts.mac ? "mac " : "", g_opts.seq ? "seq " : "",
                 g_opts.fresh ? "fresh" : "");
        if (!name[0]) strcpy(name, "(none)");
        printf("%-18s", name);
        for (int v = 0; v < V_COUNT; v++) {
            if (g_best_len[v]) printf(" %-8s", "FOUND");
            else printf(" %-8s", "-");
        }
        printf("\n");
        for (int v = 0; v < V_COUNT; v++) {
            if (!g_best_len[v]) continue;
            printf("    %-7s:", vname[v]);
            print_path(v);
            printf("\n");
        }
    }
    printf("\n'-' = nothing found: attacker acts from t=%d ms to t=%d ms after %d on-time messages.\n",
           (START_STEP + 1) * STEP_MS, MAX_DEPTH * STEP_MS, PREFIX);

    /* Cold start: the first message is checked against nothing. */
    sg_proto_state_t cold;
    sg_proto_reset(&cold);
    g_opts = (sg_proto_opts_t){ .seq = 1, .fresh = 1, .mac = 1 };
    uint8_t b[SG_MSG_LEN];
    sg_msg_t out;
    encode(b, 1, T0_MS, true);
    g_mac_valid = 1;
    sg_verdict_t v = sg_proto_check(&cold, &g_opts, b, sizeof b, 3600LL * 1000 * 1000, mac_cb, &out);
    printf("cold start, all checks: a 1-hour-old genuine message as the FIRST delivery is %s\n",
           v == SG_ACCEPT ? "ACCEPTED (trust on first message)" : "rejected");
    return 0;
}
