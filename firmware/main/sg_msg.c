#include "sg_msg.h"

#include <string.h>

static void put_u16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put_u32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = v >> (8 * i); }
static void put_u64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = v >> (8 * i); }

static uint16_t get_u16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t get_u32(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}
static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

void sg_msg_encode(const sg_msg_t *m, uint8_t out[SG_MSG_LEN])
{
    uint32_t fbits;
    memcpy(&fbits, &m->value, sizeof fbits);

    out[0] = m->version;
    out[1] = m->type;
    put_u16(&out[2], m->flags);
    put_u32(&out[4], m->seq);
    put_u64(&out[8], m->ts_ms);
    put_u32(&out[16], fbits);
    memcpy(&out[SG_MSG_MAC_OFF], m->mac, SG_MSG_MAC_LEN);
}

bool sg_msg_decode(const uint8_t *buf, size_t len, sg_msg_t *out)
{
    if (len != SG_MSG_LEN || buf[0] != SG_MSG_VERSION) {
        return false;
    }
    uint32_t fbits = get_u32(&buf[16]);

    out->version = buf[0];
    out->type    = buf[1];
    out->flags   = get_u16(&buf[2]);
    out->seq     = get_u32(&buf[4]);
    out->ts_ms   = get_u64(&buf[8]);
    memcpy(&out->value, &fbits, sizeof fbits);
    memcpy(out->mac, &buf[SG_MSG_MAC_OFF], SG_MSG_MAC_LEN);
    return true;
}
