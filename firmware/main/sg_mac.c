#include "sg_mac.h"

#include <string.h>

#include "esp_log.h"
#include "psa/crypto.h"

#include "sg_config.h"
#include "sg_msg.h"

static const char *TAG = "sg_mac";

#define SG_MAC_ALG PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), SG_MSG_MAC_LEN)

static psa_key_id_t s_key;

bool sg_mac_verify(const uint8_t *data, size_t len, const uint8_t *mac)
{
    /* psa_mac_verify compares in constant time. */
    return psa_mac_verify(s_key, SG_MAC_ALG, data, len, mac, SG_MSG_MAC_LEN) == PSA_SUCCESS;
}

bool sg_mac_init(void)
{
    static const uint8_t key[] = SG_HMAC_KEY;

    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)st);
        return false;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attr, SG_MAC_ALG);
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    st = psa_import_key(&attr, key, sizeof key, &s_key);
    psa_reset_key_attributes(&attr);
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key failed: %d", (int)st);
        return false;
    }

    /* Known answer, computed independently with Python's hmac module:
     * sensor msg {flags=MAC, seq=1, ts=1762700000000, value=22.0}. */
    static const uint8_t expect[SG_MSG_MAC_LEN] = { 0x85, 0x21, 0x14, 0x31, 0xa9, 0x15, 0xf2, 0x45 };
    sg_msg_t m = { .version = SG_MSG_VERSION, .type = SG_MSG_SENSOR, .flags = SG_FLAG_MAC,
                   .seq = 1, .ts_ms = 1762700000000ULL, .value = 22.0f };
    uint8_t buf[SG_MSG_LEN];
    sg_msg_encode(&m, buf);

    uint8_t got[SG_MSG_MAC_LEN];
    size_t got_len = 0;
    st = psa_mac_compute(s_key, SG_MAC_ALG, buf, SG_MSG_MAC_OFF, got, sizeof got, &got_len);
    if (st != PSA_SUCCESS || got_len != SG_MSG_MAC_LEN || memcmp(got, expect, sizeof got) != 0) {
        ESP_LOGE(TAG, "HMAC self-test FAILED (status %d)", (int)st);
        return false;
    }
    if (!sg_mac_verify(buf, SG_MSG_MAC_OFF, expect)) {
        ESP_LOGE(TAG, "HMAC verify self-test FAILED");
        return false;
    }
    ESP_LOGI(TAG, "HMAC-SHA256/64 self-test passed");
    return true;
}
