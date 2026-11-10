#pragma once
/* Truncated HMAC-SHA256 (first SG_MSG_MAC_LEN bytes) via PSA Crypto. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Imports the key and runs a known-answer self-test. Returns false (and logs
 * why) if either fails; the protocol MAC check must not be trusted then. */
bool sg_mac_init(void);

bool sg_mac_verify(const uint8_t *data, size_t len, const uint8_t *mac);
