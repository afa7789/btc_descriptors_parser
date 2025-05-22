#include "bech32.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h> // Ensure stdbool.h is included for 'bool'

// The Bech32 character set
static const char *CHARSET = "qpzry9x8gf2tvdaj45fdzcvbhjqwkfgp";

// Generator coefficients for the Bech32/Bech32m checksum
static const uint32_t GENERATOR[] = {0x3b6a57b2UL, 0x26508e6dL, 0x1ea119faUL, 0x3d4233ddUL, 0x2a1462b3UL};

// PolyMod for Bech32 checksum calculation
static uint32_t polymod(const uint8_t *values, size_t len) {
    uint32_t chk = 1;
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = values[i];
        uint32_t top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ b;
        for (int j = 0; j < 5; ++j) {
            if ((top >> j) & 1) {
                chk ^= GENERATOR[j];
            }
        }
    }
    return chk;
}

// Expand the HRP into a form for checksumming.
static void hrp_expand(uint8_t *ret, const char *hrp) {
    size_t hrplen = strlen(hrp);
    for (size_t i = 0; i < hrplen; ++i) {
        ret[i] = hrp[i] >> 5;
    }
    ret[hrplen] = 0;
    for (size_t i = 0; i < hrplen; ++i) {
        ret[hrplen + 1 + i] = hrp[i] & 0x1f;
    }
}

// Create the checksum for a Bech32/Bech32m string
static void bech32_create_checksum(uint8_t *data, size_t data_len, uint32_t constant) {
    uint32_t chk = polymod(data, data_len);
    chk ^= constant; // Apply the constant for Bech32 or Bech32m
    for (int i = 0; i < 6; ++i) {
        data[data_len + i] = (chk >> (5 * (5 - i))) & 0x1f;
    }
}

// Convert between different bit sizes
int convert_bits(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen, int frombits, int tobits, int pad) {
    uint32_t acc = 0;
    int bits = 0;
    size_t i = 0;
    size_t o = 0;
    size_t max_outlen = *outlen;

    while (i < inlen) {
        acc = (acc << frombits) | in[i];
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            if (o >= max_outlen) return 0; // Output buffer too small
            out[o++] = (acc >> bits) & ((1 << tobits) - 1);
        }
        i++;
    }

    if (pad) {
        if (bits > 0) {
            if (o >= max_outlen) return 0; // Output buffer too small
            out[o++] = (acc << (tobits - bits)) & ((1 << tobits) - 1);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & ((1 << tobits) - 1))) {
        return 0; // Invalid padding
    }

    *outlen = o;
    return 1;
}

// Bech32 encoding
bool bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len) {
    if (strlen(hrp) + 7 + data_len > MAX_BECH32_LENGTH) {
        return false; // Resulting string too long
    }

    uint8_t checksum_data[strlen(hrp) * 2 + 1 + data_len + 6];
    size_t hrp_len = strlen(hrp);

    hrp_expand(checksum_data, hrp);
    memcpy(checksum_data + hrp_len * 2 + 1, data, data_len);

    bech32_create_checksum(checksum_data, hrp_len * 2 + 1 + data_len, 1); // Bech32 constant is 1

    size_t output_idx = 0;
    for (size_t i = 0; i < hrp_len; ++i) {
        output[output_idx++] = hrp[i];
    }
    output[output_idx++] = '1';

    for (size_t i = 0; i < data_len; ++i) {
        output[output_idx++] = CHARSET[data[i]];
    }

    for (size_t i = 0; i < 6; ++i) {
        output[output_idx++] = CHARSET[checksum_data[hrp_len * 2 + 1 + data_len + i]];
    }
    output[output_idx] = '\0';

    return true;
}

// Bech32m encoding
bool bech32m_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len) {
    if (strlen(hrp) + 7 + data_len > MAX_BECH32_LENGTH) {
        return false; // Resulting string too long
    }

    uint8_t checksum_data[strlen(hrp) * 2 + 1 + data_len + 6];
    size_t hrp_len = strlen(hrp);

    hrp_expand(checksum_data, hrp);
    memcpy(checksum_data + hrp_len * 2 + 1, data, data_len);

    // Bech32m constant is 0x2bc830a3UL
    bech32_create_checksum(checksum_data, hrp_len * 2 + 1 + data_len, 0x2bc830a3UL);

    size_t output_idx = 0;
    for (size_t i = 0; i < hrp_len; ++i) {
        output[output_idx++] = hrp[i];
    }
    output[output_idx++] = '1';

    for (size_t i = 0; i < data_len; ++i) {
        output[output_idx++] = CHARSET[data[i]];
    }

    for (size_t i = 0; i < 6; ++i) {
        output[output_idx++] = CHARSET[checksum_data[hrp_len * 2 + 1 + data_len + i]];
    }
    output[output_idx] = '\0';

    return true;
}