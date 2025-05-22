#ifndef BECH32_H
#define BECH32_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Max length of a Bech32/Bech32m string
#define MAX_BECH32_LENGTH 90

// Function to convert between different bit sizes
int convert_bits(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen, int frombits, int tobits, int pad);

// Bech32 encoding (for P2WPKH - segwit version 0)
// hrp: Human-readable part (e.g., "bc", "tb")
// data: 5-bit array representing the witness program
// data_len: length of the 5-bit array
// output: buffer to store the Bech32 encoded string
// output_size: size of the output buffer
// Returns true on success, false on failure.
bool bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len);

// Bech32m encoding (for P2TR - segwit version 1)
// hrp: Human-readable part (e.g., "bc", "tb")
// data: 5-bit array representing the witness program
// data_len: length of the 5-bit array
// output: buffer to store the Bech32m encoded string
// output_size: size of the output buffer
// Returns true on success, false on failure.
bool bech32m_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len);

#endif /* BECH32_H */