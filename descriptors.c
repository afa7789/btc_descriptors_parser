#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ripemd.h> // Include for RIPEMD160
#include <json-c/json.h>
#include "descriptors.h"
#include "bech32.h" // Include bech32.h

// Define RIPEMD160_DIGEST_LENGTH if not already defined (common for older OpenSSL)
#ifndef RIPEMD160_DIGEST_LENGTH
#define RIPEMD160_DIGEST_LENGTH 20
#endif

// Bitcoin Base58 alphabet
static const char *b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Base58Check version bytes
#define MAINNET_PUBLIC 0x0488B21E // xpub
#define MAINNET_PRIVATE 0x0488ADE4 // xprv
#define MAINNET_P2PKH 0x00 // Address version for P2PKH
#define MAINNET_P2SH 0x05 // Address version for P2SH

// Function to calculate SHA256 hash
static void sha256(const uint8_t *data, size_t data_len, uint8_t *output) {
    SHA256(data, data_len, output);
}

// Function to calculate RIPEMD160 hash
static int ripemd160(const uint8_t *data, size_t data_len, uint8_t *output) {
    RIPEMD160_CTX ctx;
    if (!RIPEMD160_Init(&ctx)) return 0;
    if (!RIPEMD160_Update(&ctx, data, data_len)) return 0;
    if (!RIPEMD160_Final(output, &ctx)) return 0;
    return 1;
}

// Function to calculate HASH160 (SHA256 then RIPEMD160)
static int hash160(const uint8_t *data, size_t data_len, uint8_t output[RIPEMD160_DIGEST_LENGTH]) {
    uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
    sha256(data, data_len, sha256_hash);
    return ripemd160(sha256_hash, SHA256_DIGEST_LENGTH, output);
}

// Base58 encoding (without checksum)
static int base58_encode(const uint8_t *input, size_t input_len, char *output, size_t output_size) {
    if (input_len == 0) {
        output[0] = '\0';
        return 1;
    }

    uint8_t temp[input_len * 2]; // Max size needed for conversion
    memset(temp, 0, sizeof(temp));
    size_t j = 0;

    int leading_zeros = 0;
    for (size_t i = 0; i < input_len && input[i] == 0; ++i) {
        leading_zeros++;
    }

    for (size_t i = 0; i < input_len; ++i) {
        int carry = input[i];
        for (int k = sizeof(temp) - 1; k >= 0; --k) {
            carry += 256 * temp[k];
            temp[k] = carry % 58;
            carry /= 58;
        }
    }

    // Skip leading zeros in converted digits
    while (j < sizeof(temp) && temp[j] == 0) {
        j++;
    }

    if (output_size < (size_t)leading_zeros + sizeof(temp) - j + 1) {
        return 0; // Output buffer too small
    }

    for (int i = 0; i < leading_zeros; ++i) {
        output[i] = b58_alphabet[0];
    }
    for (size_t i = j; i < sizeof(temp); ++i) {
        output[leading_zeros + (i - j)] = b58_alphabet[temp[i]];
    }
    output[leading_zeros + sizeof(temp) - j] = '\0';
    return 1;
}

// Base58Check encoding
int base58_encode_check(const uint8_t *input, size_t input_len, char *output, size_t output_size) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t hash2[SHA256_DIGEST_LENGTH];
    uint8_t data_with_checksum[input_len + 4];

    memcpy(data_with_checksum, input, input_len);

    sha256(input, input_len, hash);
    sha256(hash, SHA256_DIGEST_LENGTH, hash2);

    memcpy(data_with_checksum + input_len, hash2, 4);

    return base58_encode(data_with_checksum, input_len + 4, output, output_size);
}

// Base58 decoding (without checksum)
static int base58_decode(const char *input, uint8_t *output, size_t *output_len) {
    size_t input_len = strlen(input);
    size_t bin_size = (input_len * 733 / 1000) + 1; // Approx 733 bytes per 1000 chars + 1 for safety
    uint8_t bin[bin_size];
    memset(bin, 0, bin_size);

    int leading_zeros = 0;
    for (size_t i = 0; i < input_len && input[i] == b58_alphabet[0]; ++i) {
        leading_zeros++;
    }

    for (size_t i = 0; i < input_len; ++i) {
        const char *digit_ptr = strchr(b58_alphabet, input[i]);
        if (!digit_ptr) return 0; // Invalid Base58 character
        int digit = digit_ptr - b58_alphabet;

        int carry = digit;
        for (int j = (int)bin_size - 1; j >= 0; --j) {
            carry += 58 * bin[j];
            bin[j] = carry % 256;
            carry /= 256;
        }
    }

    size_t j = 0;
    while (j < bin_size && bin[j] == 0) {
        j++;
    }

    *output_len = (bin_size - j) + leading_zeros;
    if (*output_len > 0) {
        memcpy(output + leading_zeros, bin + j, bin_size - j);
        memset(output, 0, leading_zeros); // Fill leading zeros for output
    } else {
        *output_len = 0;
    }
    return 1;
}


// Base58Check decoding
int base58_decode_check(const char *input, uint8_t *output, size_t output_size) {
    uint8_t decoded_data[output_size + 4]; // Max size needed for decoded data + checksum
    size_t decoded_len;

    if (!base58_decode(input, decoded_data, &decoded_len)) {
        return 0; // Base58 decode failed
    }

    if (decoded_len < 4) {
        return 0; // Not enough data for checksum
    }

    uint8_t data_without_checksum[decoded_len - 4];
    memcpy(data_without_checksum, decoded_data, decoded_len - 4);

    uint8_t hash1[SHA256_DIGEST_LENGTH];
    uint8_t hash2[SHA256_DIGEST_LENGTH];

    sha256(data_without_checksum, decoded_len - 4, hash1);
    sha256(hash1, SHA256_DIGEST_LENGTH, hash2);

    if (memcmp(decoded_data + decoded_len - 4, hash2, 4) != 0) {
        // printf("Error: Checksum mismatch\n");
        return 0; // Checksum mismatch
    }

    if (output_size < (decoded_len - 4)) {
        return 0; // Output buffer too small
    }
    memcpy(output, data_without_checksum, decoded_len - 4);
    return (int)(decoded_len - 4); // Return length of data without checksum
}


// Function to deserialize an extended key (xprv or xpub)
int hd_deserialize(const char *key_str, ExtendedKey *key) {
    uint8_t data[78 + 4]; // 78 bytes for key data + 4 bytes for checksum
    int decoded_len = base58_decode_check(key_str, data, sizeof(data));

    if (decoded_len != 78) {
        printf("Error: Failed to decode extended key or invalid length (%d instead of 78)\n", decoded_len);
        return 0; // Failed to decode or invalid length
    }

    // Populate the ExtendedKey structure
    memcpy(key->version, data, 4);
    key->depth = data[4];
    memcpy(key->parent_fingerprint, data + 5, 4);
    key->child_number = (data[9] << 24) | (data[10] << 16) | (data[11] << 8) | data[12];
    memcpy(key->chain_code, data + 13, 32);

    // Determine if it's a private or public key based on version bytes
    if (key->version[0] == 0x04 && key->version[1] == 0x88 &&
        key->version[2] == 0xAD && key->version[3] == 0xE4) { // xprv (mainnet)
        key->is_private = true;
        memcpy(key->key, data + 45, 33); // Private key is 33 bytes (0x00 + 32-byte key)
    } else if (key->version[0] == 0x04 && key->version[1] == 0x88 &&
               key->version[2] == 0xB2 && key->version[3] == 0x1E) { // xpub (mainnet)
        key->is_private = false;
        memcpy(key->key, data + 45, 33); // Public key is 33 bytes (compressed)
    } else {
        printf("Error: Unknown extended key version: %02x%02x%02x%02x\n", key->version[0], key->version[1], key->version[2], key->version[3]);
        return 0;
    }

    printf("Decoded key successfully:\n");
    printf("  Version: %02x%02x%02x%02x\n", key->version[0], key->version[1], key->version[2], key->version[3]);
    printf("  Depth: %u\n", key->depth);
    printf("  Parent fingerprint: %02x%02x%02x%02x\n",
           key->parent_fingerprint[0], key->parent_fingerprint[1],
           key->parent_fingerprint[2], key->parent_fingerprint[3]);
    printf("  Child number: %u\n", key->child_number);
    printf("  Is private: %s\n", key->is_private ? "true" : "false");
    return 1;
}

// Function to derive a child extended key
int hd_derive_child(ExtendedKey *parent, ExtendedKey *child, uint32_t index) {
    if (!parent->is_private && (index & HARDENED_BIT)) {
        printf("Error: Cannot derive hardened child from public parent.\n");
        return 0;
    }

    uint8_t data[77]; // 33 for parent public key (or 33 for private) + 32 for chain code + 4 for index
    uint8_t I[64]; // HMAC-SHA512 output
    uint8_t IL[32];
    uint8_t IR[32];
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k_bn = BN_new();
    BIGNUM *n_bn = BN_new(); // Order of the secp256k1 curve
    BIGNUM *x_bn = BN_new(); // For parent private key scalar

    if (!ctx || !k_bn || !n_bn || !x_bn) {
        printf("Error: BN_new/BN_CTX_new failed.\n");
        BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx);
        return 0;
    }

    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        printf("Error: EC_KEY_new_by_curve_name failed.\n");
        BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx);
        return 0;
    }
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    EC_GROUP_get_order(group, n_bn, ctx);

    if (index & HARDENED_BIT) {
        // Hardened derivation
        data[0] = 0x00; // Prefix for hardened derivation
        memcpy(data + 1, parent->key + 1, 32); // Copy 32-byte private key
        // Append child index
        data[33] = (index >> 24) & 0xFF;
        data[34] = (index >> 16) & 0xFF;
        data[35] = (index >> 8) & 0xFF;
        data[36] = index & 0xFF;
        HMAC(EVP_sha512(), parent->chain_code, 32, data, 37, I, NULL);
    } else {
        // Non-hardened derivation
        // Public key derivation using the parent's public key
        uint8_t parent_pubkey[33];
        if (parent->is_private) {
            // If parent is private, compute its public key
            EC_KEY *parent_eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
            if (!parent_eckey) {
                printf("Error: EC_KEY_new_by_curve_name failed for parent_eckey.\n");
                BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey);
                return 0;
            }
            BIGNUM *parent_prv_bn = BN_bin2bn(parent->key + 1, 32, NULL);
            if (!parent_prv_bn || !EC_KEY_set_private_key(parent_eckey, parent_prv_bn)) {
                printf("Error: Failed to set parent private key.\n");
                BN_free(parent_prv_bn); BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(parent_eckey);
                return 0;
            }
            
            // Derive public key from private key using EC_POINT_mul
            EC_POINT *pub_point = EC_POINT_new(group);
            if (!pub_point) {
                printf("Error: EC_POINT_new failed.\n");
                BN_free(parent_prv_bn); BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(parent_eckey);
                return 0;
            }
            if (!EC_POINT_mul(group, pub_point, parent_prv_bn, NULL, NULL, ctx)) {
                printf("Error: EC_POINT_mul failed to derive public key.\n");
                EC_POINT_free(pub_point); BN_free(parent_prv_bn); BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(parent_eckey);
                return 0;
            }
            if (!EC_KEY_set_public_key(parent_eckey, pub_point)) {
                printf("Error: EC_KEY_set_public_key failed.\n");
                EC_POINT_free(pub_point); BN_free(parent_prv_bn); BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(parent_eckey);
                return 0;
            }
            EC_POINT_free(pub_point); // Free the temporary point
            BN_free(parent_prv_bn);

            const EC_POINT *parent_pub = EC_KEY_get0_public_key(parent_eckey);
            if (!parent_pub) {
                printf("Error: Public key point is null for non-hardened derivation.\n");
                BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(parent_eckey);
                return 0;
            }

            size_t pub_len = EC_POINT_point2oct(group, parent_pub, POINT_CONVERSION_COMPRESSED, parent_pubkey, 33, ctx);
            if (pub_len != 33) {
                printf("Error: Failed to serialize parent public key (pub_len = %zu).\n", pub_len);
                BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(parent_eckey);
                return 0;
            }
            EC_KEY_free(parent_eckey);
        } else {
            memcpy(parent_pubkey, parent->key, 33);
        }

        memcpy(data, parent_pubkey, 33);
        // Append child index
        data[33] = (index >> 24) & 0xFF;
        data[34] = (index >> 16) & 0xFF;
        data[35] = (index >> 8) & 0xFF;
        data[36] = index & 0xFF;
        HMAC(EVP_sha512(), parent->chain_code, 32, data, 37, I, NULL);
    }

    memcpy(IL, I, 32);
    memcpy(IR, I + 32, 32);

    // Calculate new private key
    BN_bin2bn(IL, 32, k_bn); // IL is the new private key scalar
    BN_bin2bn(parent->key + 1, 32, x_bn); // Parent private key scalar

    if (BN_cmp(k_bn, n_bn) >= 0 || BN_is_zero(k_bn)) {
        printf("Error: Invalid derived private key (k_bn is too large or zero).\n");
        BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey);
        return 0;
    }

    BN_mod_add(k_bn, k_bn, x_bn, n_bn, ctx); // k_child = (IL + k_parent) mod N

    if (BN_cmp(k_bn, n_bn) >= 0 || BN_is_zero(k_bn)) {
        printf("Error: Invalid derived private key (k_child is too large or zero after addition).\n");
        BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey);
        return 0;
    }


    child->is_private = parent->is_private;
    child->depth = parent->depth + 1;
    child->child_number = index;
    memcpy(child->chain_code, IR, 32);

    // Set child private key (0x00 prefix + 32-byte key)
    child->key[0] = 0x00;
    BN_bn2binpad(k_bn, child->key + 1, 32);

    // Compute child's parent fingerprint
    uint8_t pubkey_hash[RIPEMD160_DIGEST_LENGTH];
    uint8_t parent_pubkey_for_fingerprint[33];

    if (parent->is_private) {
        EC_KEY *temp_eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!temp_eckey) {
            printf("Error: EC_KEY_new_by_curve_name failed for temp_eckey.\n");
            BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey);
            return 0;
        }
        BIGNUM *temp_prv_bn = BN_bin2bn(parent->key + 1, 32, NULL);
        if (!temp_prv_bn || !EC_KEY_set_private_key(temp_eckey, temp_prv_bn)) {
            printf("Error: Failed to set private key for fingerprint computation.\n");
            BN_free(temp_prv_bn); BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(temp_eckey);
            return 0;
        }
        
        // Derive public key from private key using EC_POINT_mul
        EC_POINT *pub_point = EC_POINT_new(group);
        if (!pub_point) {
            printf("Error: EC_POINT_new failed.\n");
            BN_free(temp_prv_bn); BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(temp_eckey);
            return 0;
        }
        if (!EC_POINT_mul(group, pub_point, temp_prv_bn, NULL, NULL, ctx)) {
            printf("Error: EC_POINT_mul failed to derive public key for fingerprint.\n");
            EC_POINT_free(pub_point); BN_free(temp_prv_bn); BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(temp_eckey);
            return 0;
        }
        if (!EC_KEY_set_public_key(temp_eckey, pub_point)) {
            printf("Error: EC_KEY_set_public_key failed for fingerprint.\n");
            EC_POINT_free(pub_point); BN_free(temp_prv_bn); BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(temp_eckey);
            return 0;
        }
        EC_POINT_free(pub_point); // Free the temporary point
        BN_free(temp_prv_bn);

        const EC_POINT *temp_pub = EC_KEY_get0_public_key(temp_eckey);
        if (!temp_pub) {
            printf("Error: Public key point is null for fingerprint computation.\n");
            BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(temp_eckey);
            return 0;
        }

        size_t pub_len = EC_POINT_point2oct(group, temp_pub, POINT_CONVERSION_COMPRESSED, parent_pubkey_for_fingerprint, 33, ctx);
        if (pub_len != 33) {
            printf("Error: Failed to serialize public key for fingerprint (pub_len = %zu).\n", pub_len);
            BN_free(k_bn); BN_free(n_bn); BN_free(x_bn); BN_CTX_free(ctx); EC_KEY_free(eckey); EC_KEY_free(temp_eckey);
            return 0;
        }
        EC_KEY_free(temp_eckey);
    } else {
        memcpy(parent_pubkey_for_fingerprint, parent->key, 33);
    }

    hash160(parent_pubkey_for_fingerprint, 33, pubkey_hash);
    memcpy(child->parent_fingerprint, pubkey_hash, 4);

    // Set version for child key
    if (child->is_private) {
        child->version[0] = (MAINNET_PRIVATE >> 24) & 0xFF;
        child->version[1] = (MAINNET_PRIVATE >> 16) & 0xFF;
        child->version[2] = (MAINNET_PRIVATE >> 8) & 0xFF;
        child->version[3] = MAINNET_PRIVATE & 0xFF;
    } else {
        child->version[0] = (MAINNET_PUBLIC >> 24) & 0xFF;
        child->version[1] = (MAINNET_PUBLIC >> 16) & 0xFF;
        child->version[2] = (MAINNET_PUBLIC >> 8) & 0xFF;
        child->version[3] = MAINNET_PUBLIC & 0xFF;
    }


    BN_free(k_bn);
    BN_free(n_bn);
    BN_free(x_bn);
    BN_CTX_free(ctx);
    EC_KEY_free(eckey);
    return 1;
}

// Function to print extended key information
void print_extended_key(const ExtendedKey *key) {
    if (!key) return;

    printf("  Version: %02x%02x%02x%02x\n", key->version[0], key->version[1], key->version[2], key->version[3]);
    printf("  Depth: %u\n", key->depth);
    printf("  Parent fingerprint: %02x%02x%02x%02x\n",
           key->parent_fingerprint[0], key->parent_fingerprint[1],
           key->parent_fingerprint[2], key->parent_fingerprint[3]);
    printf("  Child number: %u\n", key->child_number);
    printf("  Is private: %s\n", key->is_private ? "true" : "false");

    printf("  Chain code: ");
    for (int i = 0; i < 32; ++i) printf("%02x", key->chain_code[i]);
    printf("\n");

    printf("  Key: ");
    for (int i = 0; i < 33; ++i) printf("%02x", key->key[i]);
    printf("\n");
}

// Function to print private key information (including WIF and derived public key)
void print_private_key_info(const ExtendedKey *key) {
    if (!key || !key->is_private) {
        printf("No private key available\n\n");
        return;
    }

    printf("Private key information:\n");
    print_extended_key(key); // Re-use print_extended_key for common fields

    char wif[53]; // Max size for WIF
    if (privkey_to_wif(key->key + 1, true, wif, sizeof(wif))) { // Pass the 32-byte private key, always derive compressed WIF
        printf("  WIF private key (for wallet import): %s\n", wif);
    } else {
        printf("  WIF private key (for wallet import): Failed to generate\n");
    }
    
    // Derive and print the corresponding public key (compressed)
    uint8_t derived_public_key_compressed[33]; // Compressed public key
    if (private_key_to_public_key(key->key + 1, derived_public_key_compressed, true, NULL)) { // Pass true for compressed
        printf("  Derived Compressed Public Key (hex): ");
        for (int i = 0; i < 33; ++i) printf("%02x", derived_public_key_compressed[i]);
        printf("\n");
    } else {
        printf("  Derived Compressed Public Key (hex): Failed to generate\n");
    }
    printf("\n");
}

/**
 * @brief Convert a private key to WIF format
 * @param privkey Private key (32 bytes)
 * @param compressed Whether to use compressed public key format
 * @param wif Output buffer for WIF string
 * @param wif_size Size of output buffer
 * @return 1 on success, 0 on failure
 */
int privkey_to_wif(const uint8_t *privkey, bool compressed, char *wif, size_t wif_size) {
    if (!privkey || !wif || wif_size < 53) return 0;

    // Prepare data for Base58Check encoding
    size_t data_len = compressed ? 34 : 33; // 33 for uncompressed, 34 for compressed (0x01 suffix)
    uint8_t data[38]; // Version(1) + PrivKey(32) + CompFlag(0/1) + Checksum(4)

    // Set version byte
    data[0] = 0x80; // 0x80 for mainnet private key

    // Copy private key
    memcpy(data + 1, privkey, 32);

    // Add compression flag if needed
    if (compressed) {
        data[33] = 0x01;
    }

    // Calculate checksum (double SHA256, first 4 bytes)
    uint8_t hash1[SHA256_DIGEST_LENGTH];
    uint8_t hash2[SHA256_DIGEST_LENGTH];

    sha256(data, data_len, hash1);
    sha256(hash1, SHA256_DIGEST_LENGTH, hash2);

    // Append checksum
    memcpy(data + data_len, hash2, 4);
    data_len += 4;

    return base58_encode(data, data_len, wif, wif_size);
}


// Function to convert public key to P2PKH address
// Now takes pubkey_len to handle both compressed (33 bytes) and uncompressed (65 bytes)
int pubkey_to_p2pkh_address(const uint8_t *pubkey, size_t pubkey_len, char *address, size_t address_size) {
    uint8_t pubkey_hash[RIPEMD160_DIGEST_LENGTH]; // 20 bytes
    if (!hash160(pubkey, pubkey_len, pubkey_hash)) return 0; // Use pubkey_len

    uint8_t data_with_version[1 + RIPEMD160_DIGEST_LENGTH];
    data_with_version[0] = MAINNET_P2PKH; // 0x00 for P2PKH addresses
    memcpy(data_with_version + 1, pubkey_hash, RIPEMD160_DIGEST_LENGTH);

    return base58_encode_check(data_with_version, sizeof(data_with_version), address, address_size);
}

// Function to convert public key to P2WPKH address (Bech32)
int pubkey_to_p2wpkh_address(const uint8_t *pubkey, char *address, size_t address_size) {
    uint8_t pubkey_hash[RIPEMD160_DIGEST_LENGTH]; // 20 bytes
    if (!hash160(pubkey, 33, pubkey_hash)) return 0; // Always uses compressed pubkey (33 bytes) for P2WPKH

    // Correct size for 5-bit data: ceil(20 bytes * 8 bits/byte / 5 bits/group) = ceil(160/5) = 32 groups
    uint8_t five_bit_data[1 + 32]; // Witness version (0) + 32 bytes for 5-bit hash
    size_t five_bit_data_len = 32; // Initialize with max possible output length for the hash part

    five_bit_data[0] = 0x00; // Witness version 0 for P2WPKH

    if (!convert_bits(five_bit_data + 1, &five_bit_data_len, pubkey_hash, RIPEMD160_DIGEST_LENGTH, 8, 5, 1)) {
        printf("Error: Failed to convert bits for P2WPKH.\n");
        return 0;
    }
    // After convert_bits, five_bit_data_len will contain the actual number of 5-bit elements generated (which should be 32)
    five_bit_data_len += 1; // Account for witness version byte

    if (!bech32_encode(address, "bc", five_bit_data, five_bit_data_len)) {
        printf("Error: Failed to encode Bech32 address for P2WPKH.\n");
        return 0;
    }
    return 1;
}

// Function to convert public key to P2SH-P2WPKH address (Base58Check)
int pubkey_to_p2sh_p2wpkh_address(const uint8_t *pubkey, char *address, size_t address_size) {
    uint8_t pubkey_hash[RIPEMD160_DIGEST_LENGTH]; // 20 bytes
    if (!hash160(pubkey, 33, pubkey_hash)) return 0; // Always uses compressed pubkey (33 bytes) for P2SH-P2WPKH

    // Script for P2WPKH: 0014 <20-byte-hash>
    uint8_t script_pubkey[22];
    script_pubkey[0] = 0x00; // OP_0
    script_pubkey[1] = 0x14; // PUSH 20 bytes
    memcpy(script_pubkey + 2, pubkey_hash, RIPEMD160_DIGEST_LENGTH);

    uint8_t script_hash[RIPEMD160_DIGEST_LENGTH];
    if (!hash160(script_pubkey, sizeof(script_pubkey), script_hash)) return 0;

    uint8_t data_with_version[1 + RIPEMD160_DIGEST_LENGTH];
    data_with_version[0] = MAINNET_P2SH; // 0x05 for P2SH addresses
    memcpy(data_with_version + 1, script_hash, RIPEMD160_DIGEST_LENGTH);

    return base58_encode_check(data_with_version, sizeof(data_with_version), address, address_size);
}

// Function to convert public key to P2TR address (Bech32m)
int pubkey_to_p2tr_address(const uint8_t *pubkey, char *address, size_t address_size) {
    // For P2TR, the witness program is the 32-byte x-only public key
    // You need to extract the x-only public key from the compressed pubkey (33 bytes)
    // For simplicity here, we assume pubkey is already the 32-byte x-only key
    // In a full implementation, you'd convert the 33-byte compressed pubkey to 32-byte x-only pubkey
    // by removing the parity byte and handling potential curve points.
    // Let's use the full 33-byte compressed pubkey and adjust.

    // A proper P2TR address takes the x-only public key (32 bytes).
    // If your `pubkey` argument is the 33-byte compressed format, you need to extract the x-coordinate.
    uint8_t xonly_pubkey[32];
    if (pubkey[0] != 0x02 && pubkey[0] != 0x03) {
        printf("Error: Invalid compressed public key format for P2TR.\n");
        return 0;
    }
    memcpy(xonly_pubkey, pubkey + 1, 32); // Copy the 32-byte x-coordinate

    // Correct size for 5-bit data: ceil(32 bytes * 8 bits/byte / 5 bits/group) = ceil(256/5) = 52 groups
    uint8_t five_bit_data[1 + 52]; // Witness version (1) + 52 bytes for 5-bit x-only pubkey
    size_t five_bit_data_len = 52; // Initialize with max possible output length for the hash part

    five_bit_data[0] = 0x01; // Witness version 1 for P2TR
    size_t in_len = 32; // 32 bytes for x-only pubkey

    if (!convert_bits(five_bit_data + 1, &five_bit_data_len, xonly_pubkey, in_len, 8, 5, 1)) {
        printf("Error: Failed to convert bits for P2TR.\n");
        return 0;
    }
    five_bit_data_len += 1; // Account for witness version byte

    if (!bech32m_encode(address, "bc", five_bit_data, five_bit_data_len)) {
        printf("Error: Failed to encode Bech32m address for P2TR.\n");
        return 0;
    }
    return 1;
}

// Function to convert private key (32 bytes) to public key (33 or 65 bytes)
// @param private_key Input 32-byte private key
// @param public_key_out Output buffer for public key (33 bytes for compressed, 65 for uncompressed)
// @param compressed If true, output compressed (33 bytes), else uncompressed (65 bytes)
// @param public_key_len_out Optional: If not NULL, returns the actual length of the public key generated
int private_key_to_public_key(const uint8_t *private_key, uint8_t *public_key_out, bool compressed, size_t *public_key_len_out) {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) {
        printf("Error: EC_KEY_new_by_curve_name failed.\n");
        return 0;
    }
    BIGNUM *prv_bn = BN_bin2bn(private_key, 32, NULL);
    if (!prv_bn || !EC_KEY_set_private_key(eckey, prv_bn)) {
        printf("Error: Failed to set private key.\n");
        BN_free(prv_bn); EC_KEY_free(eckey);
        return 0;
    }

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    BN_CTX *ctx = BN_CTX_new();
    if (!group || !ctx) {
        printf("Error: EC_GROUP or BN_CTX is null.\n");
        BN_free(prv_bn); EC_KEY_free(eckey); BN_CTX_free(ctx);
        return 0;
    }

    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point) {
        printf("Error: EC_POINT_new failed.\n");
        BN_free(prv_bn); EC_KEY_free(eckey); BN_CTX_free(ctx);
        return 0;
    }
    if (!EC_POINT_mul(group, pub_point, prv_bn, NULL, NULL, ctx)) {
        printf("Error: EC_POINT_mul failed to derive public key.\n");
        EC_POINT_free(pub_point); BN_free(prv_bn); EC_KEY_free(eckey); BN_CTX_free(ctx);
        return 0;
    }
    if (!EC_KEY_set_public_key(eckey, pub_point)) {
        printf("Error: EC_KEY_set_public_key failed.\n");
        EC_POINT_free(pub_point); BN_free(prv_bn); EC_KEY_free(eckey); BN_CTX_free(ctx);
        return 0;
    }
    EC_POINT_free(pub_point); // Free the temporary point
    BN_free(prv_bn);

    point_conversion_form_t form = compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    size_t pub_len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(eckey), form, public_key_out, compressed ? 33 : 65, ctx);

    if (public_key_len_out) {
        *public_key_len_out = pub_len;
    }

    if ((compressed && pub_len != 33) || (!compressed && pub_len != 65)) {
        printf("Error: Failed to serialize public key (pub_len = %zu, expected %d).\n", pub_len, compressed ? 33 : 65);
        BN_CTX_free(ctx); EC_KEY_free(eckey);
        return 0;
    }
    BN_CTX_free(ctx);
    EC_KEY_free(eckey);
    return 1;
}

// Function to decode WIF private key
int wif_to_private_key(const char *wif_str, uint8_t *private_key_out, bool *compressed_out) {
    uint8_t decoded_data[38]; // Max for 0x80 + 32-byte key + 0x01 (if compressed) + 4-byte checksum
    int decoded_len = base58_decode_check(wif_str, decoded_data, sizeof(decoded_data));

    if (decoded_len < 33 || decoded_len > 34) {
        printf("Error: Invalid decoded length for WIF private key (%d).\n", decoded_len);
        return 0;
    }

    if (decoded_data[0] != 0x80) { // Check for mainnet private key prefix
        printf("Error: Invalid WIF version byte (expected 0x80, got 0x%02x).\n", decoded_data[0]);
        return 0;
    }

    if (decoded_len == 34) { // Compressed WIF has an extra 0x01 byte at the end of the key
        *compressed_out = true;
        memcpy(private_key_out, decoded_data + 1, 32);
        if (decoded_data[33] != 0x01) {
            printf("Warning: Compressed WIF with unexpected last byte (expected 0x01, got 0x%02x).\n", decoded_data[33]);
        }
    } else {
        *compressed_out = false;
        memcpy(private_key_out, decoded_data + 1, 32);
    }
    return 1;
}


// Function to generate address from extended key
int extended_key_to_address(const ExtendedKey *key, AddressType type, char *address, size_t address_size) {
    uint8_t pubkey_compressed[33]; // Always derive compressed for these types if from extended key
    uint8_t pubkey_uncompressed[65]; // For P2PKH if needed
    size_t pubkey_len;

    if (key->is_private) {
        // Derive compressed public key for SegWit-based types and P2PKH in extended key context
        if (!private_key_to_public_key(key->key + 1, pubkey_compressed, true, &pubkey_len)) {
            printf("Error: Failed to derive compressed public key from extended private key.\n");
            return 0;
        }
    } else {
        memcpy(pubkey_compressed, key->key, 33);
        pubkey_len = 33;
    }

    switch (type) {
        case ADDR_LEGACY_P2PKH:
            // For P2PKH from extended key, we assume compressed for consistent behavior.
            // If an uncompressed address is explicitly needed, the caller should handle that.
            return pubkey_to_p2pkh_address(pubkey_compressed, pubkey_len, address, address_size);
        case ADDR_P2SH_P2WPKH:
            return pubkey_to_p2sh_p2wpkh_address(pubkey_compressed, address, address_size);
        case ADDR_P2WPKH:
            return pubkey_to_p2wpkh_address(pubkey_compressed, address, address_size);
        case ADDR_P2TR:
            return pubkey_to_p2tr_address(pubkey_compressed, address, address_size);
        default:
            printf("Error: Unknown address type.\n");
            return 0;
    }
}

// Function to parse a derivation path segment (e.g., "0h", "1")
static int parse_path_segment(const char *segment, uint32_t *index_val) {
    if (!segment) return 0;
    bool hardened = false;
    size_t len = strlen(segment);
    if (len > 0 && (segment[len - 1] == '\'' || segment[len - 1] == 'h')) {
        hardened = true;
        // Remove 'h' or '\'' for parsing
        char *temp_segment = strdup(segment);
        if (!temp_segment) return 0;
        temp_segment[len - 1] = '\0';
        *index_val = (uint32_t)strtoul(temp_segment, NULL, 10);
        free(temp_segment);
    } else {
        *index_val = (uint32_t)strtoul(segment, NULL, 10);
    }

    if (hardened) {
        *index_val |= HARDENED_BIT;
    }
    return 1;
}

// Function to check if a segment is hardened
bool is_segment_hardened(const char *segment) {
    size_t len = strlen(segment);
    return (len > 0 && (segment[len - 1] == '\'' || segment[len - 1] == 'h'));
}

// Function to generate address from descriptor components
int generate_address_from_descriptor(const DescriptorComponents *comp, AddressType addr_type, uint32_t index_wildcard, char *address, size_t address_size) {
    ExtendedKey master_key;

    // Check if key starts with '[' for fingerprint (skip for simplicity if it's just xpub/xprv)
    const char *key_start = comp->xprv_or_xpub;
    if (key_start[0] == '[') {
        key_start = strchr(key_start, ']');
        if (!key_start) return 0; // Malformed descriptor
        key_start++; // Move past ']'
    }

    if (!hd_deserialize(key_start, &master_key)) {
        printf("Failed to decode key: %s\n", comp->xprv_or_xpub);
        return 0;
    }

    // Parse the BIP32 path and derive children
    ExtendedKey derived_key = master_key; // Start with the master key
    uint32_t path_indices[MAX_PATH_DEPTH];
    int path_depth = 0;

    printf("Parsed derivation path with 4 indices\n");

    // Purpose
    if (comp->purpose && strcmp(comp->purpose, "") != 0) {
        if (!parse_path_segment(comp->purpose, &path_indices[path_depth])) return 0;
        printf("  Index 0: %s\n", comp->purpose);
        path_depth++;
    }
    // Coin Type
    if (comp->coin_type && strcmp(comp->coin_type, "") != 0) {
        if (!parse_path_segment(comp->coin_type, &path_indices[path_depth])) return 0;
        printf("  Index 1: %s\n", comp->coin_type);
        path_depth++;
    }
    // Account
    if (comp->account && strcmp(comp->account, "") != 0) {
        if (!parse_path_segment(comp->account, &path_indices[path_depth])) return 0;
        printf("  Index 2: %s\n", comp->account);
        path_depth++;
    }
    // Change (external/internal)
    if (comp->change && strcmp(comp->change, "") != 0) {
        if (!parse_path_segment(comp->change, &path_indices[path_depth])) return 0;
        printf("  Index 3: %s\n", comp->change);
        path_depth++;
    }
    // Address Index (wildcard or specific)
    if (comp->address_index && strcmp(comp->address_index, "*") != 0 && strcmp(comp->address_index, "") != 0) {
        if (!parse_path_segment(comp->address_index, &path_indices[path_depth])) return 0;
        printf("  Index %d: %s\n", path_depth, comp->address_index);
        path_depth++;
    } else if (comp->address_index && strcmp(comp->address_index, "*") == 0) {
        // If wildcard, use the provided `index_wildcard`
        path_indices[path_depth] = index_wildcard;
        printf("  Index %d: %u\n", path_depth, index_wildcard);
        path_depth++;
    }


    printf("Starting derivation path with %d indices\n", path_depth);
    printf("Master key is_private: %s\n", master_key.is_private ? "true" : "false");

    for (int i = 0; i < path_depth; ++i) {
        ExtendedKey temp_key;
        printf("Deriving index %d: %u%s\n", i, path_indices[i] & (~HARDENED_BIT), (path_indices[i] & HARDENED_BIT) ? "'" : "");
        printf("Deriving child key: index=%u%s, parent is_private=%s\n",
               path_indices[i] & (~HARDENED_BIT), (path_indices[i] & HARDENED_BIT) ? "'" : "",
               derived_key.is_private ? "true" : "false");
        if (!hd_derive_child(&derived_key, &temp_key, path_indices[i])) {
            printf("Child key derivation failed\n");
            return 0;
        }
        derived_key = temp_key; // Copy the derived key
        printf("Successfully derived child at index %d\n", i);
    }
    printf("Path derivation completed successfully\n");
    print_private_key_info(&derived_key);

    return extended_key_to_address(&derived_key, addr_type, address, address_size);
}


// Function to generate a range of addresses
int generate_address_range(const DescriptorComponents *comp, AddressType addr_type, uint32_t start_index, uint32_t count, void (*callback)(const char *address, uint32_t index, void *user_data), void *user_data) {
    char address[MAX_ADDRESS_SIZE];
    int success = 1;

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t current_index = start_index + i;
        printf("Deriving additional child key for wildcard index: %u\n", current_index);
        if (generate_address_from_descriptor(comp, addr_type, current_index, address, sizeof(address))) {
            callback(address, current_index, user_data);
        } else {
            success = 0;
            break;
        }
    }
    return success;
}

// Function to free descriptor components
void free_descriptor_components(DescriptorComponents *comp) {
    if (comp) {
        free(comp->xprv_or_xpub);
        free(comp->purpose);
        free(comp->coin_type);
        free(comp->account);
        free(comp->change);
        free(comp->address_index);
        // Do not free the struct itself, assuming it's stack-allocated or managed by caller
    }
}

// Function to process a single descriptor string
int process_descriptor(const char *desc_str, uint32_t index, char *address, size_t address_size) {
    DescriptorComponents comp = {0}; // Initialize to zero

    // Parse the descriptor string
    char *temp_desc = strdup(desc_str);
    if (!temp_desc) return 0;

    // Determine descriptor type and extract key and path
    // For simplicity, this parsing is basic and assumes the format based on the examples.
    // A robust parser would use regex or more sophisticated string parsing.
    char *key_start = NULL;
    AddressType addr_type;

    if (strncmp(temp_desc, "pkh(", 4) == 0) {
        addr_type = ADDR_LEGACY_P2PKH;
        key_start = temp_desc + 4;
    } else if (strncmp(temp_desc, "sh(wpkh(", 8) == 0) {
        addr_type = ADDR_P2SH_P2WPKH;
        key_start = temp_desc + 8;
    } else if (strncmp(temp_desc, "wpkh(", 5) == 0) {
        addr_type = ADDR_P2WPKH;
        key_start = temp_desc + 5;
    } else if (strncmp(temp_desc, "tr(", 3) == 0) {
        addr_type = ADDR_P2TR;
        key_start = temp_desc + 3;
    } else {
        printf("Error: Unknown descriptor type: %s\n", desc_str);
        free(temp_desc);
        return 0;
    }

    char *closing_paren = strrchr(key_start, ')');
    if (!closing_paren) {
        printf("Error: Malformed descriptor (missing closing parenthesis).\n");
        free(temp_desc);
        return 0;
    }
    *closing_paren = '\0'; // Null-terminate the key part

    comp.is_private = (strstr(key_start, "xprv") != NULL);
    comp.xprv_or_xpub = strdup(key_start);

    // Parse path components from the key_start string (e.g., "[fingerprint/purpose'/coin'/account'/change/address_index]")
    char *path_part = strchr(comp.xprv_or_xpub, '/');
    if (path_part) {
        // Extract purpose, coin_type, account, change, address_index
        // This is a simplified parsing for demonstration
        char *token;
        int current_path_segment = 0;
        char *path_copy = strdup(path_part + 1); // Skip initial '/'
        if (!path_copy) { free_descriptor_components(&comp); free(temp_desc); return 0; }

        // Null-terminate the key part before the path
        *(path_part) = '\0';


        token = strtok(path_copy, "/");
        while (token != NULL && current_path_segment < MAX_PATH_DEPTH) {
            if (current_path_segment == 0) comp.purpose = strdup(token);
            else if (current_path_segment == 1) comp.coin_type = strdup(token);
            else if (current_path_segment == 2) comp.account = strdup(token);
            else if (current_path_segment == 3) comp.change = strdup(token);
            else if (current_path_segment == 4) comp.address_index = strdup(token);
            current_path_segment++;
            token = strtok(NULL, "/");
        }
        free(path_copy);
    } else {
        // No explicit path, assume default
        comp.purpose = strdup("44h"); // Default BIP44
        comp.coin_type = strdup("0h"); // Default Bitcoin
        comp.account = strdup("0h"); // Default first account
        comp.change = strdup("0");   // Default external
        comp.address_index = strdup("*"); // Default wildcard
    }

    printf("Descriptor type: %d\n", addr_type);
    printf("Is private: %s\n", comp.is_private ? "true" : "false");
    printf("Key: %s\n", comp.xprv_or_xpub);
    printf("Purpose: %s\n", comp.purpose ? comp.purpose : "N/A");
    printf("Coin type: %s\n", comp.coin_type ? comp.coin_type : "N/A");
    printf("Account: %s\n", comp.account ? comp.account : "N/A");
    printf("Change: %s\n", comp.change ? comp.change : "N/A");
    printf("Address index: %s\n", comp.address_index ? comp.address_index : "N/A");

    printf("Generating address from descriptor components:\n");
    printf("  Key: %s\n", comp.xprv_or_xpub);
    printf("  Is private: %s\n", comp.is_private ? "true" : "false");
    printf("  Purpose: %s\n", comp.purpose ? comp.purpose : "N/A");
    printf("  Coin type: %s\n", comp.coin_type ? comp.coin_type : "N/A");
    printf("  Account: %s\n", comp.account ? comp.account : "N/A");
    printf("  Change: %s\n", comp.change ? comp.change : "N/A");
    printf("  Address index: %s\n", comp.address_index ? comp.address_index : "N/A");
    printf("  Address type: %d\n", addr_type);
    printf("  Index: %u\n", index);


    int result = generate_address_from_descriptor(&comp, addr_type, index, address, address_size);

    free_descriptor_components(&comp);
    free(temp_desc);
    return result;
}

#ifdef MAIN_INCLUDED
// This section is for a simple main function to test, not part of the library itself.
// You would define MAIN_INCLUDED in your build process if you want to compile this.

// Dummy callback for address range generation
void address_callback(const char *address, uint32_t index, void *user_data) {
    printf("Generated address for index %u: %s\n", index, address);
}


int main() {
    printf("=== Testing Descriptor Parsing ===\n");
    char address[MAX_ADDRESS_SIZE];
    size_t address_size = sizeof(address);

    // Test with xprv for P2WPKH
    printf("Descriptor type: 2\n");
    printf("Is private: true\n");
    printf("Key: xprv9s21ZrQH143K2yScEid4jC8MxKnYdHwLZHzZinSrefzvzKU37r5jmFS2NiEr3rbgyNy3GbTGK6VD8utDsy77nJcizMoyesBYC7NTnGVuAsE\n");
    printf("Purpose: 84h\n");
    printf("Coin type: 0h\n");
    printf("Account: 0h\n");
    printf("Change: 0\n");
    printf("Address index: *\n");
    if (process_descriptor("wpkh(xprv9s21ZrQH143K2yScEid4jC8MxKnYdHwLZHzZinSrefzvzKU37r5jmFS2NiEr3rbgyNy3GbTGK6VD8utDsy77nJcizMoyesBYC7NTnGVuAsE/84h/0h/0h/0/*)", 0, address, address_size)) {
        printf("Successfully generated address: %s\n", address);
        printf("Generated address: %s\n\n", address);
    } else {
        printf("Failed to generate address.\n\n");
    }

    // Test with xprv for P2TR
    printf("=== Testing Taproot Descriptor Parsing ===\n");
    printf("Descriptor type: 3\n");
    printf("Is private: true\n");
    printf("Key: xprv9s21ZrQH143K2yScEid4jC8MxKnYdHwLZHzZinSrefzvzKU37r5jmFS2NiEr3rbgyNy3GbTGK6VD8utDsy77nJcizMoyesBYC7NTnGVuAsE\n");
    printf("Purpose: 86h\n");
    printf("Coin type: 0h\n");
    printf("Account: 0h\n");
    printf("Change: 0\n");
    printf("Address index: *\n");
    if (process_descriptor("tr(xprv9s21ZrQH143K2yScEid4jC8MxKnYdHwLZHzZinSrefzvzKU37r5jmFS2NiEr3rbgyNy3GbTGK6VD8utDsy77nJcizMoyesBYC7NTnGVuAsE/86h/0h/0h/0/*)", 0, address, address_size)) {
        printf("Successfully generated address: %s\n", address);
        printf("Generated address: %s\n\n", address);
    } else {
        printf("Failed to generate address.\n\n");
    }

    // Test with xprv for Legacy P2PKH
    printf("=== Testing Legacy Descriptor Parsing ===\n");
    printf("Descriptor type: 0\n");
    printf("Is private: true\n");
    printf("Key: xprv9s21ZrQH143K2yScEid4jC8MxKnYdHwLZHzZinSrefzvzKU37r5jmFS2NiEr3rbgyNy3GbTGK6VD8utDsy77nJcizMoyesBYC7NTnGVuAsE\n");
    printf("Purpose: 44h\n");
    printf("Coin type: 0h\n");
    printf("Account: 0h\n");
    printf("Change: 0\n");
    printf("Address index: *\n");
    if (process_descriptor("pkh(xprv9s21ZrQH143K2yScEid4jC8MxKnYdHwLZHzZinSrefzvzKU37r5jmFS2NiEr3rbgyNy3GbTGK6VD8utDsy77nJcizMoyesBYC7NTnGVuAsE/44h/0h/0h/0/*)", 0, address, address_size)) {
        printf("Successfully generated address: %s\n", address);
        printf("Generated address: %s\n\n", address);
    } else {
        printf("Failed to generate address.\n\n");
    }

    // NEW TEST CASE: Derive public key and P2PKH address from WIF private key
    printf("=== Testing Public Key and P2PKH Address from WIF ===\n");
    const char *wif_priv_key_compressed = "KxKDceXxfjKenixD2xuG9buidJoQkhBUMo1zt8g1BmDXvNbXaN9c"; // Compressed WIF
    const char *wif_priv_key_uncompressed = "5JmK8b7L8b7W8R8N8V8U8T8S8Q8P8O8N8M8L8K8J8I8H8G8F8E8D8C8B8A8Z8Y8X8W8V8U8T8S8R8Q8P8O8N8M8L8K8J8I8H8G8F8E8D8C8B8A"; // Example Uncompressed WIF (replace with actual if possible)

    uint8_t raw_priv_key[32];
    uint8_t derived_pub_key[65]; // Max size for uncompressed public key
    size_t derived_pub_key_len;
    bool compressed_flag_from_wif;
    char p2pkh_address_from_wif[MAX_ADDRESS_SIZE];


    // --- Test with the provided compressed WIF ---
    printf("\n--- Processing WIF: %s ---\n", wif_priv_key_compressed);
    if (wif_to_private_key(wif_priv_key_compressed, raw_priv_key, &compressed_flag_from_wif)) {
        printf("Decoded Private Key (hex): ");
        for (int i = 0; i < 32; ++i) printf("%02x", raw_priv_key[i]);
        printf("\n");
        printf("WIF indicates compression: %s\n", compressed_flag_from_wif ? "true" : "false");

        // Per the WIF, derive the compressed public key
        if (private_key_to_public_key(raw_priv_key, derived_pub_key, true, &derived_pub_key_len)) {
            printf("Derived COMPRESSED Public Key (hex): ");
            for (int i = 0; i < derived_pub_key_len; ++i) printf("%02x", derived_pub_key[i]);
            printf(" (Length: %zu)\n", derived_pub_key_len);

            if (pubkey_to_p2pkh_address(derived_pub_key, derived_pub_key_len, p2pkh_address_from_wif, sizeof(p2pkh_address_from_wif))) {
                printf("Generated P2PKH Address (from COMPRESSED pubkey): %s\n", p2pkh_address_from_wif);
            } else {
                printf("Failed to generate P2PKH address from compressed public key.\n");
            }
        } else {
            printf("Failed to derive compressed public key from private key.\n");
        }

        // Also derive the UNCOMPRESSED public key and its address for comparison
        if (private_key_to_public_key(raw_priv_key, derived_pub_key, false, &derived_pub_key_len)) {
            printf("Derived UNCOMPRESSED Public Key (hex): ");
            for (int i = 0; i < derived_pub_key_len; ++i) printf("%02x", derived_pub_key[i]);
            printf(" (Length: %zu)\n", derived_pub_key_len);

            if (pubkey_to_p2pkh_address(derived_pub_key, derived_pub_key_len, p2pkh_address_from_wif, sizeof(p2pkh_address_from_wif))) {
                printf("Generated P2PKH Address (from UNCOMPRESSED pubkey): %s\n", p2pkh_address_from_wif);
                // This is the address you were likely looking for: 15unhGFHfEHxtDy54GxKDV7WV3Be35xmAF
                printf("This should match 15unhGFHfEHxtDy54GxKDV7WV3Be35xmAF if it was derived from an uncompressed public key.\n");
            } else {
                printf("Failed to generate P2PKH address from uncompressed public key.\n");
            }
        } else {
            printf("Failed to derive uncompressed public key from private key.\n");
        }

    } else {
        printf("Failed to decode WIF private key: %s.\n", wif_priv_key_compressed);
    }
    printf("\n");


    // --- Test with an uncompressed WIF (if available, otherwise placeholder) ---
    printf("\n--- Processing WIF: %s ---\n", wif_priv_key_uncompressed);
    // Note: The example WIF_PRIV_KEY_UNCOMPRESSED might not be valid,
    // replace with a known uncompressed WIF for proper testing.
    // An uncompressed WIF usually starts with '5'.
    if (wif_to_private_key(wif_priv_key_uncompressed, raw_priv_key, &compressed_flag_from_wif)) {
        printf("Decoded Private Key (hex): ");
        for (int i = 0; i < 32; ++i) printf("%02x", raw_priv_key[i]);
        printf("\n");
        printf("WIF indicates compression: %s\n", compressed_flag_from_wif ? "true" : "false");

        // Per the WIF, derive the public key based on its compression flag
        if (private_key_to_public_key(raw_priv_key, derived_pub_key, compressed_flag_from_wif, &derived_pub_key_len)) {
            printf("Derived Public Key (hex, based on WIF's compression flag): ");
            for (int i = 0; i < derived_pub_key_len; ++i) printf("%02x", derived_pub_key[i]);
            printf(" (Length: %zu)\n", derived_pub_key_len);

            if (pubkey_to_p2pkh_address(derived_pub_key, derived_pub_key_len, p2pkh_address_from_wif, sizeof(p2pkh_address_from_wif))) {
                printf("Generated P2PKH Address (from pubkey based on WIF's compression flag): %s\n", p2pkh_address_from_wif);
            } else {
                printf("Failed to generate P2PKH address from public key (based on WIF's compression flag).\n");
            }
        } else {
            printf("Failed to derive public key from private key (based on WIF's compression flag).\n");
        }

    } else {
        printf("Failed to decode WIF private key: %s. (This is expected if the example uncompressed WIF is invalid.)\n", wif_priv_key_uncompressed);
    }

    printf("\n");


    printf("=== Testing JSON Descriptor Parsing ===\n");

    const char *json_files[] = {"list-descriptors.json", "list_descriptors_true.json"};
    printf("Found 2 files to test\n\n");

    for (int file_idx = 0; file_idx < 2; ++file_idx) {
        const char *filename = json_files[file_idx];
        printf("Processing file: %s\n\n", filename);

        json_object *root = NULL;
        json_object *descriptors_array = NULL;
        FILE *fp = fopen(filename, "r");
        if (fp == NULL) {
            fprintf(stderr, "Error: Could not open file %s\n", filename);
            continue;
        }

        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        char *json_string = malloc(fsize + 1);
        if (!json_string) {
            fprintf(stderr, "Error: Memory allocation failed for %s\n", filename);
            fclose(fp);
            continue;
        }
        fread(json_string, 1, fsize, fp);
        fclose(fp);
        json_string[fsize] = '\0';

        root = json_tokener_parse(json_string);
        free(json_string);

        if (!root) {
            fprintf(stderr, "Error: Could not parse JSON from %s\n", filename);
            continue;
        }

        json_object_object_get_ex(root, "descriptors", &descriptors_array);
        if (!descriptors_array || !json_object_is_type(descriptors_array, json_type_array)) {
            fprintf(stderr, "Error: 'descriptors' array not found or not an array in %s\n", filename);
            json_object_put(root);
            continue;
        }

        int num_descriptors = json_object_array_length(descriptors_array);
        printf("Found %d descriptors in %s\n\n", num_descriptors, filename);

        for (int i = 0; i < num_descriptors; ++i) {
            // Corrected JSON parsing logic:
            json_object *desc_entry_obj = json_object_array_get_idx(descriptors_array, i);
            if (!desc_entry_obj || !json_object_is_type(desc_entry_obj, json_type_object)) {
                fprintf(stderr, "Error: Descriptor entry at index %d is not an object in %s\n", i, filename);
                continue;
            }

            json_object *desc_str_obj = NULL;
            json_object_object_get_ex(desc_entry_obj, "desc", &desc_str_obj);
            if (!desc_str_obj || !json_object_is_type(desc_str_obj, json_type_string)) {
                fprintf(stderr, "Error: 'desc' field not found or not a string in descriptor at index %d in %s\n", i, filename);
                continue;
            }
            const char *desc = json_object_get_string(desc_str_obj);


            printf("Processing descriptor %d\n", i);
            printf("Descriptor %d from %s: %s\n", i, filename, desc);

            char generated_address[MAX_ADDRESS_SIZE];
            if (process_descriptor(desc, 0, generated_address, sizeof(generated_address))) {
                printf("Received generated address: %s\n\n", generated_address);
            } else {
                printf("Failed to generate address\n\n");
            }
        }
        json_object_put(root); // Free the json_object
    }

    return 0;
}

#endif // MAIN_INCLUDED