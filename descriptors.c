#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/param_build.h>

// Bitcoin Base58 alphabet
static const char *b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Bitcoin network versions
static const uint8_t XPRV_VERSION[4] = {0x04, 0x88, 0xAD, 0xE4};
static const uint8_t XPUB_VERSION[4] = {0x04, 0x88, 0xB2, 0x1E};

// Address types
typedef enum {
    ADDR_LEGACY_P2PKH,
    ADDR_P2SH_P2WPKH,
    ADDR_P2WPKH,
    ADDR_P2TR
} AddressType;

// Struct to hold parsed descriptor components (with named BIP32 path segments)
typedef struct {
    bool is_private;           // true = xprv, false = xpub
    char *xprv_or_xpub;        // The actual key (without prefix)
    
    // BIP32 Path Components (Named for BIP44 Compatibility)
    char *purpose;        // "44h" (BIP44)
    char *coin_type;      // "0h" (Bitcoin)
    char *account;        // "0h" (First account)
    char *change;         // "0" (External) or "1" (Internal/Change)
    char *address_index;  // "*" (Wildcard) or specific index (e.g., "5")
} DescriptorComponents;

// Structure to hold an extended key (xpub or xprv)
typedef struct {
    uint8_t version[4];      // 4 bytes of version
    uint8_t depth;           // Depth: 0x00 for master nodes, 0x01 for level-1 derived keys, etc.
    uint8_t parent_fingerprint[4]; // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    uint32_t child_number;   // Child number
    uint8_t chain_code[32];  // 32 bytes
    uint8_t key[33];         // 33 bytes: 0x00 + private key for xprv, compressed public key for xpub
    bool is_private;         // true for xprv, false for xpub
} ExtendedKey;

// Structure for BIP32 derivation path
typedef struct {
    uint32_t indices[10];  // Support up to 10 levels
    size_t length;
} DerivationPath;

/**
 * @brief Frees memory used by DescriptorComponents struct
 * @param comp Pointer to the DescriptorComponents structure to free
 */
void free_descriptor_components(DescriptorComponents *comp) {
    if (!comp) return;
    
    if (comp->xprv_or_xpub) free(comp->xprv_or_xpub);
    if (comp->purpose) free(comp->purpose);
    if (comp->coin_type) free(comp->coin_type);
    if (comp->account) free(comp->account);
    if (comp->change) free(comp->change);
    if (comp->address_index) free(comp->address_index);
    
    // Reset pointers
    comp->xprv_or_xpub = NULL;
    comp->purpose = NULL;
    comp->coin_type = NULL;
    comp->account = NULL;
    comp->change = NULL;
    comp->address_index = NULL;
}

/**
 * @brief Parses a BIP32 path like "/44h/0h/0h/0/\*" into named segments
 * @param path String containing the BIP32 path to parse
 * @param comp Pointer to the DescriptorComponents structure to populate
 */
void parse_bip32_path(const char *path, DescriptorComponents *comp) {
    if (!path || !comp) return;

    // Make a copy to avoid modifying the original
    char *path_copy = strdup(path);
    if (!path_copy) return;

    // Split by '/'
    char *segment = strtok(path_copy, "/");
    int depth = 0;

    while (segment) {
        char *segment_copy = strdup(segment);
        if (!segment_copy) {
            free(path_copy);
            return;
        }
        
        switch (depth) {
            case 0: comp->purpose = segment_copy; break;
            case 1: comp->coin_type = segment_copy; break;
            case 2: comp->account = segment_copy; break;
            case 3: comp->change = segment_copy; break;
            case 4: comp->address_index = segment_copy; break;
            default: free(segment_copy); break; // Ignore extra segments (unlikely in BIP32)
        }
        segment = strtok(NULL, "/");
        depth++;
    }

    free(path_copy);
}

/**
 * @brief Parses a BIP32 path from a descriptor with fingerprint
 * @param desc The descriptor string to parse
 * @param comp Pointer to the DescriptorComponents structure to populate
 * @return true if successful, false otherwise
 */
bool parse_descriptor_path(const char *desc, DescriptorComponents *comp) {
    if (!desc || !comp) return false;

    // Look for the fingerprint pattern: [fingerprint/path]
    const char *fingerprint_start = strstr(desc, "[");
    if (!fingerprint_start) return false;

    // Find the first slash after the fingerprint
    const char *path_start = strchr(fingerprint_start, '/');
    if (!path_start) return false;

    // Find the closing bracket
    const char *path_end = strchr(fingerprint_start, ']');
    if (!path_end || path_end < path_start) return false;

    // Extract the path (without the fingerprint)
    size_t path_len = path_end - path_start;
    char *path_str = malloc(path_len + 1);
    if (!path_str) return false;

    strncpy(path_str, path_start + 1, path_len - 1); // Skip the leading '/'
    path_str[path_len - 1] = '\0';

    // Parse the path segments
    char *path_copy = strdup(path_str);
    if (!path_copy) {
        free(path_str);
        return false;
    }

    // Split by '/'
    char *segment = strtok(path_copy, "/");
    int depth = 0;

    while (segment) {
        char *segment_copy = strdup(segment);
        if (!segment_copy) {
            free(path_copy);
            free(path_str);
            return false;
        }
        
        switch (depth) {
            case 0: comp->purpose = segment_copy; break;
            case 1: comp->coin_type = segment_copy; break;
            case 2: comp->account = segment_copy; break;
            default: free(segment_copy); break; // Ignore extra segments in the fingerprint part
        }
        segment = strtok(NULL, "/");
        depth++;
    }

    free(path_copy);

    // Now look for the additional path after the xpub
    const char *xpub_end = strstr(path_end, "xpub");
    if (!xpub_end) {
        xpub_end = strstr(path_end, "xprv");
    }
    
    if (xpub_end) {
        // Skip to the end of the key
        xpub_end = strchr(xpub_end, '/');
        if (xpub_end) {
            // Find the end of this path (either ')' or '#')
            const char *extra_path_end = strstr(xpub_end, ")");
            if (!extra_path_end) {
                extra_path_end = strstr(xpub_end, "#");
            }
            
            if (extra_path_end) {
                // Extract the extra path
                size_t extra_path_len = extra_path_end - xpub_end;
                char *extra_path = malloc(extra_path_len + 1);
                if (extra_path) {
                    strncpy(extra_path, xpub_end + 1, extra_path_len - 1); // Skip the leading '/'
                    extra_path[extra_path_len - 1] = '\0';
                    
                    // Parse the extra path segments
                    char *extra_copy = strdup(extra_path);
                    if (extra_copy) {
                        // Split by '/'
                        char *segment = strtok(extra_copy, "/");
                        int depth = 0;
                        
                        while (segment) {
                            char *segment_copy = strdup(segment);
                            if (!segment_copy) {
                                free(extra_copy);
                                free(extra_path);
                                free(path_str);
                                return false;
                            }
                            
                            switch (depth) {
                                case 0: comp->change = segment_copy; break;
                                case 1: comp->address_index = segment_copy; break;
                                default: free(segment_copy); break; // Ignore extra segments
                            }
                            segment = strtok(NULL, "/");
                            depth++;
                        }
                        
                        free(extra_copy);
                    }
                    
                    free(extra_path);
                }
            }
        }
    }

    free(path_str);
    return true;
}

/**
 * @brief Extracts xprv/xpub and BIP32 path from a descriptor string
 * @param desc The descriptor string to parse
 * @return A populated DescriptorComponents structure
 */
DescriptorComponents extract_descriptor_components(const char *desc) {
    DescriptorComponents result = {false, NULL, NULL, NULL, NULL, NULL, NULL};
    if (!desc) return result;

    // Check if it's xprv or xpub
    const char *start = strstr(desc, "(xprv");
    bool is_private = true;
    if (!start) {
        start = strstr(desc, "]xpub");
        is_private = false;
        if (!start) {
            // Try direct format without brackets
            start = strstr(desc, "xprv");
            is_private = true;
            if (!start) {
                start = strstr(desc, "xpub");
                is_private = false;
                if (!start) {
                    return result;  // No xprv/xpub found
                }
            }
        }
    }

    // Skip the prefix
    if (is_private) {
        if (start[0] == '(') {
            start += 5; // Skip "(xprv"
        } else {
            start += 4; // Skip "xprv"
        }
    } else {
        if (start[0] == ']') {
            start += 5; // Skip "]xpub"
        } else {
            start += 4; // Skip "xpub"
        }
    }

    // Find the end of the xprv/xpub (either '/' or ')')
    const char *end_of_key = start;
    while (*end_of_key && *end_of_key != '/' && *end_of_key != ')') {
        end_of_key++;
    }
    if (end_of_key == start) return result;  // No key found

    // Extract xprv/xpub
    size_t key_len = end_of_key - start;
    result.xprv_or_xpub = malloc(key_len + 1);
    if (!result.xprv_or_xpub) return result;
    
    strncpy(result.xprv_or_xpub, start, key_len);
    result.xprv_or_xpub[key_len] = '\0';
    result.is_private = is_private;

    // Parse the BIP32 path
    if (is_private) {
        // For xprv, the path is directly after the key
        if (*end_of_key == '/') {
            const char *end_of_path = strstr(end_of_key, ")#");
            if (!end_of_path) {
                end_of_path = strstr(end_of_key, ")");
            }
            if (end_of_path) {
                size_t path_len = end_of_path - end_of_key;
                char *path_str = malloc(path_len + 1);
                if (path_str) {
                    strncpy(path_str, end_of_key + 1, path_len - 1); // Skip the leading '/'
                    path_str[path_len - 1] = '\0';
                    parse_bip32_path(path_str, &result);
                    free(path_str);
                }
            }
        }
    } else {
        // For xpub, we need to parse the fingerprint path and the extra path
        parse_descriptor_path(desc, &result);
    }

    return result;
}

/**
 * @brief Encodes binary data to Base58 string
 * @param data Input binary data to encode
 * @param data_len Length of input data in bytes
 * @param result Output buffer to store Base58 string
 * @param result_size Size of output buffer
 * @return 1 on success, 0 on failure
 */
int base58_encode(const uint8_t *data, size_t data_len, char *result, size_t result_size) {
    if (!data || !result || result_size == 0) return 0;
    
    BIGNUM *bn = BN_new();
    if (!bn) return 0;

    if (!BN_bin2bn(data, data_len, bn)) {
        BN_free(bn);
        return 0;
    }
    
    // Encode
    char *result_ptr = result + result_size - 1;
    *result_ptr = '\0';
    
    while (!BN_is_zero(bn) && result_ptr > result) {
        int remainder = BN_div_word(bn, 58);
        if (remainder == (BN_ULONG)-1) {
            BN_free(bn);
            return 0;
        }
        *(--result_ptr) = b58_alphabet[remainder];
    }
    
    // Add leading '1's for leading zeros in data
    for (size_t i = 0; i < data_len && data[i] == 0; i++) {
        if (result_ptr > result) {
            *(--result_ptr) = b58_alphabet[0];
        }
    }
    
    // Move the result to the beginning of the output buffer
    if (result_ptr > result) {
        size_t output_len = (result + result_size - 1) - result_ptr;
        memmove(result, result_ptr, output_len + 1);
    }
    
    BN_free(bn);
    return 1;
}

/**
 * @brief Decodes a Base58 string to binary data
 * @param input Input Base58 string
 * @param output Output buffer for binary data
 * @param output_len Pointer to size of output buffer (updated with actual length)
 * @return 1 on success, 0 on failure
 */
int base58_decode(const char *input, uint8_t *output, size_t *output_len) {
    if (!input || !output || !output_len || *output_len == 0) return 0;
    
    size_t input_len = strlen(input);
    if (input_len == 0) return 0;
    
    // Count leading '1's (for leading zeros)
    size_t leading_ones = 0;
    while (leading_ones < input_len && input[leading_ones] == '1') {
        leading_ones++;
    }
    
    // Prepare BIGNUM
    BIGNUM *bn = BN_new();
    if (!bn) return 0;
    
    // BN_zero returns void in OpenSSL 3.0, so we don't check its return value
    BN_zero(bn);
    
    // Decode
    for (size_t i = leading_ones; i < input_len; i++) {
        const char *p = strchr(b58_alphabet, input[i]);
        if (!p) {
            BN_free(bn);
            return 0; // Invalid character
        }
        
        if (!BN_mul_word(bn, 58)) {
            BN_free(bn);
            return 0;
        }
        
        if (!BN_add_word(bn, p - b58_alphabet)) {
            BN_free(bn);
            return 0;
        }
    }
    
    // Convert BIGNUM to binary
    size_t bn_size = BN_num_bytes(bn);
    if (bn_size + leading_ones > *output_len) {
        BN_free(bn);
        return 0; // Output buffer too small
    }
    
    // Add leading zeros
    memset(output, 0, leading_ones);
    
    // Convert BIGNUM to binary (skip leading zeros)
    if (bn_size > 0) {
        if (BN_bn2bin(bn, output + leading_ones) != bn_size) {
            BN_free(bn);
            return 0;
        }
    }
    
    *output_len = leading_ones + bn_size;
    BN_free(bn);
    return 1;
}

/**
 * @brief Checks if a BIP32 derivation index is hardened
 * @param index The index to check
 * @return true if hardened, false otherwise
 */
bool is_hardened(uint32_t index) {
    return index >= 0x80000000;
}

/**
 * @brief Parses a derivation index string (e.g., "44h" or "0'") to uint32_t value
 * @param str String representation of the index
 * @return The parsed index value
 */
uint32_t parse_derivation_index(const char *str) {
    if (!str) return 0;
    
    char *endptr;
    uint32_t index = strtoul(str, &endptr, 10);
    
    // Check for hardened notation ('h', ''')
    if (*endptr == 'h' || *endptr == '\'' || *endptr == 'H') {
        index |= 0x80000000;  // Set the hardened bit
    }
    
    return index;
}

/**
 * @brief Checks if a derivation path contains hardened indices
 * @param comp Pointer to the DescriptorComponents structure
 * @return true if path contains hardened indices, false otherwise
 */
bool path_contains_hardened(const DescriptorComponents *comp) {
    if (!comp) return false;
    
    // Check purpose
    if (comp->purpose && (strstr(comp->purpose, "h") || strstr(comp->purpose, "'"))) {
        return true;
    }
    
    // Check coin_type
    if (comp->coin_type && (strstr(comp->coin_type, "h") || strstr(comp->coin_type, "'"))) {
        return true;
    }
    
    // Check account
    if (comp->account && (strstr(comp->account, "h") || strstr(comp->account, "'"))) {
        return true;
    }
    
    // Check change (unlikely to be hardened, but check anyway)
    if (comp->change && (strstr(comp->change, "h") || strstr(comp->change, "'"))) {
        return true;
    }
    
    // Check address_index (unlikely to be hardened, but check anyway)
    if (comp->address_index && comp->address_index[0] != '*' && 
        (strstr(comp->address_index, "h") || strstr(comp->address_index, "'"))) {
        return true;
    }
    
    return false;
}

/**
 * @brief Parses descriptor components into a DerivationPath structure
 * @param comp Pointer to the DescriptorComponents structure
 * @return The parsed DerivationPath
 */
DerivationPath parse_path(const DescriptorComponents *comp) {
    DerivationPath path = {{0}, 0};
    if (!comp) return path;
    
    // Add purpose
    if (comp->purpose) {
        path.indices[path.length++] = parse_derivation_index(comp->purpose);
    }
    
    // Add coin type
    if (comp->coin_type) {
        path.indices[path.length++] = parse_derivation_index(comp->coin_type);
    }
    
    // Add account
    if (comp->account) {
        path.indices[path.length++] = parse_derivation_index(comp->account);
    }
    
    // Add change
    if (comp->change) {
        path.indices[path.length++] = parse_derivation_index(comp->change);
    }
    
    // We'll handle address_index separately since it could be a wildcard "*"
    
    return path;
}

/**
 * @brief Decodes Base58Check encoded extended key
 * @param encoded The Base58 encoded string
 * @param key Pointer to ExtendedKey structure to populate
 * @return 1 on success, 0 on failure
 */
int decode_extended_key(const char *encoded, ExtendedKey *key) {
    if (!encoded || !key) return 0;
    
    // Check if we need to add xpub/xprv prefix
    char *full_key = NULL;
    const char *decode_str = encoded;
    
    // If the key doesn't start with 'x', it might be missing the prefix
    if (encoded[0] != 'x') {
        // Add the appropriate prefix based on the is_private flag
        if (key->is_private) {
            full_key = malloc(strlen(encoded) + 5);
            if (!full_key) return 0;
            sprintf(full_key, "xprv%s", encoded);
        } else {
            full_key = malloc(strlen(encoded) + 5);
            if (!full_key) return 0;
            sprintf(full_key, "xpub%s", encoded);
        }
        decode_str = full_key;
    }
    
    // Allocate buffer for decoded data (including 4-byte checksum)
    uint8_t decoded[82]; // 78 bytes data + 4 bytes checksum
    size_t decoded_len = sizeof(decoded);
    
    if (!base58_decode(decode_str, decoded, &decoded_len)) {
        if (full_key) free(full_key);
        return 0;
    }
    
    if (decoded_len != 82) {
        if (full_key) free(full_key);
        return 0;
    }
    
    // Verify checksum
    uint8_t checksum[32];
    SHA256(decoded, 78, checksum);
    SHA256(checksum, 32, checksum);
    
    if (memcmp(checksum, decoded + 78, 4) != 0) {
        if (full_key) free(full_key);
        return 0; // Invalid checksum
    }
    
    // Extract components
    memcpy(key->version, decoded, 4);
    key->depth = decoded[4];
    memcpy(key->parent_fingerprint, decoded + 5, 4);
    key->child_number = (decoded[9] << 24) | (decoded[10] << 16) | (decoded[11] << 8) | decoded[12];
    memcpy(key->chain_code, decoded + 13, 32);
    memcpy(key->key, decoded + 45, 33);
    
    // Determine if it's a private key
    key->is_private = (decoded[45] == 0x00 && memcmp(key->version, XPRV_VERSION, 4) == 0);
    
    if (full_key) free(full_key);
    return 1;
}

/**
 * @brief Generates a fingerprint from a public key
 * @param pubkey Public key to generate fingerprint from
 * @param pubkey_len Length of public key
 * @param fingerprint Output buffer for fingerprint (4 bytes)
 */
void get_pubkey_fingerprint(const uint8_t *pubkey, size_t pubkey_len, uint8_t fingerprint[4]) {
    if (!pubkey || !fingerprint || pubkey_len == 0) return;
    
    uint8_t hash[32];
    uint8_t ripemd[20];
    
    SHA256(pubkey, pubkey_len, hash);
    
    // Use EVP_MD API instead of deprecated RIPEMD160
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (!EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    if (!EVP_DigestUpdate(ctx, hash, 32)) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    if (!EVP_DigestFinal_ex(ctx, ripemd, NULL)) {
        EVP_MD_CTX_free(ctx);
        return;
    }
    
    EVP_MD_CTX_free(ctx);
    
    memcpy(fingerprint, ripemd, 4);
}

/**
 * @brief Computes a public key from a private key
 * @param privkey Private key (32 bytes)
 * @param pubkey Output buffer for public key (33 bytes)
 * @return 1 on success, 0 on failure
 */
int privkey_to_pubkey(const uint8_t *privkey, uint8_t *pubkey) {
    if (!privkey || !pubkey) return 0;
    
    // Use EC_KEY API for compatibility with older OpenSSL versions
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) return 0;
    
    BIGNUM *priv_bn = BN_bin2bn(privkey, 32, NULL);
    if (!priv_bn) {
        EC_KEY_free(key);
        return 0;
    }
    
    if (!EC_KEY_set_private_key(key, priv_bn)) {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return 0;
    }
    
    const EC_GROUP *group = EC_KEY_get0_group(key);
    if (!group) {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return 0;
    }
    
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point) {
        BN_free(priv_bn);
        EC_KEY_free(key);
        return 0;
    }
    
    // Calculate public key = private key * G
    if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(key);
        return 0;
    }
    
    // Convert to compressed point format (33 bytes)
    if (EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, pubkey, 33, NULL) != 33) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        EC_KEY_free(key);
        return 0;
    }
    
    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    EC_KEY_free(key);
    return 1;
}

/**
 * @brief Derives a child extended key from a parent extended key using BIP32
 * @param parent Parent extended key
 * @param index Child index (hardened if >= 0x80000000)
 * @param child Output buffer for child extended key
 * @return 1 on success, 0 on failure
 */
int derive_child_key(const ExtendedKey *parent, uint32_t index, ExtendedKey *child) {
    if (!parent || !child) return 0;
    
    // Cannot derive hardened child from public key
    if (!parent->is_private && is_hardened(index)) {
        printf("Error: Cannot derive hardened child key (index %u') from public key\n", 
               index & 0x7FFFFFFF);
        return 0;
    }
    
    // Initialize child key with zeros
    memset(child, 0, sizeof(ExtendedKey));
    
    // Copy parent data to child
    memcpy(child->version, parent->version, 4);
    child->depth = parent->depth + 1;
    child->child_number = index;
    child->is_private = parent->is_private;
    
    if (parent->is_private) {
        // Parent is private key (xprv)
        uint8_t parent_pubkey[33];
        
        // Compute parent's public key
        if (!privkey_to_pubkey(parent->key + 1, parent_pubkey)) {
            return 0;
        }
        
        // Set parent fingerprint
        get_pubkey_fingerprint(parent_pubkey, 33, child->parent_fingerprint);
        
        // For hardened derivation
        if (is_hardened(index)) {
            // Data = 0x00 || parent private key || index
            uint8_t data[38]; // Increased size to 38 to fix array bounds issue
            memset(data, 0, sizeof(data));
            
            data[0] = 0;
            memcpy(data + 1, parent->key, 33);
            data[34] = (index >> 24) & 0xFF;
            data[35] = (index >> 16) & 0xFF;
            data[36] = (index >> 8) & 0xFF;
            data[37] = index & 0xFF;
            
            // HMAC-SHA512
            uint8_t I[64];
            if (!HMAC(EVP_sha512(), parent->chain_code, 32, data, 38, I, NULL)) {
                return 0;
            }
            
            // Split I into I_L and I_R
            BIGNUM *I_L = BN_bin2bn(I, 32, NULL);
            if (!I_L) {
                return 0;
            }
            
            memcpy(child->chain_code, I + 32, 32);
            
            // Get the curve order
            BIGNUM *order = BN_new();
            if (!order) {
                BN_free(I_L);
                return 0;
            }
            
            if (!BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")) {
                BN_free(I_L);
                BN_free(order);
                return 0;
            }
            
            // Check if I_L >= curve order
            if (BN_cmp(I_L, order) >= 0) {
                BN_free(I_L);
                BN_free(order);
                return 0; // Invalid derivation
            }
            
            // Child key = (I_L + parent key) mod n
            BIGNUM *parent_key = BN_bin2bn(parent->key + 1, 32, NULL);
            if (!parent_key) {
                BN_free(I_L);
                BN_free(order);
                return 0;
            }
            
            if (!BN_add(I_L, I_L, parent_key)) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0;
            }
            
            // Create a BN_CTX for BN_mod operation
            BN_CTX *ctx = BN_CTX_new();
            if (!ctx) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0;
            }
            
            if (!BN_mod(I_L, I_L, order, ctx)) {
                BN_CTX_free(ctx);
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0;
            }
            
            BN_CTX_free(ctx);
            
            // Check for zero key
            if (BN_is_zero(I_L)) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0; // Invalid derivation
            }
            
            // Convert to binary
            child->key[0] = 0; // Private key prefix
            memset(child->key + 1, 0, 32); // Clear the buffer
            
            int bn_bytes = BN_num_bytes(I_L);
            if (bn_bytes > 32) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0; // Invalid key size
            }
            
            if (!BN_bn2bin(I_L, child->key + 1 + (32 - bn_bytes))) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0;
            }
            
            BN_free(I_L);
            BN_free(parent_key);
            BN_free(order);
        } else {
            // For normal derivation (index < 0x80000000)
            // Data = parent public key || index
            uint8_t data[37];
            memset(data, 0, sizeof(data));
            
            memcpy(data, parent_pubkey, 33);
            data[33] = (index >> 24) & 0xFF;
            data[34] = (index >> 16) & 0xFF;
            data[35] = (index >> 8) & 0xFF;
            data[36] = index & 0xFF;
            
            // HMAC-SHA512
            uint8_t I[64];
            if (!HMAC(EVP_sha512(), parent->chain_code, 32, data, 37, I, NULL)) {
                return 0;
            }
            
            // Split I into I_L and I_R
            BIGNUM *I_L = BN_bin2bn(I, 32, NULL);
            if (!I_L) {
                return 0;
            }
            
            memcpy(child->chain_code, I + 32, 32);
            
            // Get the curve order
            BIGNUM *order = BN_new();
            if (!order) {
                BN_free(I_L);
                return 0;
            }
            
            if (!BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")) {
                BN_free(I_L);
                BN_free(order);
                return 0;
            }
            
            // Check if I_L >= curve order
            if (BN_cmp(I_L, order) >= 0) {
                BN_free(I_L);
                BN_free(order);
                return 0; // Invalid derivation
            }
            
            // Child key = (I_L + parent key) mod n
            BIGNUM *parent_key = BN_bin2bn(parent->key + 1, 32, NULL);
            if (!parent_key) {
                BN_free(I_L);
                BN_free(order);
                return 0;
            }
            
            if (!BN_add(I_L, I_L, parent_key)) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0;
            }
            
            // Create a BN_CTX for BN_mod operation
            BN_CTX *ctx = BN_CTX_new();
            if (!ctx) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0;
            }
            
            if (!BN_mod(I_L, I_L, order, ctx)) {
                BN_CTX_free(ctx);
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0;
            }
            
            BN_CTX_free(ctx);
            
            // Check for zero key
            if (BN_is_zero(I_L)) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0; // Invalid derivation
            }
            
            // Convert to binary
            child->key[0] = 0; // Private key prefix
            memset(child->key + 1, 0, 32); // Clear the buffer
            
            int bn_bytes = BN_num_bytes(I_L);
            if (bn_bytes > 32) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0; // Invalid key size
            }
            
            if (!BN_bn2bin(I_L, child->key + 1 + (32 - bn_bytes))) {
                BN_free(I_L);
                BN_free(parent_key);
                BN_free(order);
                return 0;
            }
            
            BN_free(I_L);
            BN_free(parent_key);
            BN_free(order);
        }
    } else {
        // Parent is public key (xpub)
        // Normal derivation only (can't derive hardened keys from public key)
        if (is_hardened(index)) {
            return 0; // Can't derive hardened child from public key
        }
        
        // Set parent fingerprint
        get_pubkey_fingerprint(parent->key, 33, child->parent_fingerprint);
        
        // Data = parent public key || index
        uint8_t data[37];
        memset(data, 0, sizeof(data));
        
        memcpy(data, parent->key, 33);
        data[33] = (index >> 24) & 0xFF;
        data[34] = (index >> 16) & 0xFF;
        data[35] = (index >> 8) & 0xFF;
        data[36] = index & 0xFF;
        
        // HMAC-SHA512
        uint8_t I[64];
        if (!HMAC(EVP_sha512(), parent->chain_code, 32, data, 37, I, NULL)) {
            return 0;
        }
        
        // Split I into I_L and I_R
        BIGNUM *I_L = BN_bin2bn(I, 32, NULL);
        if (!I_L) {
            return 0;
        }
        
        memcpy(child->chain_code, I + 32, 32);
        
        // Get the curve order
        BIGNUM *order = BN_new();
        if (!order) {
            BN_free(I_L);
            return 0;
        }
        
        if (!BN_hex2bn(&order, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")) {
            BN_free(I_L);
            BN_free(order);
            return 0;
        }
        
        // Check if I_L >= curve order
        if (BN_cmp(I_L, order) >= 0) {
            BN_free(I_L);
            BN_free(order);
            return 0; // Invalid derivation
        }
        
        // Use EC_KEY API for compatibility with older OpenSSL versions
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
        if (!key) {
            BN_free(I_L);
            BN_free(order);
            return 0;
        }
        
        const EC_GROUP *group = EC_KEY_get0_group(key);
        if (!group) {
            EC_KEY_free(key);
            BN_free(I_L);
            BN_free(order);
            return 0;
        }
        
        EC_POINT *point1 = EC_POINT_new(group);
        EC_POINT *point2 = EC_POINT_new(group);
        EC_POINT *result = EC_POINT_new(group);
        
        if (!point1 || !point2 || !result) {
            if (point1) EC_POINT_free(point1);
            if (point2) EC_POINT_free(point2);
            if (result) EC_POINT_free(result);
            EC_KEY_free(key);
            BN_free(I_L);
            BN_free(order);
            return 0;
        }
        
        // point1 = I_L*G
        if (!EC_POINT_mul(group, point1, I_L, NULL, NULL, NULL)) {
            EC_POINT_free(point1);
            EC_POINT_free(point2);
            EC_POINT_free(result);
            EC_KEY_free(key);
            BN_free(I_L);
            BN_free(order);
            return 0;
        }
        
        // point2 = parent public key
        if (!EC_POINT_oct2point(group, point2, parent->key, 33, NULL)) {
            EC_POINT_free(point1);
            EC_POINT_free(point2);
            EC_POINT_free(result);
            EC_KEY_free(key);
            BN_free(I_L);
            BN_free(order);
            return 0;
        }
        
        // result = point1 + point2
        if (!EC_POINT_add(group, result, point1, point2, NULL)) {
            EC_POINT_free(point1);
            EC_POINT_free(point2);
            EC_POINT_free(result);
            EC_KEY_free(key);
            BN_free(I_L);
            BN_free(order);
            return 0;
        }
        
        // Check if result is at infinity
        if (EC_POINT_is_at_infinity(group, result)) {
            EC_POINT_free(point1);
            EC_POINT_free(point2);
            EC_POINT_free(result);
            EC_KEY_free(key);
            BN_free(I_L);
            BN_free(order);
            return 0; // Invalid derivation
        }
        
        // Convert to compressed point format
        if (EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED, child->key, 33, NULL) != 33) {
            EC_POINT_free(point1);
            EC_POINT_free(point2);
            EC_POINT_free(result);
            EC_KEY_free(key);
            BN_free(I_L);
            BN_free(order);
            return 0;
        }
        
        EC_POINT_free(point1);
        EC_POINT_free(point2);
        EC_POINT_free(result);
        EC_KEY_free(key);
        BN_free(I_L);
        BN_free(order);
    }
    
    return 1;
}

/**
 * @brief Derives a series of child keys based on the derivation path
 * @param master Master extended key
 * @param path Derivation path
 * @param derived Output buffer for derived extended key
 * @return 1 on success, 0 on failure
 */
int derive_path(const ExtendedKey *master, const DerivationPath *path, ExtendedKey *derived) {
    if (!master || !path || !derived) return 0;
    
    // Start with a copy of the master key
    memcpy(derived, master, sizeof(ExtendedKey));
    
    // Apply each derivation step
    for (size_t i = 0; i < path->length; i++) {
        ExtendedKey child;
        memset(&child, 0, sizeof(ExtendedKey));
        
        if (!derive_child_key(derived, path->indices[i], &child)) {
            return 0;
        }
        
        // Copy the child key to derived for the next iteration
        memcpy(derived, &child, sizeof(ExtendedKey));
    }
    
    return 1;
}

/**
 * @brief Convert public key to P2WPKH address (SegWit)
 * @param pubkey Public key (33 bytes)
 * @param address Output buffer for address
 * @param address_size Size of address buffer
 * @return 1 on success, 0 on failure
 */
int pubkey_to_p2wpkh_address(const uint8_t *pubkey, char *address, size_t address_size) {
    if (!pubkey || !address || address_size < 45) return 0;
    
    // Step 1: SHA256 hash of the public key
    uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(pubkey, 33, sha256_hash);
    
    // Step 2: RIPEMD160 hash of the SHA256 hash
    uint8_t hash160[20]; // RIPEMD160_DIGEST_LENGTH
    
    // Use EVP_MD API instead of deprecated RIPEMD160
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }
    
    if (!EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DigestUpdate(ctx, sha256_hash, SHA256_DIGEST_LENGTH)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DigestFinal_ex(ctx, hash160, NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Step 3: Encode the hash with Bech32 (bc1...)
    // This is a simplified Bech32 encoding - in real implementations,
    // you'd want to use a proper Bech32 library
    
    // For now, we'll format it as 'bc1q' followed by the hash160 in hex
    strcpy(address, "bc1q");
    for (int i = 0; i < 20; i++) {
        sprintf(address + 4 + (i * 2), "%02x", hash160[i]);
    }
    
    return 1;
}

/**
 * @brief Convert public key to legacy P2PKH address (Pay-to-Public-Key-Hash)
 * @param pubkey Public key (33 bytes compressed)
 * @param address Output buffer for address
 * @param address_size Size of address buffer
 * @return 1 on success, 0 on failure
 */
int pubkey_to_legacy_address(const uint8_t *pubkey, char *address, size_t address_size) {
    if (!pubkey || !address || address_size < 35) return 0;
    
    // Step 1: SHA256 hash of the public key
    uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(pubkey, 33, sha256_hash);
    
    // Step 2: RIPEMD160 hash of the SHA256 hash
    uint8_t hash160[20]; // RIPEMD160_DIGEST_LENGTH
    
    // Use EVP_MD API instead of deprecated RIPEMD160
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }
    
    if (!EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DigestUpdate(ctx, sha256_hash, SHA256_DIGEST_LENGTH)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DigestFinal_ex(ctx, hash160, NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Step 3: Prepare data for Base58Check encoding (version 0x00 + HASH160 + checksum)
    uint8_t data[25];
    data[0] = 0x00; // P2PKH address version
    memcpy(data + 1, hash160, 20);
    
    // Step 4: Calculate checksum (double SHA256)
    SHA256(data, 21, sha256_hash);
    SHA256(sha256_hash, SHA256_DIGEST_LENGTH, sha256_hash);
    memcpy(data + 21, sha256_hash, 4);
    
    // Step 5: Base58Check encode
    if (!base58_encode(data, 25, address, address_size)) {
        return 0;
    }
    
    return 1;
}

/**
 * @brief Convert public key to P2SH-P2WPKH address (Nested SegWit)
 * @param pubkey Public key (33 bytes compressed)
 * @param address Output buffer for address
 * @param address_size Size of address buffer
 * @return 1 on success, 0 on failure
 */
int pubkey_to_p2sh_p2wpkh_address(const uint8_t *pubkey, char *address, size_t address_size) {
    if (!pubkey || !address || address_size < 35) return 0;
    
    // Step 1: SHA256 hash of the public key
    uint8_t sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(pubkey, 33, sha256_hash);
    
    // Step 2: RIPEMD160 hash of the SHA256 hash (HASH160)
    uint8_t hash160[20]; // RIPEMD160_DIGEST_LENGTH
    
    // Use EVP_MD API instead of deprecated RIPEMD160
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }
    
    if (!EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DigestUpdate(ctx, sha256_hash, SHA256_DIGEST_LENGTH)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DigestFinal_ex(ctx, hash160, NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Step 3: Create the P2WPKH redeem script: 0x0014 + HASH160
    uint8_t redeem_script[22];
    redeem_script[0] = 0x00;
    redeem_script[1] = 0x14;
    memcpy(redeem_script + 2, hash160, 20);
    
    // Step 4: Calculate HASH160 of the redeem script
    SHA256(redeem_script, 22, sha256_hash);
    
    // Use EVP_MD API again for RIPEMD160
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return 0;
    }
    
    if (!EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DigestUpdate(ctx, sha256_hash, SHA256_DIGEST_LENGTH)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (!EVP_DigestFinal_ex(ctx, hash160, NULL)) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Step 5: Prepare data for Base58Check encoding (version 0x05 + HASH160 + checksum)
    uint8_t data[25];
    data[0] = 0x05; // P2SH address version
    memcpy(data + 1, hash160, 20);
    
    // Calculate checksum (double SHA256)
    SHA256(data, 21, sha256_hash);
    SHA256(sha256_hash, SHA256_DIGEST_LENGTH, sha256_hash);
    memcpy(data + 21, sha256_hash, 4);
    
    // Base58Check encode
    if (!base58_encode(data, 25, address, address_size)) {
        return 0;
    }
    
    return 1;
}

/**
 * @brief Convert public key to P2TR address (Taproot)
 * @param pubkey Public key (33 bytes compressed)
 * @param address Output buffer for address
 * @param address_size Size of address buffer
 * @return 1 on success, 0 on failure
 */
int pubkey_to_p2tr_address(const uint8_t *pubkey, char *address, size_t address_size) {
    if (!pubkey || !address || address_size < 45) return 0;
    
    // For P2TR, we need x-only public key (32 bytes)
    uint8_t x_only_pubkey[32];
    
    // Skip the first byte (0x02 or 0x03 for compressed key)
    memcpy(x_only_pubkey, pubkey + 1, 32);
    
    // In a real implementation, we would:
    // 1. Compute the tagged hash "TapTweak" of the x-only pubkey
    // 2. Use Bech32m encoding (not regular Bech32)
    // 3. Include the version byte (0x01 for P2TR)
    
    // This is a placeholder implementation that just shows the x-only pubkey
    strcpy(address, "bc1p");
    for (int i = 0; i < 32; i++) {
        sprintf(address + 4 + (i * 2), "%02x", x_only_pubkey[i]);
    }
    
    return 1;
}

/**
 * @brief Converts an extended key's public key to a Bitcoin address
 * @param key Extended key containing the public key
 * @param type Type of address to generate (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR)
 * @param address Output buffer for the address
 * @param address_size Size of the address buffer
 * @return 1 on success, 0 on failure
 */
int extended_key_to_address(const ExtendedKey *key, AddressType type, char *address, size_t address_size) {
    if (!key || !address) return 0;
    
    uint8_t pubkey[33];
    
    // If we have a private key, derive the public key first
    if (key->is_private) {
        if (!privkey_to_pubkey(key->key + 1, pubkey)) {
            return 0;
        }
    } else {
        // Already have public key
        memcpy(pubkey, key->key, 33);
    }
    
    // Generate address based on type
    switch (type) {
        case ADDR_LEGACY_P2PKH:
            return pubkey_to_legacy_address(pubkey, address, address_size);
        case ADDR_P2SH_P2WPKH:
            return pubkey_to_p2sh_p2wpkh_address(pubkey, address, address_size);
        case ADDR_P2WPKH:
            return pubkey_to_p2wpkh_address(pubkey, address, address_size);
        case ADDR_P2TR:
            return pubkey_to_p2tr_address(pubkey, address, address_size);
        default:
            return 0;
    }
}

/**
 * @brief Determines if a BIP32 index represents an address index (based on descriptor)
 * @param index_str String representation of the index (can be "*" for range)
 * @return true if it's a valid address index or wildcard, false otherwise
 */
bool is_valid_address_index(const char *index_str) {
    if (!index_str) return false;
    
    // Check if it's a wildcard
    if (strcmp(index_str, "*") == 0) return true;
    
    // Check if it's a numeric index (0-2^31-1)
    char *endptr;
    unsigned long index = strtoul(index_str, &endptr, 10);
    
    // Valid if we parsed the entire string and index is in valid range
    return (*endptr == '\0' && index < 0x80000000);
}

/**
 * @brief Generate an address from descriptor components and index
 * @param comp Descriptor components containing the key and derivation path
 * @param addr_type Type of address to generate
 * @param index Index to use if the descriptor has a wildcard
 * @param address Output buffer for address
 * @param address_size Size of address buffer
 * @return 1 on success, 0 on failure
 */
int generate_address_from_descriptor(const DescriptorComponents *comp, 
                                    AddressType addr_type,
                                    uint32_t index,
                                    char *address,
                                    size_t address_size) {
    if (!comp || !comp->xprv_or_xpub || !address) return 0;
    
    // Check if we're trying to derive hardened paths from xpub
    if (!comp->is_private && path_contains_hardened(comp)) {
        // For xpub keys with hardened paths, we can still show the public key
        // but we can't derive further
        printf("Warning: Cannot derive hardened paths from xpub key. Showing base public key only.\n");
        
        // Decode the extended key
        ExtendedKey master_key;
        memset(&master_key, 0, sizeof(ExtendedKey));
        master_key.is_private = comp->is_private;
        
        if (!decode_extended_key(comp->xprv_or_xpub, &master_key)) {
            return 0;
        }
        
        // Generate address from the base key
        return extended_key_to_address(&master_key, addr_type, address, address_size);
    }
    
    // Decode the extended key
    ExtendedKey master_key;
    memset(&master_key, 0, sizeof(ExtendedKey));
    master_key.is_private = comp->is_private;
    
    if (!decode_extended_key(comp->xprv_or_xpub, &master_key)) {
        return 0;
    }
    
    // Parse derivation path
    DerivationPath path = parse_path(comp);
    
    // If we have a wildcard in the address index, replace it with the provided index
    bool has_wildcard = comp->address_index && strcmp(comp->address_index, "*") == 0;
    
    // Derive keys according to path
    ExtendedKey derived_key;
    memset(&derived_key, 0, sizeof(ExtendedKey));
    
    if (!derive_path(&master_key, &path, &derived_key)) {
        return 0;
    }
    
    // If there's a wildcard index, do an additional derivation step
    if (has_wildcard) {
        ExtendedKey child_key;
        memset(&child_key, 0, sizeof(ExtendedKey));
        
        if (!derive_child_key(&derived_key, index, &child_key)) {
            return 0;
        }
        derived_key = child_key;
    }
    
    // Generate address from the derived key
    return extended_key_to_address(&derived_key, addr_type, address, address_size);
}

/**
 * @brief Generate addresses for a specific range from a descriptor
 * @param comp Descriptor components
 * @param addr_type Type of address to generate
 * @param start_index Starting index for address generation
 * @param count Number of addresses to generate
 * @return 1 on success, 0 on failure
 */
int generate_address_range(const DescriptorComponents *comp, 
                          AddressType addr_type,
                          uint32_t start_index,
                          uint32_t count) {
    if (!comp || !comp->xprv_or_xpub) return 0;
    
    // Check if we're trying to derive hardened paths from xpub
    if (!comp->is_private && path_contains_hardened(comp)) {
        // For xpub keys with hardened paths, we can still show the public key
        // but we can't derive further
        printf("Warning: Cannot derive hardened paths from xpub key. Showing base public key only.\n");
        
        // Decode the extended key
        ExtendedKey master_key;
        memset(&master_key, 0, sizeof(ExtendedKey));
        master_key.is_private = comp->is_private;
        
        if (!decode_extended_key(comp->xprv_or_xpub, &master_key)) {
            return 0;
        }
        
        // Print the public key in hex format
        printf("Public key (hex): ");
        for (int i = 0; i < 33; i++) {
            printf("%02x", master_key.key[i]);
        }
        printf("\n");
        
        // Generate address from the base key
        char address[100];
        if (extended_key_to_address(&master_key, addr_type, address, sizeof(address))) {
            printf("Base public key address: %s\n", address);
            return 1;
        } else {
            printf("Failed to generate address from base public key\n");
            return 0;
        }
    }
    
    // Buffer for addresses
    char address[100];
    
    printf("Generating %u addresses starting from index %u:\n", count, start_index);
    printf("----------------------------------------------------\n");
    
    // Generate each address in the range
    for (uint32_t i = 0; i < count; i++) {
        uint32_t index = start_index + i;
        
        if (generate_address_from_descriptor(comp, addr_type, index, address, sizeof(address))) {
            printf("Index %u: %s\n", index, address);
        } else {
            printf("Failed to generate address for index %u\n", index);
            return 0;
        }
    }
    
    printf("----------------------------------------------------\n");
    return 1;
}

/**
 * @brief Determines the address type from the descriptor string
 * @param desc Descriptor string
 * @return The determined address type (defaults to P2WPKH if not recognized)
 */
AddressType get_address_type_from_descriptor(const char *desc) {
    if (!desc) return ADDR_P2WPKH; // Default to P2WPKH
    
    if (strncmp(desc, "pkh(", 4) == 0) {
        return ADDR_LEGACY_P2PKH;
    } else if (strstr(desc, "sh(wpkh(") != NULL) {
        return ADDR_P2SH_P2WPKH;
    } else if (strncmp(desc, "wpkh(", 5) == 0) {
        return ADDR_P2WPKH;
    } else if (strncmp(desc, "tr(", 3) == 0) {
        return ADDR_P2TR;
    }
    
    // Default to P2WPKH if not recognized
    return ADDR_P2WPKH;
}

/**
 * @brief Prints detailed information about an extended key
 * @param key The extended key to print information for
 */
void print_extended_key_info(const ExtendedKey *key) {
    if (!key) return;
    
    printf("Extended Key Details:\n");
    printf("  Is Private: %s\n", key->is_private ? "Yes (xprv)" : "No (xpub)");
    printf("  Depth: %u\n", key->depth);
    printf("  Parent Fingerprint: %02x%02x%02x%02x\n", 
           key->parent_fingerprint[0], key->parent_fingerprint[1],
           key->parent_fingerprint[2], key->parent_fingerprint[3]);
    printf("  Child Number: %u%s\n", 
           key->child_number & 0x7FFFFFFF,
           (key->child_number & 0x80000000) ? "'" : "");
    
    // Print chain code (first few bytes)
    printf("  Chain Code: %02x%02x%02x%02x...\n",
           key->chain_code[0], key->chain_code[1],
           key->chain_code[2], key->chain_code[3]);
    
    // For private keys, just indicate we have it (don't print it)
    if (key->is_private) {
        printf("  Private Key: [Present]\n");
    } else {
        // For public keys, print the first few bytes
        printf("  Public Key: %02x%02x%02x%02x...\n",
               key->key[0], key->key[1], key->key[2], key->key[3]);
    }
}

int main() {
    // const char *filename = "list-descriptors.json";
    const char *filename = "list_descriptors_true.json";

    struct json_object *json_obj = json_object_from_file(filename);
    if (!json_obj) {
        printf("Error reading or parsing '%s'\n", filename);
        return 1;
    }

    // Access descriptors array
    struct json_object *descriptors;
    if (json_object_object_get_ex(json_obj, "descriptors", &descriptors)) {
        int array_len = json_object_array_length(descriptors);
        printf("Found %d descriptors\n", array_len);

        for (int i = 0; i < array_len; i++) {
            struct json_object *descriptor = json_object_array_get_idx(descriptors, i);
            struct json_object *desc;

            if (json_object_object_get_ex(descriptor, "desc", &desc)) {
                const char *desc_str = json_object_get_string(desc);
                printf("\nOriginal descriptor %d: %s\n", i+1, desc_str);

                // Extract components
                DescriptorComponents comp = extract_descriptor_components(desc_str);
                if (comp.xprv_or_xpub) {
                    printf("Key type: %s\n", comp.is_private ? "xprv (private)" : "xpub (public)");
                    printf("Extracted key: %s\n", comp.xprv_or_xpub);

                    // Decode the extended key
                    ExtendedKey decoded_key;
                    memset(&decoded_key, 0, sizeof(ExtendedKey));
                    decoded_key.is_private = comp.is_private;
                    
                    if (decode_extended_key(comp.xprv_or_xpub, &decoded_key)) {
                        print_extended_key_info(&decoded_key);
                    } else {
                        printf("Error: Failed to decode extended key\n");
                    }

                    // Print named BIP32 path segments (if they exist)
                    if (comp.purpose) {
                        printf("BIP32 Path:\n");
                        printf("  Purpose: %s\n", comp.purpose);
                        printf("  Coin Type: %s\n", comp.coin_type ? comp.coin_type : "N/A");
                        printf("  Account: %s\n", comp.account ? comp.account : "N/A");
                        printf("  Change: %s\n", comp.change ? comp.change : "N/A");
                        printf("  Address Index: %s\n", comp.address_index ? comp.address_index : "N/A");

                        // Determine address type from descriptor
                        AddressType addr_type = get_address_type_from_descriptor(desc_str);
                        printf("Address Type: ");
                        switch (addr_type) {
                            case ADDR_LEGACY_P2PKH: printf("Legacy P2PKH (1...)\n"); break;
                            case ADDR_P2SH_P2WPKH: printf("P2SH-P2WPKH (3...)\n"); break;
                            case ADDR_P2WPKH: printf("Native SegWit P2WPKH (bc1q...)\n"); break;
                            case ADDR_P2TR: printf("Taproot P2TR (bc1p...)\n"); break;
                        }

                        // If we have a wildcard address index, generate a sample of addresses
                        if (comp.address_index && strcmp(comp.address_index, "*") == 0) {
                            // Generate first 5 addresses for this descriptor
                            generate_address_range(&comp, addr_type, 0, 5);
                        } else if (comp.address_index) {
                            // Generate a single address at the specified index
                            uint32_t index = parse_derivation_index(comp.address_index);
                            char address[100];
                            
                            if (generate_address_from_descriptor(&comp, addr_type, index, address, sizeof(address))) {
                                printf("Address: %s\n", address);
                            } else {
                                printf("Failed to generate address\n");
                            }
                        }
                    } else {
                        printf("No BIP32 path found.\n");
                    }
                } else {
                    printf("No xprv/xpub found in descriptor.\n");
                }
                free_descriptor_components(&comp);  // Clean up
            }
        }
    }

    json_object_put(json_obj);
    return 0;
}
