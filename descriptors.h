#ifndef DESCRIPTORS_H
#define DESCRIPTORS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Constants
#define MAX_PATH_DEPTH 10
#define MAX_ADDRESS_SIZE 100
#define HARDENED_BIT 0x80000000

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
    uint32_t indices[MAX_PATH_DEPTH];  // Support up to MAX_PATH_DEPTH levels
    size_t length;
} DerivationPath;

// Base58 encoding/decoding functions
int base58_decode(const char *input, uint8_t *output, size_t *output_len);
int base58_encode(const uint8_t *data, size_t data_len, char *result, size_t result_size);

// Descriptor parsing functions
bool parse_descriptor_type(const char *desc, AddressType *addr_type);
DescriptorComponents extract_descriptor_components(const char *desc);
void free_descriptor_components(DescriptorComponents *comp);
bool parse_bip32_path(const char *path, DescriptorComponents *comp);
bool parse_descriptor_path(const char *desc, DescriptorComponents *comp);
uint32_t parse_derivation_index(const char *str);
bool is_hardened(uint32_t index);
bool path_contains_hardened(const DescriptorComponents *comp);
DerivationPath parse_path(const DescriptorComponents *comp);
bool is_valid_address_index(const char *index_str);

// Extended key functions
int decode_extended_key(const char *encoded, ExtendedKey *key);
void print_extended_key_info(const ExtendedKey *key);
int get_pubkey_fingerprint(const uint8_t *pubkey, size_t pubkey_len, 
                            uint8_t fingerprint[4]);
int privkey_to_pubkey(const uint8_t *privkey, uint8_t *pubkey);
int derive_child_key(const ExtendedKey *parent, uint32_t index,
                    ExtendedKey *child);
int derive_path(const ExtendedKey *master, const DerivationPath *path,
                ExtendedKey *derived);

// Address generation functions
int pubkey_to_p2wpkh_address(const uint8_t *pubkey, char *address,
                            size_t address_size);
int pubkey_to_legacy_address(const uint8_t *pubkey, char *address,
                            size_t address_size);
int pubkey_to_p2sh_p2wpkh_address(const uint8_t *pubkey, char *address,
                            size_t address_size);
int pubkey_to_p2tr_address(const uint8_t *pubkey, char *address,
                        size_t address_size);
int extended_key_to_address(const ExtendedKey *key, AddressType type,
                            char *address, 
                            size_t address_size);
int generate_address_from_descriptor(const DescriptorComponents *comp, 
                                    AddressType addr_type,
                                    uint32_t index,
                                    char *address,
                                    size_t address_size);

int generate_address_range(const DescriptorComponents *comp,
                            AddressType addr_type,
                            uint32_t start_index,
                            uint32_t count,
                            void (*callback)(
                                const char *address, 
                                uint32_t index, 
                                void *user_data
                            ),
                            void *user_data);

int process_descriptor(const char *desc, uint32_t index, char *address, 
                        size_t address_size);

bool is_segment_hardened(const char *segment);

#endif /* DESCRIPTORS_H */
