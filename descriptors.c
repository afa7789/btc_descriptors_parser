#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

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

// Free memory used by DescriptorComponents
void free_descriptor_components(DescriptorComponents *comp) {
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

// Parse a BIP32 path like "/44h/0h/0h/0/*" into named segments
void parse_bip32_path(const char *path, DescriptorComponents *comp) {
    if (!path || !comp) return;

    // Make a copy to avoid modifying the original
    char *path_copy = strdup(path);
    if (!path_copy) return;

    // Split by '/'
    char *segment = strtok(path_copy, "/");
    int depth = 0;

    while (segment) {
        switch (depth) {
            case 0: comp->purpose = strdup(segment); break;
            case 1: comp->coin_type = strdup(segment); break;
            case 2: comp->account = strdup(segment); break;
            case 3: comp->change = strdup(segment); break;
            case 4: comp->address_index = strdup(segment); break;
            default: break; // Ignore extra segments (unlikely in BIP32)
        }
        segment = strtok(NULL, "/");
        depth++;
    }

    free(path_copy);
}

// Extract xprv/xpub + named BIP32 path
DescriptorComponents extract_descriptor_components(const char *desc) {
    DescriptorComponents result = {false, NULL, NULL, NULL, NULL, NULL, NULL};
    if (!desc) return result;

    // Check if it's xprv or xpub
    const char *start = strstr(desc, "(xprv");
    bool is_private = true;
    if (!start) {
        start = strstr(desc, "]xpub");
        is_private = false;
    }
    if (!start) return result;  // No xprv/xpub found

    start += 5;

    // Find the end of the xprv/xpub (either '/' or ')')
    const char *end_of_key = start;
    while (*end_of_key && *end_of_key != '/' && *end_of_key != ')') {
        end_of_key++;
    }
    if (end_of_key == start) return result;  // No key found
    printf("Key found: %.*s\n", (int)(end_of_key - start), start);

    // Extract xprv/xpub
    size_t key_len = end_of_key - start;
    result.xprv_or_xpub = malloc(key_len + 1);
    strncpy(result.xprv_or_xpub, start, key_len);
    result.xprv_or_xpub[key_len] = '\0';
    result.is_private = is_private;

    // Extract and parse derivation path (if it exists)
    if (is_private) {
        if (*end_of_key == '/') {
            const char *end_of_path = strstr(end_of_key, ")#");
            printf("bip_path found: %.*s\n", (int)(end_of_path - end_of_key), end_of_key);
            if (end_of_path) {
                size_t path_len = end_of_path - end_of_key;
                char *path_str = malloc(path_len + 1);
                strncpy(path_str, end_of_key, path_len);
                path_str[path_len] = '\0';
                parse_bip32_path(path_str, &result);
                free(path_str);
            }
        }
    } else {
        if (desc) {
            const char *start_of_path = strstr(desc, "([");
            const char *end_of_path = strstr(desc, "]xpub");
        
            if (start_of_path && end_of_path) {
                start_of_path += 2;  // Skip "(["
                size_t path_len = end_of_path - start_of_path;
        
                // Calculate end_of_key (after xpub key up to '/' or ')')
                const char *xpub_start = end_of_path + strlen("]xpub");
                const char *end_of_key = xpub_start;
        
                while (*end_of_key && *end_of_key != '/' && *end_of_key != ')') {
                    end_of_key++;
                }
        
                // Get the next 4 chars after end_of_key
                const char *extra_path_start = end_of_key;
                size_t extra_path_len = 0;
        
                if (*extra_path_start) {
                    // Take up to 4 characters if available
                    while (extra_path_len < 4 && extra_path_start[extra_path_len] && extra_path_start[extra_path_len] != ')') {
                        extra_path_len++;
                    }
                }
        
                // Allocate buffer for path + 4 extra chars + null terminator
                size_t total_len = path_len + extra_path_len;
                char *path_str = malloc(total_len + 1);
                if (path_str) {
                    // Copy fingerprint/path part
                    strncpy(path_str, start_of_path, path_len);
        
                    // Append 4 extra chars after end_of_key
                    if (extra_path_len > 0) {
                        strncpy(path_str + path_len, extra_path_start, extra_path_len);
                    }
        
                    // Null-terminate
                    path_str[total_len] = '\0';
        
                    // Debug output
                    printf("Final bip_path for parse_bip32_path: %s\n", path_str);
        
                    // Parse it
                    parse_bip32_path(path_str, &result);
        
                    free(path_str);
                }
            }
        }
    }

    return result;
}

int main() {
    const char *filename = "list-descriptors.json";
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

                    // Print named BIP32 path segments (if they exist)
                    if (comp.purpose) {
                        printf("BIP32 Path:\n");
                        printf("  Purpose: %s\n", comp.purpose);
                        printf("  Coin Type: %s\n", comp.coin_type ? comp.coin_type : "N/A");
                        printf("  Account: %s\n", comp.account ? comp.account : "N/A");
                        printf("  Change: %s\n", comp.change ? comp.change : "N/A");
                        printf("  Address Index: %s\n", comp.address_index ? comp.address_index : "N/A");
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