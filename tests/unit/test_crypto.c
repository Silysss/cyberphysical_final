#include "../../common/protocol.h"
#include <assert.h>
#include <stdio.h>

/**
 * @file test_crypto.c
 * @brief Unit tests for the core cryptographic and utility functions.
 */

#define TEST_VAULT_FILE "test_vault_temp.bin"

// ============================================================================
// Test Helpers
// ============================================================================

/**
 * @brief Prints a standardized header for each unit test.
 */
static void print_test_header(const char *test_name) {
    printf("  Testing: %s... ", test_name);
}

/**
 * @brief Prints a success indicator for the current test.
 */
static void print_test_pass(void) {
    printf("✅\n");
}

// ============================================================================
// Unit Tests
// ============================================================================

/**
 * @brief Verifies the bitwise XOR utility function.
 */
static void test_xor_bytes(void) {
    print_test_header("XOR operation");

    uint8_t a[4] = {0x01, 0x02, 0x03, 0x04};
    uint8_t b[4] = {0x01, 0x04, 0x05, 0x08};
    uint8_t result[4];

    xor_bytes(result, a, b, 4);

    assert(result[0] == 0x00);  // 0x01 ^ 0x01 = 0x00
    assert(result[1] == 0x06);  // 0x02 ^ 0x04 = 0x06
    assert(result[2] == 0x06);  // 0x03 ^ 0x05 = 0x06
    assert(result[3] == 0x0C);  // 0x04 ^ 0x08 = 0x0C

    print_test_pass();
}

/**
 * @brief Ensures vault generation produces random, unique keys.
 */
static void test_vault_generation(void) {
    print_test_header("Vault generation (uniqueness)");

    SecureVault vault1, vault2;

    generate_secure_vault(&vault1);
    generate_secure_vault(&vault2);

    // Two separately generated vaults must be statistically unique
    int different = 0;
    for (int i = 0; i < N_KEYS; i++) {
        if (memcmp(vault1.keys[i], vault2.keys[i], KEY_SIZE_BYTES) != 0) {
            different = 1;
            break;
        }
    }
    assert(different == 1);

    print_test_pass();
}

/**
 * @brief Validates challenge generation (bounds and uniqueness).
 */
static void test_challenge_indices(void) {
    print_test_header("Challenge index generation");

    Challenge challenge;
    generate_challenge(&challenge);

    // Indices must be within the valid range [0, N_KEYS)
    assert(challenge.indices[0] >= 0 && challenge.indices[0] < N_KEYS);
    assert(challenge.indices[1] >= 0 && challenge.indices[1] < N_KEYS);
    // Indices must be unique within a single challenge
    assert(challenge.indices[0] != challenge.indices[1]);

    print_test_pass();
}

/**
 * @brief Verifies the composite key derivation from vault indices.
 */
static void test_vault_key_computation(void) {
    print_test_header("Vault key computation");

    SecureVault vault;
    generate_secure_vault(&vault);

    Challenge challenge;
    generate_challenge(&challenge);

    uint8_t key[KEY_SIZE_BYTES];
    compute_vault_key(&vault, &challenge, key);

    // Manually compute XOR to verify the implementation
    uint8_t expected[KEY_SIZE_BYTES] = {0};
    for (int i = 0; i < P_INDICES; i++) {
        xor_bytes(expected, expected, vault.keys[challenge.indices[i]], KEY_SIZE_BYTES);
    }

    assert(memcmp(key, expected, KEY_SIZE_BYTES) == 0);
    print_test_pass();
}

/**
 * @brief Tests symmetric encryption/decryption consistency with AES-128-CBC.
 */
static void test_aes_encryption_decryption(void) {
    print_test_header("AES encryption/decryption");

    uint8_t key[16] = "0123456789abcdef";
    uint8_t plaintext[32] = "Confidential data to encrypt...";
    uint8_t ciphertext[64];
    uint8_t decrypted[64];

    int enc_len = aes_encrypt(plaintext, 32, key, ciphertext);
    assert(enc_len > 0);
    assert(enc_len % AES_BLOCK_SIZE == 0);

    int dec_len = aes_decrypt(ciphertext, enc_len, key, decrypted);
    assert(dec_len == 32);
    assert(memcmp(plaintext, decrypted, 32) == 0);

    print_test_pass();
}

/**
 * @brief Verifies vault serialization/deserialization logic.
 */
static void test_vault_save_load(void) {
    print_test_header("Vault save and load");

    SecureVault original, loaded;
    uint8_t master_key[16] = "test-master-key!";

    generate_secure_vault(&original);

    // Persist to temporary file
    int save_result = save_vault(&original, TEST_VAULT_FILE, master_key);
    assert(save_result == 1);

    // Load from disk
    int load_result = load_vault(&loaded, TEST_VAULT_FILE, master_key);
    assert(load_result == 1);

    // Ensure content matches perfectly
    assert(memcmp(&original, &loaded, sizeof(SecureVault)) == 0);

    // Resource cleanup
    remove(TEST_VAULT_FILE);

    print_test_pass();
}

/**
 * @brief Validates error handling for missing vault files.
 */
static void test_vault_load_nonexistent(void) {
    print_test_header("Load nonexistent vault");

    SecureVault vault;
    uint8_t master_key[16] = "test-master-key!";
    int result = load_vault(&vault, "nonexistent_file_12345.bin", master_key);
    assert(result == 0);

    print_test_pass();
}

/**
 * @brief Checks for HMAC determinism and collision resilience.
 */
static void test_hmac_sha256(void) {
    print_test_header("HMAC-SHA256 (determinism)");

    uint8_t data[] = "Machine learning is fun";
    uint8_t key[] = "secret-key";
    uint8_t out1[32], out2[32];

    hmac_sha256(data, sizeof(data), key, sizeof(key), out1);
    hmac_sha256(data, sizeof(data), key, sizeof(key), out2);

    // Deterministic test
    assert(memcmp(out1, out2, 32) == 0);

    // Non-collision test
    uint8_t out3[32];
    uint8_t data2[] = "Machine learning is NOT fun";
    hmac_sha256(data2, sizeof(data2), key, sizeof(key), out3);
    assert(memcmp(out1, out3, 32) != 0);

    print_test_pass();
}

/**
 * @brief Validates that multiple parties produce the same vault update.
 */
static void test_vault_update_integrity(void) {
    print_test_header("Vault update (synchronization)");

    SecureVault vault_client, vault_server, original;
    generate_secure_vault(&vault_client);
    memcpy(&vault_server, &vault_client, sizeof(SecureVault));
    memcpy(&original, &vault_client, sizeof(SecureVault));

    uint8_t t[16] = "session-key-123";

    update_secure_vault(&vault_client, t, 16);
    update_secure_vault(&vault_server, t, 16);

    // Sync test: client and server MUST reach same state
    assert(memcmp(&vault_client, &vault_server, sizeof(SecureVault)) == 0);

    // Mutation test: vault MUST differ from state before update
    assert(memcmp(&vault_client, &original, sizeof(SecureVault)) != 0);

    print_test_pass();
}

/**
 * @brief Ensures vault updates actually modify the keys.
 */
static void test_vault_update_changes(void) {
    print_test_header("Vault update (content changes)");

    SecureVault vault, original;
    generate_secure_vault(&vault);
    memcpy(&original, &vault, sizeof(SecureVault));

    uint8_t t[16] = "session-key-456";
    update_secure_vault(&vault, t, 16);

    // Final integrity check
    assert(memcmp(&vault, &original, sizeof(SecureVault)) != 0);

    print_test_pass();
}

// ============================================================================
// Main entry point
// ============================================================================

int main(void) {
    LOG_INIT();
    printf("========================================\n");
    printf("       Unit Tests - Crypto Module\n");
    printf("========================================\n\n");

    test_xor_bytes();
    test_vault_generation();
    test_challenge_indices();
    test_vault_key_computation();
    test_aes_encryption_decryption();
    test_vault_save_load();
    test_vault_load_nonexistent();
    test_hmac_sha256();
    test_vault_update_integrity();
    test_vault_update_changes();

    printf("\n========================================\n");
    printf("  All unit tests passed successfully!\n");
    printf("========================================\n");

    return 0;
}