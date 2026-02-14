#include "../../common/protocol.h"
#include <assert.h>
#include <stdio.h>

#define TEST_VAULT_FILE "test_vault_temp.bin"

// ============================================================================
// Test Helpers
// ============================================================================

static void print_test_header(const char *test_name) {
    printf("  Testing: %s... ", test_name);
}

static void print_test_pass(void) {
    printf("✅\n");
}

// ============================================================================
// Unit Tests
// ============================================================================

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

static void test_vault_generation(void) {
    print_test_header("Vault generation (uniqueness)");

    SecureVault vault1, vault2;

    generate_secure_vault(&vault1);
    generate_secure_vault(&vault2);

    // Two separately generated vaults must be different
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

static void test_challenge_indices(void) {
    print_test_header("Challenge index generation");

    Challenge challenge;
    generate_challenge(&challenge);

    // Indices must be within valid range
    assert(challenge.indices[0] >= 0 && challenge.indices[0] < N_KEYS);
    assert(challenge.indices[1] >= 0 && challenge.indices[1] < N_KEYS);
    // Indices must be different
    assert(challenge.indices[0] != challenge.indices[1]);

    print_test_pass();
}

static void test_vault_key_computation(void) {
    print_test_header("Vault key computation");

    SecureVault vault;
    generate_secure_vault(&vault);

    Challenge challenge;
    generate_challenge(&challenge);

    uint8_t key[KEY_SIZE_BYTES];
    compute_vault_key(&vault, &challenge, key);

    // Manual XOR to verify
    uint8_t expected[KEY_SIZE_BYTES] = {0};
    for (int i = 0; i < P_INDICES; i++) {
        xor_bytes(expected, expected, vault.keys[challenge.indices[i]], KEY_SIZE_BYTES);
    }

    assert(memcmp(key, expected, KEY_SIZE_BYTES) == 0);
    print_test_pass();
}

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

static void test_vault_save_load(void) {
    print_test_header("Vault save and load");

    SecureVault original, loaded;

    generate_secure_vault(&original);

    // Save and check return value
    int save_result = save_vault(&original, TEST_VAULT_FILE);
    assert(save_result == 1);

    // Load and check return value
    int load_result = load_vault(&loaded, TEST_VAULT_FILE);
    assert(load_result == 1);

    // Verify content is identical
    assert(memcmp(&original, &loaded, sizeof(SecureVault)) == 0);

    // Cleanup
    remove(TEST_VAULT_FILE);

    print_test_pass();
}

static void test_vault_load_nonexistent(void) {
    print_test_header("Load nonexistent vault");

    SecureVault vault;
    int result = load_vault(&vault, "nonexistent_file_12345.bin");
    assert(result == 0);

    print_test_pass();
}

// ============================================================================
// Main
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

    printf("\n========================================\n");
    printf("  All unit tests passed successfully!\n");
    printf("========================================\n");

    return 0;
}