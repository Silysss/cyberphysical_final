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

static void test_challenge_response_cycle(void) {
    print_test_header("Challenge-response cycle");

    SecureVault vault;
    generate_secure_vault(&vault);

    Challenge challenge;
    generate_challenge(&challenge);

    Response response;
    compute_response(&vault, &challenge, &response);

    int is_valid = verify_response(&vault, &challenge, &response);
    assert(is_valid == 1);

    print_test_pass();
}

static void test_invalid_response_rejected(void) {
    print_test_header("Invalid response rejection");

    SecureVault vault;
    generate_secure_vault(&vault);

    Challenge challenge;
    generate_challenge(&challenge);

    // Generate a random (wrong) response
    Response wrong_response;
    generate_random_bytes(wrong_response.response, KEY_SIZE_BYTES);

    int is_valid = verify_response(&vault, &challenge, &wrong_response);
    assert(is_valid == 0);

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
    test_challenge_response_cycle();
    test_invalid_response_rejected();
    test_vault_save_load();
    test_vault_load_nonexistent();

    printf("\n========================================\n");
    printf("  All unit tests passed successfully!\n");
    printf("========================================\n");

    return 0;
}