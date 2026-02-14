#include "../../common/protocol.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define TEST_VAULT_FILE "test_integration_vault.bin"

// ============================================================================
// Test Context
// ============================================================================

typedef struct {
    SecureVault server_vault;
    SecureVault client_vault;
    Challenge challenge;
    Response client_response;
} TestContext;

// ============================================================================
// Setup & Teardown
// ============================================================================

static void setup_shared_vault(TestContext *ctx) {
    printf("  Setting up shared vault...\n");

    // Generate a vault
    generate_secure_vault(&ctx->server_vault);

    // Simulate sharing: copy to client
    memcpy(&ctx->client_vault, &ctx->server_vault, sizeof(SecureVault));

    // Verify both vaults are identical
    assert(memcmp(&ctx->server_vault, &ctx->client_vault, sizeof(SecureVault)) == 0);

    printf("  Vault configured with %d keys of %d bits each\n", N_KEYS, KEY_SIZE_BITS);
}

static void print_challenge(const Challenge *challenge) {
    printf("  Challenge indices: ");
    for (int i = 0; i < P_INDICES; i++) {
        printf("%d", challenge->indices[i]);
        if (i < P_INDICES - 1) printf(", ");
    }
    printf("\n");
    printf("  Nonce: ");
    print_hex(challenge->nonce, KEY_SIZE_BYTES);
}

// ============================================================================
// Protocol Simulation Functions
// ============================================================================

static void server_generate_challenge(TestContext *ctx) {
    printf("  [SERVER] Generating challenge...\n");
    generate_challenge(&ctx->challenge);
    print_challenge(&ctx->challenge);
}

static void client_compute_response(TestContext *ctx) {
    printf("  [CLIENT] Computing response...\n");
    compute_response(&ctx->client_vault, &ctx->challenge, &ctx->client_response);
    printf("  Response: ");
    print_hex(ctx->client_response.response, KEY_SIZE_BYTES);
}

static int server_verify_response(TestContext *ctx) {
    printf("  [SERVER] Verifying response...\n");
    int is_valid = verify_response(&ctx->server_vault, &ctx->challenge, &ctx->client_response);
    return is_valid;
}

// ============================================================================
// Test Cases
// ============================================================================

static void test_successful_authentication(void) {
    printf("\n[Test 1] Successful Authentication Flow\n");
    printf("----------------------------------------\n");

    TestContext ctx;

    setup_shared_vault(&ctx);
    server_generate_challenge(&ctx);
    client_compute_response(&ctx);

    int is_valid = server_verify_response(&ctx);

    printf("\n  Result: %s\n", is_valid ? "✅ AUTHENTICATED" : "❌ REJECTED");
    assert(is_valid == 1);
}

static void test_failed_authentication_wrong_vault(void) {
    printf("\n[Test 2] Failed Authentication (Wrong Vault)\n");
    printf("---------------------------------------------\n");

    TestContext ctx;

    // Server has one vault
    generate_secure_vault(&ctx.server_vault);

    // Client has a DIFFERENT vault (simulating attack/mistake)
    generate_secure_vault(&ctx.client_vault);

    printf("  Server and client have DIFFERENT vaults\n");

    server_generate_challenge(&ctx);
    client_compute_response(&ctx);

    int is_valid = server_verify_response(&ctx);

    printf("\n  Result: %s\n", is_valid ? "❌ UNEXPECTED SUCCESS" : "✅ CORRECTLY REJECTED");
    assert(is_valid == 0);
}

static void test_failed_authentication_tampered_response(void) {
    printf("\n[Test 3] Failed Authentication (Tampered Response)\n");
    printf("---------------------------------------------------\n");

    TestContext ctx;

    setup_shared_vault(&ctx);
    server_generate_challenge(&ctx);
    client_compute_response(&ctx);

    // Tamper with the response
    printf("  [ATTACKER] Tampering with response...\n");
    ctx.client_response.response[0] ^= 0xFF;
    printf("  Modified response: ");
    print_hex(ctx.client_response.response, KEY_SIZE_BYTES);

    int is_valid = server_verify_response(&ctx);

    printf("\n  Result: %s\n", is_valid ? "❌ UNEXPECTED SUCCESS" : "✅ CORRECTLY REJECTED");
    assert(is_valid == 0);
}

static void test_vault_persistence(void) {
    printf("\n[Test 4] Vault Persistence (Save/Load)\n");
    printf("---------------------------------------\n");

    TestContext ctx1, ctx2;

    // Create and save vault
    printf("  Creating and saving vault...\n");
    generate_secure_vault(&ctx1.server_vault);

    int save_result = save_vault(&ctx1.server_vault, TEST_VAULT_FILE);
    assert(save_result == 1);
    printf("  Vault saved to %s\n", TEST_VAULT_FILE);

    // Load vault in another context
    printf("  Loading vault in separate context...\n");
    int load_result = load_vault(&ctx2.server_vault, TEST_VAULT_FILE);
    assert(load_result == 1);

    // Verify authentication works with loaded vault
    memcpy(&ctx2.client_vault, &ctx2.server_vault, sizeof(SecureVault));
    generate_challenge(&ctx2.challenge);
    compute_response(&ctx2.client_vault, &ctx2.challenge, &ctx2.client_response);

    int is_valid = verify_response(&ctx2.server_vault, &ctx2.challenge, &ctx2.client_response);

    printf("  Authentication with persisted vault: %s\n", is_valid ? "✅ SUCCESS" : "❌ FAILED");
    assert(is_valid == 1);

    // Cleanup
    remove(TEST_VAULT_FILE);
    printf("  Cleanup complete\n");
}

static void test_multiple_challenges(void) {
    printf("\n[Test 5] Multiple Challenge-Response Cycles\n");
    printf("---------------------------------------------\n");

    TestContext ctx;
    setup_shared_vault(&ctx);

    int successes = 0;
    int iterations = 5;

    printf("  Running %d authentication cycles...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        generate_challenge(&ctx.challenge);
        compute_response(&ctx.client_vault, &ctx.challenge, &ctx.client_response);

        if (verify_response(&ctx.server_vault, &ctx.challenge, &ctx.client_response)) {
            successes++;
        }
    }

    printf("  Result: %d/%d authentications succeeded\n", successes, iterations);
    assert(successes == iterations);
}

// ============================================================================
// Main
// ============================================================================

int main(void) {
    LOG_INIT();

    printf("==============================================\n");
    printf("    Integration Tests - Authentication Protocol\n");
    printf("==============================================\n");

    test_successful_authentication();
    test_failed_authentication_wrong_vault();
    test_failed_authentication_tampered_response();
    test_vault_persistence();
    test_multiple_challenges();

    printf("\n==============================================\n");
    printf("   All integration tests passed successfully!\n");
    printf("==============================================\n");

    return 0;
}