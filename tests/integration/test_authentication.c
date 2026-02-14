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
    Challenge c1;
    Challenge c2;
    uint8_t k1[16];
    uint8_t k2[16];
} TestContext;

// ============================================================================
// Setup
// ============================================================================

static void setup_shared_vault(TestContext *ctx) {
    generate_secure_vault(&ctx->server_vault);
    memcpy(&ctx->client_vault, &ctx->server_vault, sizeof(SecureVault));
}

// ============================================================================
// Protocol Simulation
// ============================================================================

static void test_3way_handshake_flow(void) {
    printf("\n[Test 1] Full 3-Way Handshake Simulation\n");
    printf("----------------------------------------\n");

    TestContext ctx;
    setup_shared_vault(&ctx);

    // Stage 1: Client sends M1 {ID, SessionID} -> Simulating receipt
    printf("  1. [CLIENT -> SERVER] M1: Init connection\n");

    // Stage 2: Server generates C1, r1
    printf("  2. [SERVER -> CLIENT] M2: Challenge C1\n");
    generate_challenge(&ctx.c1);
    compute_vault_key(&ctx.server_vault, &ctx.c1, ctx.k1);

    // Stage 3: Client computes k1, generates C2, r2. Sends M3 {Enc(k1, r1||C2||r2)}
    printf("  3. [CLIENT -> SERVER] M3: Response to C1 + Challenge C2\n");
    uint8_t client_k1[16];
    compute_vault_key(&ctx.client_vault, &ctx.c1, client_k1);
    assert(memcmp(ctx.k1, client_k1, 16) == 0);

    generate_challenge(&ctx.c2);
    uint8_t plaintext_m3[40];
    memcpy(plaintext_m3, ctx.c1.nonce, 16);
    memcpy(plaintext_m3 + 16, ctx.c2.indices, 8);
    memcpy(plaintext_m3 + 24, ctx.c2.nonce, 16);

    uint8_t ciphertext_m3[64];
    int enc_len_m3 = aes_encrypt(plaintext_m3, 40, client_k1, ciphertext_m3);
    assert(enc_len_m3 > 0);

    // Stage 4: Server decrypts M3, verifies r1, computes k2. Sends M4 {Enc(k2, r2)}
    printf("  4. [SERVER -> CLIENT] M4: Response to C2\n");
    uint8_t decrypted_m3[64];
    int dec_len_m3 = aes_decrypt(ciphertext_m3, enc_len_m3, ctx.k1, decrypted_m3);
    assert(dec_len_m3 >= 40);
    assert(memcmp(decrypted_m3, ctx.c1.nonce, 16) == 0); // Verify r1

    Challenge server_received_c2;
    memcpy(server_received_c2.indices, decrypted_m3 + 16, 8);
    memcpy(server_received_c2.nonce, decrypted_m3 + 24, 16);

    compute_vault_key(&ctx.server_vault, &server_received_c2, ctx.k2);
    uint8_t ciphertext_m4[64];
    int enc_len_m4 = aes_encrypt(server_received_c2.nonce, 16, ctx.k2, ciphertext_m4);
    assert(enc_len_m4 > 0);

    // Stage 5: Client decrypts M4, verifies r2
    printf("  5. [CLIENT] Verifying M4...\n");
    uint8_t client_k2[16];
    compute_vault_key(&ctx.client_vault, &ctx.c2, client_k2);
    assert(memcmp(ctx.k2, client_k2, 16) == 0);

    uint8_t decrypted_m4[64];
    int dec_len_m4 = aes_decrypt(ciphertext_m4, enc_len_m4, client_k2, decrypted_m4);
    assert(dec_len_m4 >= 16);
    assert(memcmp(decrypted_m4, ctx.c2.nonce, 16) == 0);

    printf("\n  Result: ✅ MUTUAL AUTHENTICATION SUCCESS\n");
}

static void test_handshake_fails_on_wrong_vault(void) {
    printf("\n[Test 2] Handshake Failure (Client has wrong vault)\n");
    printf("----------------------------------------------------\n");

    TestContext ctx;
    generate_secure_vault(&ctx.server_vault);
    generate_secure_vault(&ctx.client_vault); // Different vault

    generate_challenge(&ctx.c1);
    compute_vault_key(&ctx.server_vault, &ctx.c1, ctx.k1);

    uint8_t client_k1[16];
    compute_vault_key(&ctx.client_vault, &ctx.c1, client_k1);
    // client_k1 should be different from server's ctx.k1

    generate_challenge(&ctx.c2);
    uint8_t plaintext_m3[40];
    memcpy(plaintext_m3, ctx.c1.nonce, 16);
    memcpy(plaintext_m3 + 16, ctx.c2.indices, 8);
    memcpy(plaintext_m3 + 24, ctx.c2.nonce, 16);

    uint8_t ciphertext_m3[64];
    aes_encrypt(plaintext_m3, 40, client_k1, ciphertext_m3);

    // Server tries to decrypt with ITS k1
    uint8_t decrypted_m3[64];
    int dec_len_m3 = aes_decrypt(ciphertext_m3, 64, ctx.k1, decrypted_m3);
    
    // Decryption will either fail or yield garbage
    int success = (dec_len_m3 >= 40 && memcmp(decrypted_m3, ctx.c1.nonce, 16) == 0);

    printf("\n  Result: %s\n", success ? "❌ UNEXPECTED SUCCESS" : "✅ CORRECTLY REJECTED");
    assert(success == 0);
}

int main(void) {
    LOG_INIT();
    printf("==============================================\n");
    printf("    Integration Tests - 3-Way Handshake\n");
    printf("==============================================\n");

    test_3way_handshake_flow();
    test_handshake_fails_on_wrong_vault();

    printf("\n==============================================\n");
    printf("   All integration tests passed successfully!\n");
    printf("==============================================\n");

    return 0;
}