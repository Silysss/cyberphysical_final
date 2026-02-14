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

    // Stage 3: Client computes k1, generates C2, r2, t1. Sends M3 {Enc(k1, r1||t1||C2||r2)}
    printf("  3. [CLIENT -> SERVER] M3: Response to C1 + Challenge C2 + t1\n");
    uint8_t client_k1[16];
    compute_vault_key(&ctx.client_vault, &ctx.c1, client_k1);
    assert(memcmp(ctx.k1, client_k1, 16) == 0);

    uint8_t t1[16];
    generate_random_bytes(t1, 16);

    generate_challenge(&ctx.c2);
    uint8_t plaintext_m3[56];
    memcpy(plaintext_m3, ctx.c1.r, 16);
    memcpy(plaintext_m3 + 16, t1, 16);
    memcpy(plaintext_m3 + 32, ctx.c2.indices, 8);
    memcpy(plaintext_m3 + 40, ctx.c2.r, 16);

    uint8_t ciphertext_m3[64];
    int enc_len_m3 = aes_encrypt(plaintext_m3, 56, client_k1, ciphertext_m3);
    assert(enc_len_m3 > 0);

    // Stage 4: Server decrypts M3, verifies r1, extracts t1, generates t2. Sends M4 {Enc(k2 ^ t1, r2 || t2)}
    printf("  4. [SERVER -> CLIENT] M4: Response to C2 + t2\n");
    uint8_t decrypted_m3[64];
    int dec_len_m3 = aes_decrypt(ciphertext_m3, enc_len_m3, ctx.k1, decrypted_m3);
    assert(dec_len_m3 >= 56);
    assert(memcmp(decrypted_m3, ctx.c1.r, 16) == 0); // Verify r1

    uint8_t server_received_t1[16];
    memcpy(server_received_t1, decrypted_m3 + 16, 16);

    Challenge server_received_c2;
    memcpy(server_received_c2.indices, decrypted_m3 + 32, 8);
    memcpy(server_received_c2.r, decrypted_m3 + 40, 16);

    compute_vault_key(&ctx.server_vault, &server_received_c2, ctx.k2);
    
    uint8_t t2[16];
    generate_random_bytes(t2, 16);

    // Key for M4 = k2 ^ t1
    uint8_t k_m4[16];
    xor_bytes(k_m4, ctx.k2, server_received_t1, 16);

    uint8_t plaintext_m4[32];
    memcpy(plaintext_m4, server_received_c2.r, 16);
    memcpy(plaintext_m4 + 16, t2, 16);

    uint8_t ciphertext_m4[64];
    int enc_len_m4 = aes_encrypt(plaintext_m4, 32, k_m4, ciphertext_m4);
    assert(enc_len_m4 > 0);

    uint8_t server_t[16];
    xor_bytes(server_t, server_received_t1, t2, 16);

    // Stage 5: Client decrypts M4, verifies r2, extracts t2, computes entropy
    printf("  5. [CLIENT] Verifying M4 and computing session key...\n");
    uint8_t client_k2[16];
    compute_vault_key(&ctx.client_vault, &ctx.c2, client_k2);
    
    uint8_t client_k_m4[16];
    xor_bytes(client_k_m4, client_k2, t1, 16);

    uint8_t decrypted_m4[64];
    int dec_len_m4 = aes_decrypt(ciphertext_m4, enc_len_m4, client_k_m4, decrypted_m4);
    assert(dec_len_m4 >= 32);
    assert(memcmp(decrypted_m4, ctx.c2.r, 16) == 0);

    uint8_t client_received_t2[16];
    memcpy(client_received_t2, decrypted_m4 + 16, 16);

    uint8_t client_t[16];
    xor_bytes(client_t, t1, client_received_t2, 16);

    assert(memcmp(server_t, client_t, 16) == 0);

    printf("\n  Result: ✅ MUTUAL AUTHENTICATION & SESSION KEY SUCCESS\n");
    printf("  Session Key: ");
    for(int i=0; i<16; i++) printf("%02x", client_t[i]);
    printf("\n");
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
    memcpy(plaintext_m3, ctx.c1.r, 16);
    memcpy(plaintext_m3 + 16, ctx.c2.indices, 8);
    memcpy(plaintext_m3 + 24, ctx.c2.r, 16);

    uint8_t ciphertext_m3[64];
    aes_encrypt(plaintext_m3, 40, client_k1, ciphertext_m3);

    // Server tries to decrypt with ITS k1
    uint8_t decrypted_m3[64];
    int dec_len_m3 = aes_decrypt(ciphertext_m3, 64, ctx.k1, decrypted_m3);
    
    // Decryption will either fail or yield garbage
    int success = (dec_len_m3 >= 40 && memcmp(decrypted_m3, ctx.c1.r, 16) == 0);

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