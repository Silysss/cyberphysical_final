#include "protocol.h"
#include <stdio.h>

/**
 * @file generate_vault.c
 * @brief Utility to generate the initial Secure Vault for both Client and Server.
 * 
 * This tool creates a new vault with random 128-bit keys and saves it
 * as an encrypted binary file using the MASTER_KEY from the environment.
 */
int main() {
    LOG_INIT();
    printf("Generating secure initial vault...\n");

    // 1. Generate a new set of random keys
    SecureVault vault;
    generate_secure_vault(&vault);

    // 2. Retrieve the MASTER_KEY used for at-rest encryption
    const char *master_key_str = getenv("MASTER_KEY");
    if (!master_key_str || strlen(master_key_str) < 16) {
        fprintf(stderr, "Error: MASTER_KEY not configured or too short (min 16 bytes)\n");
        return EXIT_FAILURE;
    }

    // 3. Save the vault to a central file (encrypted)
    // This file will be distributed to client/ and server/ directories.
    if (!save_vault(&vault, "common/vault.bin", (const uint8_t *)master_key_str)) {
        fprintf(stderr, "Error during vault file writing\n");
        return EXIT_FAILURE;
    }

    printf("✅ Vault successfully generated and saved to common/vault.bin\n");
    printf("Vault content summary:\n");
    for (int i = 0; i < N_KEYS; i++) {
        printf("  Key %d: ", i);
        print_hex(vault.keys[i], KEY_SIZE_BYTES);
    }

    return 0;
}