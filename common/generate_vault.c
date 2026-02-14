#include "protocol.h"
#include <stdio.h>

int main() {
    LOG_INIT();
    printf("Génération du vault sécurisé...\n");

    // Générer un nouveau vault
    SecureVault vault;
    generate_secure_vault(&vault);

    // Sauvegarder le vault dans un fichier
    if (!save_vault(&vault, "common/vault.bin")) {
        fprintf(stderr, "Erreur lors de l'écriture du vault\n");
        return EXIT_FAILURE;
    }

    printf("✅ Vault généré et sauvegardé dans common/vault.bin\n");
    printf("Contenu du vault:\n");
    for (int i = 0; i < N_KEYS; i++) {
        printf("  Clé %d: ", i);
        print_hex(vault.keys[i], KEY_SIZE_BYTES);
    }

    return 0;
}