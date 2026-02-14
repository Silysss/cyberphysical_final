#include "iot_server.h"
#include <unistd.h>
#include <signal.h>

volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

void server_init(IoTServer *server, int port) {
    const char *vault_path = getenv("VAULT_PATH");
    if (!vault_path) vault_path = "common/vault.bin";

    // Charger le vault
    if (!load_vault(&server->vault, vault_path)) {
        fprintf(stderr, "Erreur: Impossible de charger le vault depuis %s\n", vault_path);
        exit(EXIT_FAILURE);
    }
    
    // Configurer l'adresse du serveur
    server->address.sin_family = AF_INET;
    server->address.sin_addr.s_addr = INADDR_ANY;
    server->address.sin_port = htons(port);
    
    server->server_socket = -1;
    server->client_socket = -1;
}

int server_start(IoTServer *server) {
    int opt = 1;
    
    // Créer le socket
    server->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_socket == 0) {
        perror("Échec de la création du socket");
        return -1;
    }
    
    // Configurer les options du socket
    if (setsockopt(server->server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                   &opt, sizeof(opt))) {
        perror("Échec de la configuration des options du socket");
        return -1;
    }
    
    // Lier le socket à l'adresse et au port
    if (bind(server->server_socket, (struct sockaddr *)&server->address, 
             sizeof(server->address)) < 0) {
        perror("Échec du bind");
        return -1;
    }
    
    // Écouter les connexions entrantes
    if (listen(server->server_socket, 5) < 0) {
        perror("Échec de l'écoute");
        return -1;
    }
    
    printf("Serveur en écoute sur le port %d...\n", ntohs(server->address.sin_port));
    
    // Configuration du signal pour arrêter proprement
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    return 0;
}

void server_handle_client(IoTServer *server) {
    socklen_t addrlen = sizeof(server->address);
    Message msg;

    server->client_socket = accept(server->server_socket, (struct sockaddr *)&server->address, &addrlen);
    if (server->client_socket < 0) return;

    printf("[SERVER] Client connecté depuis %s\n", inet_ntoa(server->address.sin_addr));

    // 1. Recevoir M1 {device_id, session_id}
    if (receive_message(server->client_socket, &msg) < 0 || msg.type != MSG_M1) {
        close(server->client_socket);
        return;
    }
    printf("[SERVER] M1 reçu: Device=%s, Session=%u\n", msg.data.m1.device_id, msg.data.m1.session_id);

    // 2. Envoyer M2 {C1, r1}
    Challenge c1;
    generate_challenge(&c1);
    msg.type = MSG_M2;
    msg.data.m2.challenge = c1;
    if (send_message(server->client_socket, &msg) < 0) {
        close(server->client_socket);
        return;
    }
    printf("[SERVER] M2 envoyé (Challenge C1)\n");

    // 3. Recevoir M3 {Enc(k1, r1 || C2 || r2)}
    if (receive_message(server->client_socket, &msg) < 0 || msg.type != MSG_M3) {
        close(server->client_socket);
        return;
    }

    uint8_t k1[KEY_SIZE_BYTES];
    compute_vault_key(&server->vault, &c1, k1);

    uint8_t decrypted[MAX_ENC_SIZE];
    int dec_len = aes_decrypt(msg.data.encrypted.data, msg.data.encrypted.size, k1, decrypted);
    
    // Vérifier r1 et extraire t1 + challenge C2 (r1:16, t1:16, indices:8, r2:16)
    if (dec_len < 56 || memcmp(decrypted, c1.r, KEY_SIZE_BYTES) != 0) {
        printf("[SERVER] Échec de l'authentification du client (mauvaise réponse ou r1 invalide)\n");
        msg.type = MSG_FAILURE;
        send_message(server->client_socket, &msg);
        close(server->client_socket);
        return;
    }

    uint8_t t1[KEY_SIZE_BYTES];
    memcpy(t1, decrypted + 16, 16);

    Challenge c2;
    memcpy(c2.indices, decrypted + 32, 8);
    memcpy(c2.r, decrypted + 40, 16);
    printf("[SERVER] M3 validé. t1 reçu et Client authentifié ! C2 reçu.\n");

    // 4. Envoyer M4 {Enc(k2 ^ t1, r2 || t2)}
    uint8_t k2[KEY_SIZE_BYTES];
    compute_vault_key(&server->vault, &c2, k2);

    uint8_t t2[KEY_SIZE_BYTES];
    generate_random_bytes(t2, KEY_SIZE_BYTES);

    // Clé pour M4 = k2 ^ t1
    uint8_t k_m4[KEY_SIZE_BYTES];
    xor_bytes(k_m4, k2, t1, KEY_SIZE_BYTES);

    // Données à chiffrer : r2 (16 bytes) + t2 (16 bytes) = 32 bytes
    uint8_t plaintext_m4[32];
    memcpy(plaintext_m4, c2.r, 16);
    memcpy(plaintext_m4 + 16, t2, 16);

    msg.type = MSG_M4;
    msg.data.encrypted.size = aes_encrypt(plaintext_m4, 32, k_m4, msg.data.encrypted.data);
    send_message(server->client_socket, &msg);

    // Calculer la clé de session t = t1 ^ t2
    xor_bytes(server->t, t1, t2, KEY_SIZE_BYTES);
    printf("[SERVER] M4 envoyé. Clé de session établie !\n");
    printf("Session Key (t): ");
    print_hex(server->t, 16);

    // Mise à jour dynamique du Vault [Section IV.C]
    update_secure_vault(&server->vault, server->t, KEY_SIZE_BYTES);
    save_vault(&server->vault, "common/vault.bin");
    printf("[SERVER] Vault mis à jour et sauvegardé pour la prochaine session.\n");

    printf("[SERVER] Authentification Mutuelle: SUCCÈS\n");

    close(server->client_socket);
    server->client_socket = -1;
}

void server_cleanup(IoTServer *server) {
    if (server->client_socket >= 0) {
        close(server->client_socket);
    }
    if (server->server_socket >= 0) {
        close(server->server_socket);
    }
}