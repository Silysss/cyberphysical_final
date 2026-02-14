#include "iot_client.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

void client_init(IoTClient *client, const char *server_ip, int port) {
    // Charger le vault partagé
    if (!load_vault(&client->vault, "common/vault.bin")) {
        fprintf(stderr, "Erreur: Impossible de charger le vault\n");
        exit(EXIT_FAILURE);
    }

    // Configurer l'adresse du serveur
    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_port = htons(port);
    
    // Définir un ID de device par défaut (pourrait venir d'un fichier ou env)
    strncpy(client->device_id, "IOT-DEVICE-001", sizeof(client->device_id));

    // Essayer d'abord de parser comme une adresse IP
    if (inet_pton(AF_INET, server_ip, &client->server_addr.sin_addr) <= 0) {
        // Sinon, résoudre comme un nom d'hôte
        struct hostent *host = gethostbyname(server_ip);
        if (host == NULL) {
            fprintf(stderr, "Impossible de résoudre le nom d'hôte: %s\n", server_ip);
            exit(EXIT_FAILURE);
        }
        memcpy(&client->server_addr.sin_addr, host->h_addr, host->h_length);
    }

    client->server_socket = -1;
}

int client_connect(IoTClient *client) {
    client->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client->server_socket < 0) return -1;
    
    if (connect(client->server_socket, (struct sockaddr *)&client->server_addr, 
                sizeof(client->server_addr)) < 0) {
        perror("Échec de la connexion");
        return -1;
    }
    return 0;
}

int client_authenticate(IoTClient *client) {
    Message msg;

    // 1. Envoyer M1 {device_id, session_id}
    msg.type = MSG_M1;
    strncpy(msg.data.m1.device_id, client->device_id, sizeof(msg.data.m1.device_id));
    msg.data.m1.session_id = (uint32_t)time(NULL);
    if (send_message(client->server_socket, &msg) < 0) return -1;
    printf("[CLIENT] M1 envoyé: ID=%s\n", client->device_id);

    // 2. Recevoir M2 {C1, r1}
    if (receive_message(client->server_socket, &msg) < 0 || msg.type != MSG_M2) return -1;
    Challenge c1 = msg.data.m2.challenge;
    printf("[CLIENT] M2 reçu (C1 indices: %d,%d)\n", c1.indices[0], c1.indices[1]);

    // 3. Préparer M3 {Enc(k1, r1 || C2 || r2)}
    uint8_t k1[KEY_SIZE_BYTES];
    compute_vault_key(&client->vault, &c1, k1);

    Challenge c2;
    generate_challenge(&c2); // Contient r2 dans c2.nonce

    // Données à chiffrer : r1 (16 bytes) + C2 indices (2*4 bytes) + r2 (16 bytes) = 40 bytes
    uint8_t plaintext[40];
    memcpy(plaintext, c1.nonce, 16);
    memcpy(plaintext + 16, c2.indices, 8);
    memcpy(plaintext + 24, c2.nonce, 16);

    msg.type = MSG_M3;
    msg.data.encrypted.size = aes_encrypt(plaintext, 40, k1, msg.data.encrypted.data);
    if (send_message(client->server_socket, &msg) < 0) return -1;
    printf("[CLIENT] M3 envoyé (réponse chiffrée + challenge C2)\n");

    // 4. Recevoir M4 {Enc(k2, r2)}
    if (receive_message(client->server_socket, &msg) < 0 || msg.type != MSG_M4) return -1;
    
    uint8_t k2[KEY_SIZE_BYTES];
    compute_vault_key(&client->vault, &c2, k2);

    uint8_t decrypted_r2[KEY_SIZE_BYTES + 32];
    int dec_len = aes_decrypt(msg.data.encrypted.data, msg.data.encrypted.size, k2, decrypted_r2);
    
    if (dec_len < (int)KEY_SIZE_BYTES || memcmp(decrypted_r2, c2.nonce, KEY_SIZE_BYTES) != 0) {
        fprintf(stderr, "[CLIENT] Échec de l'authentification du serveur !\n");
        return -1;
    }

    printf("[CLIENT] M4 reçu et validé. Serveur authentifié !\n");
    printf("Authentification Mutuelle: SUCCÈS\n");
    return 0;
}

void client_cleanup(IoTClient *client) {
    if (client->server_socket >= 0) {
        close(client->server_socket);
    }
}