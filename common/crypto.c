#include "protocol.h"
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

void generate_random_bytes(uint8_t *buffer, size_t size) {
    if (!RAND_bytes(buffer, size)) {
        fprintf(stderr, "Erreur lors de la génération de nombres aléatoires\n");
        exit(EXIT_FAILURE);
    }
}

void xor_bytes(uint8_t *result, const uint8_t *a, const uint8_t *b, size_t size) {
    for (size_t i = 0; i < size; i++) {
        result[i] = a[i] ^ b[i];
    }
}

void generate_secure_vault(SecureVault *vault) {
    for (int i = 0; i < N_KEYS; i++) {
        generate_random_bytes(vault->keys[i], KEY_SIZE_BYTES);
    }
}

void print_hex(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Génère un défi aléatoire
void generate_challenge(Challenge *challenge) {
    // Générer des indices aléatoires uniques avec RAND_bytes
    for (int i = 0; i < P_INDICES; i++) {
        unsigned char rand_byte;
        if (!RAND_bytes(&rand_byte, 1)) {
            fprintf(stderr, "Erreur lors de la génération de l'indice aléatoire\n");
            exit(EXIT_FAILURE);
        }
        challenge->indices[i] = rand_byte % N_KEYS;
        // Vérifier les doublons
        for (int j = 0; j < i; j++) {
            if (challenge->indices[i] == challenge->indices[j]) {
                i--; // Recommencer si doublon
                break;
            }
        }
    }
    // Générer un nonce aléatoire
    generate_random_bytes(challenge->nonce, KEY_SIZE_BYTES);
}

// Calcule la réponse à un défi
void compute_response(const SecureVault *vault, const Challenge *challenge, Response *response) {
    uint8_t temp_result[KEY_SIZE_BYTES] = {0};
    
    // XOR des clés spécifiées dans le défi
    for (int i = 0; i < P_INDICES; i++) {
        int key_index = challenge->indices[i];
        xor_bytes(temp_result, temp_result, vault->keys[key_index], KEY_SIZE_BYTES);
    }
    
    // XOR avec le nonce
    xor_bytes(response->response, temp_result, challenge->nonce, KEY_SIZE_BYTES);
}

// Vérifie une réponse à un défi
int verify_response(const SecureVault *vault, const Challenge *challenge, const Response *response) {
    Response expected_response;
    compute_response(vault, challenge, &expected_response);
    
    // Comparer les réponses
    return memcmp(expected_response.response, response->response, KEY_SIZE_BYTES) == 0;
}

// Sauvegarde un vault dans un fichier
int save_vault(const SecureVault *vault, const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        return 0; // Retourne 0 en cas d'échec
    }
    size_t written = fwrite(vault, sizeof(SecureVault), 1, file);
    fclose(file);
    return written == 1; // Retourne 1 en cas de succès
}

// Charge un vault depuis un fichier
int load_vault(SecureVault *vault, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return 0; // Retourne 0 en cas d'échec
    }
    size_t read = fread(vault, sizeof(SecureVault), 1, file);
    fclose(file);
    return read == 1; // Retourne 1 en cas de succès
}

// Helper: send all bytes reliably
static int send_all(int sockfd, const void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(sockfd, (const char *)buf + total, len - total, 0);
        if (sent <= 0) {
            perror("Erreur lors de l'envoi");
            return -1;
        }
        total += sent;
    }
    return 0;
}

// Helper: receive all bytes reliably
static int recv_all(int sockfd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t received = recv(sockfd, (char *)buf + total, len - total, 0);
        if (received <= 0) {
            if (received == 0) {
                fprintf(stderr, "Connexion fermée par le pair\n");
            } else {
                perror("Erreur lors de la réception");
            }
            return -1;
        }
        total += received;
    }
    return 0;
}

// Envoie un message via socket
int send_message(int sockfd, const Message *message) {
    // Envoyer le type de message d'abord
    if (send_all(sockfd, &message->type, sizeof(message->type)) < 0) {
        return -1;
    }

    // Envoyer les données en fonction du type
    switch (message->type) {
        case MSG_CHALLENGE: {
            Challenge *challenge = (Challenge *)&message->data.challenge;
            if (send_all(sockfd, challenge->indices, sizeof(challenge->indices)) < 0 ||
                send_all(sockfd, challenge->nonce, sizeof(challenge->nonce)) < 0) {
                return -1;
            }
            break;
        }
        case MSG_RESPONSE: {
            Response *response = (Response *)&message->data.response;
            if (send_all(sockfd, response->response, sizeof(response->response)) < 0) {
                return -1;
            }
            break;
        }
        case MSG_SUCCESS:
        case MSG_FAILURE:
            // Pas de données supplémentaires
            break;
        default:
            fprintf(stderr, "Type de message inconnu: %d\n", message->type);
            return -1;
    }

    return 0;
}

// Reçoit un message via socket
int receive_message(int sockfd, Message *message) {
    // Recevoir le type de message d'abord
    if (recv_all(sockfd, &message->type, sizeof(message->type)) < 0) {
        return -1;
    }

    // Recevoir les données en fonction du type
    switch (message->type) {
        case MSG_CHALLENGE: {
            Challenge *challenge = (Challenge *)&message->data.challenge;
            if (recv_all(sockfd, challenge->indices, sizeof(challenge->indices)) < 0 ||
                recv_all(sockfd, challenge->nonce, sizeof(challenge->nonce)) < 0) {
                return -1;
            }
            break;
        }
        case MSG_RESPONSE: {
            Response *response = (Response *)&message->data.response;
            if (recv_all(sockfd, response->response, sizeof(response->response)) < 0) {
                return -1;
            }
            break;
        }
        case MSG_SUCCESS:
        case MSG_FAILURE:
            // Pas de données supplémentaires
            break;
        default:
            fprintf(stderr, "Type de message inconnu: %d\n", message->type);
            return -1;
    }

    return 0;
}