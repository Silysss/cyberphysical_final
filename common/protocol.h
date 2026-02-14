#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// Paramètres du papier [cite: 117, 130]
#define N_KEYS 4          // Nombre de clés dans le vault (n)
#define KEY_SIZE_BITS 128 // Taille des clés en bits (m)
#define KEY_SIZE_BYTES (KEY_SIZE_BITS / 8)
#define P_INDICES 2 // Nombre d'indices par défi (p < n)

// Types de messages
#define MSG_CHALLENGE 1
#define MSG_RESPONSE 2
#define MSG_SUCCESS 3
#define MSG_FAILURE 4

// Structure pour représenter un vault de clés
typedef struct {
    uint8_t keys[N_KEYS][KEY_SIZE_BYTES];
} SecureVault;

// Structure pour représenter un défi
typedef struct {
    int indices[P_INDICES];
    uint8_t nonce[KEY_SIZE_BYTES];
} Challenge;

// Structure pour représenter une réponse
typedef struct {
    uint8_t response[KEY_SIZE_BYTES];
} Response;

// Structure pour représenter un message
typedef struct {
    int type;
    union {
        Challenge challenge;
        Response response;
    } data;
} Message;

// Fonctions de base
void generate_random_bytes(uint8_t *buffer, size_t size);
void xor_bytes(uint8_t *result, const uint8_t *a, const uint8_t *b, size_t size);
void generate_secure_vault(SecureVault *vault);
void print_hex(const uint8_t *data, size_t size);

// Fonctions de gestion du vault et du protocole
void generate_challenge(Challenge *challenge);
void compute_response(const SecureVault *vault, const Challenge *challenge, Response *response);
int verify_response(const SecureVault *vault, const Challenge *challenge, const Response *response);

// Fonctions de communication réseau
int send_message(int sockfd, const Message *message);
int receive_message(int sockfd, Message *message);

// Fonctions de gestion de fichier pour le vault
int save_vault(const SecureVault *vault, const char *filename);
int load_vault(SecureVault *vault, const char *filename);

// Désactive le buffering de printf pour Docker logs
#define LOG_INIT() setvbuf(stdout, NULL, _IONBF, 0);

#endif
