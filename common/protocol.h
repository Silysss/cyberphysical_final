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
#define AES_BLOCK_SIZE 16

// Types de messages pour le 3-way handshake
#define MSG_M1 10 // Init: {device_id, session_id}
#define MSG_M2 11 // Server Challenge: {C1, r1}
#define MSG_M3 12 // Client Response + Challenge: {Enc(k1, r1 || C2 || r2)}
#define MSG_M4 13 // Server Response: {Enc(k2, r2)}

#define MSG_SUCCESS 3
#define MSG_FAILURE 4

// Structure pour représenter un vault de clés
typedef struct {
    uint8_t keys[N_KEYS][KEY_SIZE_BYTES];
} SecureVault;

// Structure pour représenter un défi
typedef struct {
    int indices[P_INDICES];
    uint8_t r[KEY_SIZE_BYTES]; // r1 ou r2
} Challenge;

// Structures pour les messages du handshake
typedef struct {
    char device_id[32];
    uint32_t session_id;
} MsgM1;

typedef struct {
    Challenge challenge;
} MsgM2;

// Taille maximale pour les données chiffrées (r1(16) + C2(2*4) + r2(16) = 40, arrondi au bloc AES supérieur = 48)
#define MAX_ENC_SIZE 64

typedef struct {
    uint8_t data[MAX_ENC_SIZE];
    size_t size;
} MsgEncrypted;

// Structure pour représenter un message générique
typedef struct {
    int type;
    union {
        MsgM1 m1;
        MsgM2 m2;
        MsgEncrypted encrypted; // Pour M3 et M4
    } data;
} Message;

// Fonctions de base
void generate_random_bytes(uint8_t *buffer, size_t size);
void xor_bytes(uint8_t *result, const uint8_t *a, const uint8_t *b, size_t size);
void generate_secure_vault(SecureVault *vault);
void print_hex(const uint8_t *data, size_t size);

// Fonctions de gestion du vault et du protocole
void generate_challenge(Challenge *challenge);
void compute_vault_key(const SecureVault *vault, const Challenge *challenge, uint8_t *key);
void update_secure_vault(SecureVault *vault, const uint8_t *session_data, size_t data_len);

// Chiffrement AES avec les clés du vault
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext);

// HMAC SHA-256
void hmac_sha256(const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len, uint8_t *out);

// Fonctions de communication réseau
int send_message(int sockfd, const Message *message);
int receive_message(int sockfd, Message *message);

// Fonctions de gestion de fichier pour le vault
int save_vault(const SecureVault *vault, const char *filename);
int load_vault(SecureVault *vault, const char *filename);

// Désactive le buffering de printf pour Docker logs
#define LOG_INIT() setvbuf(stdout, NULL, _IONBF, 0);

#endif
