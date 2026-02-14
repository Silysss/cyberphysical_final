#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/**
 * @file protocol.h
 * @brief Global protocol definitions, constants, and cryptographic structures.
 * 
 * Based on the paper: "Authentication of IoT Device and IoT Server Using Secure Vaults".
 */

// Protocol Parameters [Shah & Venkatesan]
#define N_KEYS 4          ///< Number of keys in the vault (n)
#define KEY_SIZE_BITS 128 ///< Size of each key in bits (m)
#define KEY_SIZE_BYTES (KEY_SIZE_BITS / 8)
#define P_INDICES 2       ///< Number of indices per challenge (p < n)
#define AES_BLOCK_SIZE 16 ///< Standard AES block size

// 3-Way Handshake Message Types
#define MSG_M1 10      ///< Initiation: {device_id, session_id}
#define MSG_M2 11      ///< Server Challenge: {C1, r1}
#define MSG_M3 12      ///< Client Response + Challenge: {Enc(k1, r1 || t1 || C2 || r2)}
#define MSG_M4 13      ///< Server Response: {Enc(k2 ^ t1, r2 || t2)}

#define MSG_SUCCESS 3
#define MSG_FAILURE 4
#define MSG_DATA 20    ///< Post-authentication secure data packet

#define SECURE_MESSAGE_L 64 ///< Fixed length for secure data strings

/**
 * @struct SecureVault
 * @brief Container for the shared secret keys.
 */
typedef struct {
    uint8_t keys[N_KEYS][KEY_SIZE_BYTES];
} SecureVault;

/**
 * @struct Challenge
 * @brief Challenge payload containing vault indices and a unique nonce.
 */
typedef struct {
    int indices[P_INDICES];
    uint8_t r[KEY_SIZE_BYTES]; ///< Nonce (r1 or r2)
} Challenge;

/**
 * @struct MsgM1
 * @brief M1 initiation data.
 */
typedef struct {
    char device_id[32];
    uint32_t session_id;
} MsgM1;

/**
 * @struct MsgM2
 * @brief M2 server challenge data.
 */
typedef struct {
    Challenge challenge;
} MsgM2;

#define MAX_ENC_SIZE 128 ///< Maximum size for encrypted payloads (includes padding)

/**
 * @struct MsgEncrypted
 * @brief Generic container for encrypted message payloads (M3, M4, DATA).
 */
typedef struct {
    uint8_t data[MAX_ENC_SIZE];
    size_t size;
} MsgEncrypted;

/**
 * @struct Message
 * @brief Universal message structure for network communication.
 */
typedef struct {
    int type;
    union {
        MsgM1 m1;
        MsgM2 m2;
        MsgEncrypted encrypted; // Used for M3, M4, and DATA
    } data;
} Message;

// --- Core Helper Functions ---
void generate_random_bytes(uint8_t *buffer, size_t size);
void xor_bytes(uint8_t *result, const uint8_t *a, const uint8_t *b, size_t size);
void generate_secure_vault(SecureVault *vault);
void print_hex(const uint8_t *data, size_t size);

// --- Protocol & Vault Management ---
void generate_challenge(Challenge *challenge);
void compute_vault_key(const SecureVault *vault, const Challenge *challenge, uint8_t *key);
void update_secure_vault(SecureVault *vault, const uint8_t *session_data, size_t data_len);

// --- Cryptographic Primitives (AES & HMAC) ---
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext);
int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext);
void hmac_sha256(const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len, uint8_t *out);

// --- Network Communication ---
int send_message(int sockfd, const Message *message);
int receive_message(int sockfd, Message *message);

// --- At-Rest Protection (Encrypted Vault Files) ---
int save_vault(const SecureVault *vault, const char *filename, const uint8_t *master_key);
int load_vault(SecureVault *vault, const char *filename, const uint8_t *master_key);

/**
 * @brief Utility to disable buffering on stdout for real-time Docker logs.
 */
#define LOG_INIT() setvbuf(stdout, NULL, _IONBF, 0);

#endif
