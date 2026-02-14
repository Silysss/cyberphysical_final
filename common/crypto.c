#include "protocol.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
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

void generate_challenge(Challenge *challenge) {
    for (int i = 0; i < P_INDICES; i++) {
        unsigned char rand_byte;
        generate_random_bytes(&rand_byte, 1);
        challenge->indices[i] = rand_byte % N_KEYS;
        for (int j = 0; j < i; j++) {
            if (challenge->indices[i] == challenge->indices[j]) {
                i--;
                break;
            }
        }
    }
    generate_random_bytes(challenge->nonce, KEY_SIZE_BYTES);
}

// Calcule la clé k = XOR(K[c1], K[c2], ...)
void compute_vault_key(const SecureVault *vault, const Challenge *challenge, uint8_t *key) {
    memset(key, 0, KEY_SIZE_BYTES);
    for (int i = 0; i < P_INDICES; i++) {
        int idx = challenge->indices[i];
        xor_bytes(key, key, vault->keys[idx], KEY_SIZE_BYTES);
    }
}

// Chiffrement AES-128-CBC
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    uint8_t iv[AES_BLOCK_SIZE] = {0}; // IV fixe pour l'exemple, à améliorer avec un nonce

    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) return -1;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) return -1;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) return -1;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Déchiffrement AES-128-CBC
int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    uint8_t iv[AES_BLOCK_SIZE] = {0};

    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) return -1;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) return -1;
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) return -1;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

static int send_all(int sockfd, const void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(sockfd, (const char *)buf + total, len - total, 0);
        if (sent <= 0) return -1;
        total += sent;
    }
    return 0;
}

static int recv_all(int sockfd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t received = recv(sockfd, (char *)buf + total, len - total, 0);
        if (received <= 0) return -1;
        total += received;
    }
    return 0;
}

int send_message(int sockfd, const Message *message) {
    if (send_all(sockfd, &message->type, sizeof(message->type)) < 0) return -1;

    switch (message->type) {
        case MSG_M1:
            return send_all(sockfd, &message->data.m1, sizeof(MsgM1));
        case MSG_M2:
            return send_all(sockfd, &message->data.m2, sizeof(MsgM2));
        case MSG_M3:
        case MSG_M4:
            if (send_all(sockfd, &message->data.encrypted.size, sizeof(size_t)) < 0) return -1;
            return send_all(sockfd, message->data.encrypted.data, message->data.encrypted.size);
        case MSG_SUCCESS:
        case MSG_FAILURE:
            return 0;
        default:
            return -1;
    }
}

int receive_message(int sockfd, Message *message) {
    if (recv_all(sockfd, &message->type, sizeof(message->type)) < 0) return -1;

    switch (message->type) {
        case MSG_M1:
            return recv_all(sockfd, &message->data.m1, sizeof(MsgM1));
        case MSG_M2:
            return recv_all(sockfd, &message->data.m2, sizeof(MsgM2));
        case MSG_M3:
        case MSG_M4:
            if (recv_all(sockfd, &message->data.encrypted.size, sizeof(size_t)) < 0) return -1;
            if (message->data.encrypted.size > MAX_ENC_SIZE) return -1;
            return recv_all(sockfd, message->data.encrypted.data, message->data.encrypted.size);
        case MSG_SUCCESS:
        case MSG_FAILURE:
            return 0;
        default:
            return -1;
    }
}

int save_vault(const SecureVault *vault, const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) return 0;
    size_t written = fwrite(vault, sizeof(SecureVault), 1, file);
    fclose(file);
    return written == 1;
}

int load_vault(SecureVault *vault, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return 0;
    size_t read = fread(vault, sizeof(SecureVault), 1, file);
    fclose(file);
    return read == 1;
}