#include "protocol.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/**
 * @brief Generates cryptographically secure random bytes.
 * 
 * @param buffer Pointer to the output buffer.
 * @param size Number of random bytes to generate.
 */
void generate_random_bytes(uint8_t *buffer, size_t size) {
    if (!RAND_bytes(buffer, size)) {
        fprintf(stderr, "Error during random bytes generation\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Performs a bitwise XOR between two byte arrays.
 * 
 * @param result Buffer to store the result of (a ^ b).
 * @param a First input buffer.
 * @param b Second input buffer.
 * @param size Number of bytes to process.
 */
void xor_bytes(uint8_t *result, const uint8_t *a, const uint8_t *b, size_t size) {
    for (size_t i = 0; i < size; i++) {
        result[i] = a[i] ^ b[i];
    }
}

/**
 * @brief Fills a SecureVault structure with random 128-bit keys.
 * 
 * @param vault Pointer to the SecureVault to initialize.
 */
void generate_secure_vault(SecureVault *vault) {
    for (int i = 0; i < N_KEYS; i++) {
        generate_random_bytes(vault->keys[i], KEY_SIZE_BYTES);
    }
}

/**
 * @brief Prints a byte array in hexadecimal format followed by a newline.
 * 
 * @param data Data to print.
 * @param size Size of the data.
 */
void print_hex(const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * @brief Generates a random challenge consisting of unique vault key indices and a nonce.
 * 
 * @param challenge Pointer to the Challenge structure to populate.
 */
void generate_challenge(Challenge *challenge) {
    for (int i = 0; i < P_INDICES; i++) {
        unsigned char rand_byte;
        generate_random_bytes(&rand_byte, 1);
        challenge->indices[i] = rand_byte % N_KEYS;
        // Ensure indices are unique for each challenge
        for (int j = 0; j < i; j++) {
            if (challenge->indices[i] == challenge->indices[j]) {
                i--;
                break;
            }
        }
    }
    generate_random_bytes(challenge->r, KEY_SIZE_BYTES);
}

/**
 * @brief Computes a composite key by XORing vault keys specified in a challenge.
 * 
 * @param vault Pointer to the SecureVault containing the keys.
 * @param challenge Pointer to the Challenge containing the indices.
 * @param key Pointer to the output buffer for the 128-bit derived key.
 */
void compute_vault_key(const SecureVault *vault, const Challenge *challenge, uint8_t *key) {
    memset(key, 0, KEY_SIZE_BYTES);
    for (int i = 0; i < P_INDICES; i++) {
        int idx = challenge->indices[i];
        xor_bytes(key, key, vault->keys[idx], KEY_SIZE_BYTES);
    }
}

/**
 * @brief Encrypts plaintext using AES-128-CBC. Uses a fixed zero IV for demonstration.
 * 
 * @param plaintext Data to encrypt.
 * @param plaintext_len Length of plaintext.
 * @param key 128-bit encryption key.
 * @param ciphertext Output buffer (should be large enough for padding).
 * @return int Length of ciphertext, or -1 on error.
 */
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    uint8_t iv[AES_BLOCK_SIZE] = {0}; 

    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

/**
 * @brief Decrypts ciphertext using AES-128-CBC.
 * 
 * @param ciphertext Data to decrypt.
 * @param ciphertext_len Length of ciphertext.
 * @param key 128-bit decryption key.
 * @param plaintext Output buffer.
 * @return int Length of plaintext, or -1 on error.
 */
int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *key, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    uint8_t iv[AES_BLOCK_SIZE] = {0};

    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

/**
 * @brief Computes HMAC-SHA256 for integrity and vault updates.
 * 
 * @param data Input data.
 * @param data_len Input data length.
 * @param key HMAC key.
 * @param key_len HMAC key length.
 * @param out Output buffer (32 bytes).
 */
void hmac_sha256(const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len, uint8_t *out) {
    unsigned int len;
    HMAC(EVP_sha256(), key, key_len, data, data_len, out, &len);
}

/**
 * @brief Updates the Secure Vault using the session key 't' [cite: Section IV.C].
 * Provides Forward Secrecy by rotating all vault keys.
 * 
 * @param vault Pointer to the vault to modify.
 * @param session_data The established session key 't'.
 * @param data_len Length of session data (16 bytes).
 */
void update_secure_vault(SecureVault *vault, const uint8_t *session_data, size_t data_len) {
    uint8_t h[32]; // Output of SHA-256
    
    // h = HMAC(current vault, session_key t)
    hmac_sha256((uint8_t *)vault, sizeof(SecureVault), session_data, data_len, h);

    // Update vault by partitions of 32 bytes (256 bits)
    size_t vault_size = sizeof(SecureVault);
    size_t partition_size = 32;
    size_t num_partitions = vault_size / partition_size;
    if (vault_size % partition_size != 0) num_partitions++;

    uint8_t *vault_ptr = (uint8_t *)vault;

    for (size_t i = 0; i < num_partitions; i++) {
        uint8_t h_prime[32];
        memcpy(h_prime, h, 32);
        
        // h_prime = h ^ i (XOR partition index)
        h_prime[0] ^= (uint8_t)i;

        size_t current_partition_offset = i * partition_size;
        size_t remaining = vault_size - current_partition_offset;
        size_t to_xor = (remaining < partition_size) ? remaining : partition_size;

        for (size_t j = 0; j < to_xor; j++) {
            vault_ptr[current_partition_offset + j] ^= h_prime[j];
        }
    }
}

/**
 * @brief Helper to send all bytes over a socket despite partial writes.
 */
static int send_all(int sockfd, const void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(sockfd, (const char *)buf + total, (int)(len - total), 0);
        if (sent <= 0) return -1;
        total += sent;
    }
    return 0;
}

/**
 * @brief Helper to receive all requested bytes from a socket.
 */
static int recv_all(int sockfd, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t received = recv(sockfd, (char *)buf + total, (int)(len - total), 0);
        if (received <= 0) return -1;
        total += received;
    }
    return 0;
}

/**
 * @brief Marshals and sends a Message structure over TCP.
 * 
 * @param sockfd Active socket file descriptor.
 * @param message Message to send.
 * @return int 0 on success, -1 on error.
 */
int send_message(int sockfd, const Message *message) {
    if (send_all(sockfd, &message->type, sizeof(message->type)) < 0) return -1;

    switch (message->type) {
        case MSG_M1:
            return send_all(sockfd, &message->data.m1, sizeof(MsgM1));
        case MSG_M2:
            return send_all(sockfd, &message->data.m2, sizeof(MsgM2));
        case MSG_M3:
        case MSG_M4:
        case MSG_DATA:
            if (send_all(sockfd, &message->data.encrypted.size, sizeof(size_t)) < 0) return -1;
            return send_all(sockfd, message->data.encrypted.data, message->data.encrypted.size);
        case MSG_SUCCESS:
        case MSG_FAILURE:
            return 0;
        default:
            return -1;
    }
}

/**
 * @brief Receives and unmarshals a Message structure from TCP.
 * 
 * @param sockfd Active socket file descriptor.
 * @param message Pointer to store received message.
 * @return int 0 on success, -1 on error.
 */
int receive_message(int sockfd, Message *message) {
    if (recv_all(sockfd, &message->type, sizeof(message->type)) < 0) return -1;

    switch (message->type) {
        case MSG_M1:
            return recv_all(sockfd, &message->data.m1, sizeof(MsgM1));
        case MSG_M2:
            return recv_all(sockfd, &message->data.m2, sizeof(MsgM2));
        case MSG_M3:
        case MSG_M4:
        case MSG_DATA:
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

/**
 * @brief Saves a SecureVault to disk, encrypted with the MASTER_KEY.
 * Prepend a 16-byte random IV to the file.
 * 
 * @return int 1 on success, 0 on failure.
 */
int save_vault(const SecureVault *vault, const char *filename, const uint8_t *master_key) {
    if (!master_key) return 0;

    uint8_t iv[AES_BLOCK_SIZE];
    generate_random_bytes(iv, AES_BLOCK_SIZE);

    FILE *file = fopen(filename, "wb");
    if (!file) return 0;

    // Write IV first
    fwrite(iv, 1, AES_BLOCK_SIZE, file);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, master_key, iv);

    uint8_t ciphertext[sizeof(SecureVault) + AES_BLOCK_SIZE];
    int len, ciphertext_len;

    EVP_EncryptUpdate(ctx, ciphertext, &len, (const uint8_t *)vault, sizeof(SecureVault));
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    fwrite(ciphertext, 1, (size_t)ciphertext_len, file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(file);
    return 1;
}

/**
 * @brief Loads and decrypts a SecureVault from disk using the MASTER_KEY.
 * Reads the first 16 bytes as the IV.
 * 
 * @return int 1 on success, 0 on failure.
 */
int load_vault(SecureVault *vault, const char *filename, const uint8_t *master_key) {
    if (!master_key) return 0;

    FILE *file = fopen(filename, "rb");
    if (!file) return 0;

    uint8_t iv[AES_BLOCK_SIZE];
    if (fread(iv, 1, AES_BLOCK_SIZE, file) != AES_BLOCK_SIZE) {
        fclose(file);
        return 0;
    }

    uint8_t ciphertext[sizeof(SecureVault) + AES_BLOCK_SIZE * 2];
    size_t ciphertext_len = fread(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, master_key, iv);

    uint8_t plaintext[sizeof(SecureVault) + AES_BLOCK_SIZE * 2];
    int len, plaintext_len;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    if (plaintext_len >= (int)sizeof(SecureVault)) {
        memcpy(vault, plaintext, sizeof(SecureVault));
    } else {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}