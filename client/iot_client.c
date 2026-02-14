#include "iot_client.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

/**
 * @brief Initializes the IoT client.
 * Loads the encrypted vault from disk, resolves the server address,
 * and sets the default device ID.
 * 
 * @param client Pointer to the IoTClient context.
 * @param server_ip IP address or hostname of the server.
 * @param port TCP port of the server.
 */
void client_init(IoTClient *client, const char *server_ip, int port) {
    const char *vault_path = getenv("VAULT_PATH");
    if (!vault_path) vault_path = "client/vault.bin";

    // 1. Retrieve the MASTER_KEY for decrypting the vault at rest
    const char *master_key_str = getenv("MASTER_KEY");
    if (!master_key_str || strlen(master_key_str) < 16) {
        fprintf(stderr, "Error: MASTER_KEY not configured or too short (min 16 bytes)\n");
        exit(EXIT_FAILURE);
    }

    // 2. Load the encrypted vault from the file system
    if (!load_vault(&client->vault, vault_path, (const uint8_t *)master_key_str)) {
        fprintf(stderr, "\n❌ CRITICAL ERROR: Could not load the vault from '%s'.\n", vault_path);
        fprintf(stderr, "   Ensure the MASTER_KEY is correct and run 'make generate-vault' if needed.\n\n");
        exit(EXIT_FAILURE);
    }

    // 3. Configure server address
    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_port = htons(port);
    
    // Set default device identity
    strncpy(client->device_id, "IOT-DEVICE-001", sizeof(client->device_id));

    // Try to parse as IP address, then resolve as hostname
    if (inet_pton(AF_INET, server_ip, &client->server_addr.sin_addr) <= 0) {
        struct hostent *host = gethostbyname(server_ip);
        if (host == NULL) {
            fprintf(stderr, "Could not resolve hostname: %s\n", server_ip);
            exit(EXIT_FAILURE);
        }
        memcpy(&client->server_addr.sin_addr, host->h_addr, host->h_length);
    }

    client->server_socket = -1;
}

/**
 * @brief Establishes a TCP connection to the IoT Server.
 * 
 * @param client Pointer to the IoTClient context.
 * @return int 0 on success, -1 on failure.
 */
int client_connect(IoTClient *client) {
    client->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client->server_socket < 0) return -1;
    
    if (connect(client->server_socket, (struct sockaddr *)&client->server_addr, 
                sizeof(client->server_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }
    return 0;
}

/**
 * @brief Executes the full 3-way handshake for mutual authentication.
 * Follows the M1-M4 message sequence to establish session key 't'.
 * 
 * @param client Pointer to the IoTClient context.
 * @return int 0 on success, -1 on failure.
 */
int client_authenticate(IoTClient *client) {
    Message msg;

    // 1. Send M1: Initiation message {device_id, session_id}
    msg.type = MSG_M1;
    strncpy(msg.data.m1.device_id, client->device_id, sizeof(msg.data.m1.device_id));
    msg.data.m1.session_id = (uint32_t)time(NULL);
    if (send_message(client->server_socket, &msg) < 0) return -1;
    printf("[CLIENT] M1 sent: ID=%s\n", client->device_id);

    // 2. Receive M2: Server Challenge {C1, r1}
    if (receive_message(client->server_socket, &msg) < 0 || msg.type != MSG_M2) return -1;
    Challenge c1 = msg.data.m2.challenge;
    printf("[CLIENT] M2 received (C1 indices: %d,%d)\n", c1.indices[0], c1.indices[1]);

    // 3. Prepare M3: Response to C1 and client's own challenge C2
    uint8_t k1[KEY_SIZE_BYTES];
    compute_vault_key(&client->vault, &c1, k1);

    uint8_t t1[KEY_SIZE_BYTES];
    generate_random_bytes(t1, KEY_SIZE_BYTES);

    Challenge c2;
    generate_challenge(&c2); // Generates indices and nonce r2

    // Payload: r1(16) + t1(16) + C2_indices(8) + r2(16) = 56 bytes
    uint8_t plaintext_m3[56];
    memcpy(plaintext_m3, c1.r, 16);
    memcpy(plaintext_m3 + 16, t1, 16);
    memcpy(plaintext_m3 + 32, c2.indices, 8);
    memcpy(plaintext_m3 + 40, c2.r, 16);

    msg.type = MSG_M3;
    msg.data.encrypted.size = aes_encrypt(plaintext_m3, 56, k1, msg.data.encrypted.data);
    if (send_message(client->server_socket, &msg) < 0) return -1;
    printf("[CLIENT] M3 sent (response + challenge C2 + t1)\n");

    // 4. Receive M4: Final Server Response {Enc(k2 ^ t1, r2 || t2)}
    if (receive_message(client->server_socket, &msg) < 0 || msg.type != MSG_M4) return -1;
    
    uint8_t k2[KEY_SIZE_BYTES];
    compute_vault_key(&client->vault, &c2, k2);

    // M4 specific encryption key derived from client's challenge and part of session key
    uint8_t k_m4[KEY_SIZE_BYTES];
    xor_bytes(k_m4, k2, t1, KEY_SIZE_BYTES);

    uint8_t decrypted_m4[64];
    int dec_len = aes_decrypt(msg.data.encrypted.data, msg.data.encrypted.size, k_m4, decrypted_m4);
    
    // Validate server identity by checking nonce r2
    if (dec_len < 32 || memcmp(decrypted_m4, c2.r, KEY_SIZE_BYTES) != 0) {
        fprintf(stderr, "[CLIENT] Server failed authentication or invalid r2!\n");
        return -1;
    }

    uint8_t t2[KEY_SIZE_BYTES];
    memcpy(t2, decrypted_m4 + 16, 16);

    // Final session key computation: t = t1 ^ t2
    xor_bytes(client->t, t1, t2, KEY_SIZE_BYTES);

    printf("[CLIENT] M4 received and validated. Session key established!\n");
    printf("Session Key (t): ");
    print_hex(client->t, 16);

    // Support for Forward Secrecy: Rotate vault keys using 't'
    update_secure_vault(&client->vault, client->t, KEY_SIZE_BYTES);
    
    const char *vault_path = getenv("VAULT_PATH");
    if (!vault_path) vault_path = "client/vault.bin";
    
    const char *master_key_str = getenv("MASTER_KEY");
    
    // Save the rotated vault back to disk (encrypted at rest)
    save_vault(&client->vault, vault_path, (const uint8_t *)master_key_str);
    printf("[CLIENT] Vault updated and saved to %s\n", vault_path);

    printf("Mutual Authentication: SUCCESS\n");
    fflush(stdout);
    return 0;
}

/**
 * @brief Sends encrypted application data to the server using the session key.
 * 
 * @param client Pointer to the IoTClient context.
 * @param data String of data to send.
 * @return int 0 on success, -1 on failure.
 */
int client_send_data(IoTClient *client, const char *data) {
    Message msg;
    char secret_data[SECURE_MESSAGE_L];
    memset(secret_data, 0, SECURE_MESSAGE_L);
    strncpy(secret_data, data, SECURE_MESSAGE_L - 1);
    
    msg.type = MSG_DATA;
    msg.data.encrypted.size = aes_encrypt((uint8_t *)secret_data, SECURE_MESSAGE_L, client->t, msg.data.encrypted.data);
    
    printf("[CLIENT] Attempting to send secure data...\n");
    fflush(stdout);
    if (send_message(client->server_socket, &msg) < 0) {
        fprintf(stderr, "[CLIENT] Failed to send secure data.\n");
        return -1;
    }
    printf("[CLIENT] Secure data sent: \"%s\"\n", data);
    fflush(stdout);
    return 0;
}

/**
 * @brief Closes the server socket.
 */
void client_cleanup(IoTClient *client) {
    if (client->server_socket >= 0) {
        close(client->server_socket);
    }
}