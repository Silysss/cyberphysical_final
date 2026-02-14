#include "iot_server.h"
#include <unistd.h>
#include <signal.h>

/**
 * @file iot_server.c
 * @brief Implementation of the IoT Server logic including handshake and data reception.
 */

// Global flag to control the main server loop execution.
volatile sig_atomic_t running = 1;

/**
 * @brief Signal handler to gracefully shutdown the server.
 * 
 * @param sig Signal number (e.g., SIGINT, SIGTERM).
 */
void handle_signal(int sig) {
    (void)sig; // Avoid unused parameter warning
    running = 0;
}

/**
 * @brief Initializes the IoT server context.
 * Sets up server address and loads the encrypted vault from disk.
 * 
 * @param server Pointer to the IoTServer instance.
 * @param port Port number to listen on.
 */
void server_init(IoTServer *server, int port) {
    const char *vault_path = getenv("VAULT_PATH");
    if (!vault_path) vault_path = "server/vault.bin";

    // 1. Retrieve the MASTER_KEY used for decrypting the vault at rest.
    const char *master_key_str = getenv("MASTER_KEY");
    if (!master_key_str || strlen(master_key_str) < 16) {
        fprintf(stderr, "Error: MASTER_KEY not configured or too short (min 16 bytes)\n");
        exit(EXIT_FAILURE);
    }

    // 2. Load the encrypted vault from the file system.
    if (!load_vault(&server->vault, vault_path, (const uint8_t *)master_key_str)) {
        fprintf(stderr, "\n❌ CRITICAL ERROR: Could not load the vault from '%s'.\n", vault_path);
        fprintf(stderr, "   Check that the MASTER_KEY is correct and the vault file exists.\n\n");
        exit(EXIT_FAILURE);
    }
    
    // 3. Configure the listening address.
    server->address.sin_family = AF_INET;
    server->address.sin_addr.s_addr = INADDR_ANY;
    server->address.sin_port = htons(port);
    
    server->server_socket = -1;
    server->client_socket = -1;
}

/**
 * @brief Starts the TCP server by creating a socket, binding, and listening.
 * 
 * @param server Pointer to the IoTServer instance.
 * @return int 0 on success, -1 on failure.
 */
int server_start(IoTServer *server) {
    int opt = 1;
    
    // Create the TCP socket
    server->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_socket == 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Enable SO_REUSEADDR and SO_REUSEPORT for faster restarts
    if (setsockopt(server->server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                   &opt, sizeof(opt))) {
        perror("Failed to set socket options");
        return -1;
    }
    
    // Bind socket to the specified port
    if (bind(server->server_socket, (struct sockaddr *)&server->address, 
             sizeof(server->address)) < 0) {
        perror("Bind failed");
        return -1;
    }
    
    // Listen for incoming client connections (backlog of 5)
    if (listen(server->server_socket, 5) < 0) {
        perror("Listen failed");
        return -1;
    }
    
    printf("Server listening on port %d...\n", ntohs(server->address.sin_port));
    
    // Register signal handlers for clean exit
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    return 0;
}

/**
 * @brief High-level handler for a single client connection.
 * Executes Phase 1 (handshake) and Phase 2 (secure communication).
 * 
 * @param server Pointer to the IoTServer instance.
 */
void server_handle_client(IoTServer *server) {
    socklen_t addrlen = sizeof(server->address);
    server->client_socket = accept(server->server_socket, (struct sockaddr *)&server->address, &addrlen);
    if (server->client_socket < 0) return;

    printf("[SERVER] Client connected from %s\n", inet_ntoa(server->address.sin_addr));

    // Phase 1: Handshake Authentication
    if (server_authenticate(server) == 0) {
        printf("[SERVER] Authentication successful. Waiting for data...\n");
        fflush(stdout);
        
        // Phase 2: Post-authentication Secure Data Reception
        server_receive_data(server);
    } else {
        printf("[SERVER] Authentication failed.\n");
    }

    // Terminate connection
    close(server->client_socket);
    server->client_socket = -1;
}

/**
 * @brief Implements the server-side logic of the 3-way mutual authentication handshake.
 * 
 * @param server Pointer to the IoTServer instance.
 * @return int 0 on success, -1 on error.
 */
int server_authenticate(IoTServer *server) {
    Message msg;

    // 1. Receive M1 from Client: {device_id, session_id}
    if (receive_message(server->client_socket, &msg) < 0 || msg.type != MSG_M1) {
        return -1;
    }
    printf("[SERVER] M1 received: Device=%s, Session=%u\n", msg.data.m1.device_id, msg.data.m1.session_id);

    // 2. Send M2 to Client: Challenge C1 and nonce r1
    Challenge c1;
    generate_challenge(&c1);
    msg.type = MSG_M2;
    msg.data.m2.challenge = c1;
    if (send_message(server->client_socket, &msg) < 0) {
        return -1;
    }
    printf("[SERVER] M2 sent (Challenge C1)\n");

    // 3. Receive M3 from Client: {Enc(k1, r1 || t1 || C2 || r2)}
    if (receive_message(server->client_socket, &msg) < 0 || msg.type != MSG_M3) {
        return -1;
    }

    uint8_t k1[KEY_SIZE_BYTES];
    compute_vault_key(&server->vault, &c1, k1);

    uint8_t decrypted[MAX_ENC_SIZE];
    int dec_len = aes_decrypt(msg.data.encrypted.data, msg.data.encrypted.size, k1, decrypted);
    
    // Validate client identity by checking nonce r1 (M3 payload: r1:16, t1:16, C2_indices:8, r2:16)
    if (dec_len < 56 || memcmp(decrypted, c1.r, KEY_SIZE_BYTES) != 0) {
        printf("[SERVER] Client authentication failed (invalid response or r1 mismatch)\n");
        msg.type = MSG_FAILURE;
        send_message(server->client_socket, &msg);
        return -1;
    }

    uint8_t t1[KEY_SIZE_BYTES];
    memcpy(t1, decrypted + 16, 16);

    Challenge c2;
    memcpy(c2.indices, decrypted + 32, 8);
    memcpy(c2.r, decrypted + 40, 16);
    printf("[SERVER] M3 validated. t1 received and Client authenticated! C2 received.\n");

    // 4. Send M4 to Client: Final Response {Enc(k2 ^ t1, r2 || t2)}
    uint8_t k2[KEY_SIZE_BYTES];
    compute_vault_key(&server->vault, &c2, k2);

    uint8_t t2[KEY_SIZE_BYTES];
    generate_random_bytes(t2, KEY_SIZE_BYTES);

    // Final message encryption key is randomized using part of the session key
    uint8_t k_m4[KEY_SIZE_BYTES];
    xor_bytes(k_m4, k2, t1, KEY_SIZE_BYTES);

    // M4 payload: r2 (16 bytes) + t2 (16 bytes) = 32 bytes
    uint8_t plaintext_m4[32];
    memcpy(plaintext_m4, c2.r, 16);
    memcpy(plaintext_m4 + 16, t2, 16);

    msg.type = MSG_M4;
    msg.data.encrypted.size = aes_encrypt(plaintext_m4, 32, k_m4, msg.data.encrypted.data);
    send_message(server->client_socket, &msg);

    // Compute shared session key: t = t1 ^ t2
    xor_bytes(server->t, t1, t2, KEY_SIZE_BYTES);
    printf("[SERVER] M4 sent. Session key established!\n");
    printf("Session Key (t): ");
    print_hex(server->t, 16);

    // Forward Secrecy: Dynamic Rotation of the Vault keys using session key 't'
    update_secure_vault(&server->vault, server->t, KEY_SIZE_BYTES);
    
    const char *vault_path = getenv("VAULT_PATH");
    if (!vault_path) vault_path = "server/vault.bin";

    // Persist the updated vault to disk (encrypted at rest)
    save_vault(&server->vault, vault_path, (const uint8_t *)getenv("MASTER_KEY"));
    printf("[SERVER] Vault updated and saved to %s\n", vault_path);

    printf("[SERVER] Mutual Authentication: SUCCESS\n");
    fflush(stdout);
    return 0;
}

/**
 * @brief Receives and decrypts a single data message from the client using established session key 't'.
 * 
 * @param server Pointer to the IoTServer instance.
 * @return int 0 on success, -1 on error.
 */
int server_receive_data(IoTServer *server) {
    Message msg;
    if (receive_message(server->client_socket, &msg) == 0 && msg.type == MSG_DATA) {
        char decrypted_data[SECURE_MESSAGE_L + AES_BLOCK_SIZE];
        int dec_len = aes_decrypt(msg.data.encrypted.data, msg.data.encrypted.size, server->t, (uint8_t *)decrypted_data);
        
        if (dec_len >= SECURE_MESSAGE_L) {
            decrypted_data[SECURE_MESSAGE_L-1] = '\0'; // Enforce null termination
            printf("[SERVER] Data received (encrypted with t): \"%s\"\n", decrypted_data);
            fflush(stdout);
            return 0;
        } else {
            printf("[SERVER] Error decrypting post-authentication data.\n");
        }
    }
    return -1;
}

/**
 * @brief Cleans up server resources by closing sockets.
 * 
 * @param server Pointer to the IoTServer instance.
 */
void server_cleanup(IoTServer *server) {
    if (server->client_socket >= 0) {
        close(server->client_socket);
    }
    if (server->server_socket >= 0) {
        close(server->server_socket);
    }
}