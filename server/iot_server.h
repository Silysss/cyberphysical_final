#ifndef IOT_SERVER_H
#define IOT_SERVER_H

#include "../common/protocol.h"
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * @struct IoTServer
 * @brief Context for the IoT server application.
 */
typedef struct {
    SecureVault vault;         ///< Master secret vault (mirrors client vault)
    int server_socket;         ///< Passive listening socket
    int client_socket;         ///< Active socket for the connected client
    struct sockaddr_in address;///< Server listening address
    uint8_t t[KEY_SIZE_BYTES]; ///< Established 128-bit session key
} IoTServer;

/**
 * @brief Prepares the server structure and local vault.
 */
void server_init(IoTServer *server, int port);

/**
 * @brief Binds the socket and begins listening for connections.
 */
int server_start(IoTServer *server);

/**
 * @brief Orchestrates a client session (Accept -> Auth -> Data).
 */
void server_handle_client(IoTServer *server);

/**
 * @brief Executes Phase 1 of the protocol: Mutual Authentication.
 */
int server_authenticate(IoTServer *server);

/**
 * @brief Executes Phase 2: Secure Data Reception using session key 't'.
 */
int server_receive_data(IoTServer *server);

/**
 * @brief Gracefully releases server and client sockets.
 */
void server_cleanup(IoTServer *server);

#endif