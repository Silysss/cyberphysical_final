#ifndef IOT_CLIENT_H
#define IOT_CLIENT_H

#include "../common/protocol.h"
#include <netinet/in.h>

/**
 * @struct IoTClient
 * @brief Context for the IoT device client daemon.
 */
typedef struct {
    SecureVault vault;              ///< Local secret vault (updated dynamically)
    int server_socket;              ///< Active connection to the server
    struct sockaddr_in server_addr; ///< Server network address
    char device_id[32];             ///< Unique device identifier
    uint8_t t[KEY_SIZE_BYTES];      ///< Established 128-bit session key
} IoTClient;

/**
 * @brief Prepares the client resources.
 */
void client_init(IoTClient *client, const char *server_ip, int port);

/**
 * @brief Opens a connection to the server.
 */
int client_connect(IoTClient *client);

/**
 * @brief Executes the 3-way mutual authentication handshake.
 */
int client_authenticate(IoTClient *client);

/**
 * @brief Sends an encrypted payload using the established session key.
 */
int client_send_data(IoTClient *client, const char *data);

/**
 * @brief Releases client resources and closes the socket.
 */
void client_cleanup(IoTClient *client);

#endif