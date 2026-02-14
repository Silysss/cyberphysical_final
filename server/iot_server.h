#ifndef IOT_SERVER_H
#define IOT_SERVER_H

#include "../common/protocol.h"
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
    SecureVault vault;
    int server_socket;
    int client_socket;
    struct sockaddr_in address;
    uint8_t session_key[KEY_SIZE_BYTES];
} IoTServer;

// Initialisation du serveur
void server_init(IoTServer *server, int port);

// Démarrage du serveur (écoute)
int server_start(IoTServer *server);

// Gestion d'un client (authentification)
void server_handle_client(IoTServer *server);

// Nettoyage des ressources
void server_cleanup(IoTServer *server);

#endif