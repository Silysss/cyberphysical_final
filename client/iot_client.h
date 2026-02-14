#ifndef IOT_CLIENT_H
#define IOT_CLIENT_H

#include "../common/protocol.h"
#include <netinet/in.h>

typedef struct {
    SecureVault vault;
    int server_socket;
    struct sockaddr_in server_addr;
    char device_id[32];
    uint8_t session_key[KEY_SIZE_BYTES];
} IoTClient;

// Initialisation du client
void client_init(IoTClient *client, const char *server_ip, int port);

// Connexion au serveur
int client_connect(IoTClient *client);

// Processus d'authentification
int client_authenticate(IoTClient *client);

// Nettoyage des ressources
void client_cleanup(IoTClient *client);

#endif