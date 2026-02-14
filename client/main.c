#include "iot_client.h"
#include <stdio.h>

#define SERVER_IP "server"
#define PORT 8080

int main() {
    LOG_INIT();
    printf("Client IoT - Authentication Demo\n");
    
    IoTClient client;
    client_init(&client, SERVER_IP, PORT);
    
    if (client_connect(&client) < 0) {
        fprintf(stderr, "Échec de la connexion au serveur\n");
        client_cleanup(&client);
        return EXIT_FAILURE;
    }
    
    printf("Connecté au serveur %s:%d\n", SERVER_IP, PORT);
    
    if (client_authenticate(&client) < 0) {
        fprintf(stderr, "Échec de l'authentification\n");
    }
    
    client_cleanup(&client);
    printf("Client terminé\n");
    return 0;
}