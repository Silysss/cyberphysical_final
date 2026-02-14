#include "iot_server.h"
#include <stdio.h>
#include <signal.h>

#define PORT 8080

// Variable globale pour la gestion des signaux
extern volatile sig_atomic_t running;

int main() {
    LOG_INIT();
    printf("Serveur IoT - Authentication Demo\n");
    
    IoTServer server;
    server_init(&server, PORT);
    
    if (server_start(&server) < 0) {
        fprintf(stderr, "Échec du démarrage du serveur\n");
        server_cleanup(&server);
        return EXIT_FAILURE;
    }
    
    while (running) {
        server_handle_client(&server);
    }
    
    printf("Serveur arrêté\n");
    server_cleanup(&server);
    return 0;
}