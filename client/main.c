#include "iot_client.h"
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#define DEFAULT_HOST "server"
#define DEFAULT_PORT 8080

volatile sig_atomic_t running = 1;
volatile sig_atomic_t trigger_auth = 0;

void handle_signal(int sig) {
    if (sig == SIGUSR1) {
        trigger_auth = 1;
    } else {
        running = 0;
    }
}

int main() {
    LOG_INIT();
    printf("Client IoT Daemon - Authentication Demo\n");
    printf("En attente de commandes (SIGUSR1 pour authentifier, Ctrl+C pour quitter)\n");

    const char *host = getenv("SERVER_HOST");
    if (!host) host = DEFAULT_HOST;
    
    const char *port_env = getenv("SERVER_PORT");
    int port = port_env ? atoi(port_env) : DEFAULT_PORT;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGUSR1, handle_signal);

    IoTClient client;
    client_init(&client, host, port);

    while (running) {
        if (trigger_auth) {
            trigger_auth = 0;
            printf("\n--- Début de l'authentification ---\n");
            
            if (client_connect(&client) == 0) {
                printf("Connecté au serveur %s:%d\n", host, port);
                if (client_authenticate(&client) < 0) {
                    fprintf(stderr, "Échec de l'authentification\n");
                }
                client_cleanup(&client);
            } else {
                fprintf(stderr, "Impossible de se connecter au serveur\n");
            }
            
            printf("--- Fin de session ---\n");
            printf("En attente (SIGUSR1 pour recommencer)...\n");
        }
        
        usleep(100000); // 100ms sleep to prevent CPU spinning
    }

    printf("Client arrêté\n");
    return 0;
}