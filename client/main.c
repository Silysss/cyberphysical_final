#include "iot_client.h"
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#define DEFAULT_HOST "server"
#define DEFAULT_PORT 8080

// Control flags for signal handling
volatile sig_atomic_t running = 1;
volatile sig_atomic_t trigger_auth = 0;

/**
 * @brief Handles incoming signals for the client daemon.
 * SIGUSR1: Triggers a new authentication session.
 * SIGINT / SIGTERM: Stops the daemon.
 */
void handle_signal(int sig) {
    if (sig == SIGUSR1) {
        trigger_auth = 1;
    } else {
        running = 0;
    }
}

/**
 * @file main.c (Client)
 * @brief Entry point for the IoT Client Daemon.
 * 
 * This application runs in the background and initiates the 3-way handshake
 * only when receiving a SIGUSR1 signal.
 */
int main() {
    LOG_INIT(); // Standard protocol logging setup
    printf("IoT Client Daemon - Authentication Demo\n");
    printf("Waiting for commands (SIGUSR1 to authenticate, Ctrl+C to quit)\n");

    // Load configuration from environment variables
    const char *host = getenv("SERVER_HOST");
    if (!host) host = DEFAULT_HOST;
    
    const char *port_env = getenv("SERVER_PORT");
    int port = port_env ? atoi(port_env) : DEFAULT_PORT;

    // Register POSIX signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGUSR1, handle_signal);

    // Initialize client context (loads vault and resolves host)
    IoTClient client;
    client_init(&client, host, port);

    while (running) {
        if (trigger_auth) {
            trigger_auth = 0;
            printf("\n--- Starting Authentication Session ---\n");
            
            // 1. Establish connection
            if (client_connect(&client) == 0) {
                printf("Connected to server %s:%d\n", host, port);
                
                // 2. Perform 3-way handshake
                if (client_authenticate(&client) == 0) {
                    // 3. Send secure application data if handshake succeeds
                    char data[SECURE_MESSAGE_L];
                    snprintf(data, SECURE_MESSAGE_L, "Secure data from %s", client.device_id);
                    client_send_data(&client, data);
                } else {
                    fprintf(stderr, "Authentication failed\n");
                }
                
                // Clean up session resources (socket)
                client_cleanup(&client);
            } else {
                fprintf(stderr, "Could not connect to server\n");
            }
            
            printf("--- Session Finished ---\n");
            printf("Waiting (SIGUSR1 to retry)...\n");
        }
        
        // Sleep to prevent high CPU usage (100ms)
        usleep(100000); 
    }

    printf("Client stopped\n");
    return 0;
}