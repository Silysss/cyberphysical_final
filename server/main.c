#include "iot_server.h"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

#define DEFAULT_PORT 8080

// Global flag to control the main server loop execution.
extern volatile sig_atomic_t running;

/**
 * @file main.c (Server)
 * @brief Entry point for the IoT Server application.
 * 
 * This application listens for incoming connections from IoT devices,
 * performs mutual authentication, and establishes a secure session for data exchange.
 */
int main() {
    LOG_INIT(); // Standard protocol logging setup
    printf("IoT Server - Authentication Demo\n");
    
    // Load port configuration from environment variables
    const char *port_env = getenv("SERVER_PORT");
    int port = port_env ? atoi(port_env) : DEFAULT_PORT;
    
    // 1. Initialize server context (loads vault and sets address)
    IoTServer server;
    server_init(&server, port);
    
    // 2. Start the TCP listening socket
    if (server_start(&server) < 0) {
        fprintf(stderr, "Server startup failed\n");
        server_cleanup(&server);
        return EXIT_FAILURE;
    }
    
    // 3. Main server loop: accept and handle clients sequentially
    while (running) {
        server_handle_client(&server);
    }
    
    // 4. Graceful cleanup on SIGINT/SIGTERM
    printf("Server stopped\n");
    server_cleanup(&server);
    return 0;
}