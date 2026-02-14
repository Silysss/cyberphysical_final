#include "iot_server.h"
#include <unistd.h>
#include <signal.h>

volatile sig_atomic_t running = 1;

void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

void server_init(IoTServer *server, int port) {
    // Charger le vault partagé
    if (!load_vault(&server->vault, "common/vault.bin")) {
        fprintf(stderr, "Erreur: Impossible de charger le vault\n");
        exit(EXIT_FAILURE);
    }
    
    // Configurer l'adresse du serveur
    server->address.sin_family = AF_INET;
    server->address.sin_addr.s_addr = INADDR_ANY;
    server->address.sin_port = htons(port);
    
    server->server_socket = -1;
    server->client_socket = -1;
}

int server_start(IoTServer *server) {
    int opt = 1;
    
    // Créer le socket
    server->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server->server_socket == 0) {
        perror("Échec de la création du socket");
        return -1;
    }
    
    // Configurer les options du socket
    if (setsockopt(server->server_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                   &opt, sizeof(opt))) {
        perror("Échec de la configuration des options du socket");
        return -1;
    }
    
    // Lier le socket à l'adresse et au port
    if (bind(server->server_socket, (struct sockaddr *)&server->address, 
             sizeof(server->address)) < 0) {
        perror("Échec du bind");
        return -1;
    }
    
    // Écouter les connexions entrantes
    if (listen(server->server_socket, 5) < 0) {
        perror("Échec de l'écoute");
        return -1;
    }
    
    printf("Serveur en écoute sur le port %d...\n", ntohs(server->address.sin_port));
    
    // Configuration du signal pour arrêter proprement
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    return 0;
}

void server_handle_client(IoTServer *server) {
    socklen_t addrlen = sizeof(server->address);
    
    // Accepter une nouvelle connexion
    server->client_socket = accept(server->server_socket, 
                                    (struct sockaddr *)&server->address, 
                                    &addrlen);
    if (server->client_socket < 0) {
        if (running) {
            perror("Échec de l'acceptation");
        }
        return;
    }
    
    printf("Client connecté depuis %s:%d\n",
           inet_ntoa(server->address.sin_addr), 
           ntohs(server->address.sin_port));
    
    // Générer un défi
    Challenge challenge;
    generate_challenge(&challenge);
    printf("Défi généré: indices=%d,%d\n", challenge.indices[0], challenge.indices[1]);
    
    // Envoyer le défi au client
    Message challenge_msg = {MSG_CHALLENGE, {.challenge = challenge}};
    if (send_message(server->client_socket, &challenge_msg) < 0) {
        close(server->client_socket);
        server->client_socket = -1;
        return;
    }
    
    // Recevoir la réponse du client
    Message response_msg;
    if (receive_message(server->client_socket, &response_msg) < 0) {
        close(server->client_socket);
        server->client_socket = -1;
        return;
    }
    
    if (response_msg.type != MSG_RESPONSE) {
        fprintf(stderr, "Type de message inattendu: %d\n", response_msg.type);
        close(server->client_socket);
        server->client_socket = -1;
        return;
    }
    
    // Vérifier la réponse
    int is_valid = verify_response(&server->vault, &challenge, &response_msg.data.response);
    printf("Authentification: %s\n", is_valid ? "SUCCÈS" : "ÉCHEC");
    
    // Envoyer le résultat au client
    Message result_msg = {is_valid ? MSG_SUCCESS : MSG_FAILURE};
    send_message(server->client_socket, &result_msg);
    
    close(server->client_socket);
    server->client_socket = -1;
    printf("Connexion fermée\n");
}

void server_cleanup(IoTServer *server) {
    if (server->client_socket >= 0) {
        close(server->client_socket);
    }
    if (server->server_socket >= 0) {
        close(server->server_socket);
    }
}