#include "iot_client.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

void client_init(IoTClient *client, const char *server_ip, int port) {
    // Charger le vault partagé
    if (!load_vault(&client->vault, "common/vault.bin")) {
        fprintf(stderr, "Erreur: Impossible de charger le vault\n");
        exit(EXIT_FAILURE);
    }

    // Configurer l'adresse du serveur
    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_port = htons(port);

    // Essayer d'abord de parser comme une adresse IP
    if (inet_pton(AF_INET, server_ip, &client->server_addr.sin_addr) <= 0) {
        // Sinon, résoudre comme un nom d'hôte
        struct hostent *host = gethostbyname(server_ip);
        if (host == NULL) {
            fprintf(stderr, "Impossible de résoudre le nom d'hôte: %s\n", server_ip);
            exit(EXIT_FAILURE);
        }
        memcpy(&client->server_addr.sin_addr, host->h_addr, host->h_length);
    }

    client->server_socket = -1;
}

int client_connect(IoTClient *client) {
    // Créer le socket
    client->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client->server_socket < 0) {
        perror("Échec de la création du socket");
        return -1;
    }
    
    // Se connecter au serveur
    if (connect(client->server_socket, (struct sockaddr *)&client->server_addr, 
                sizeof(client->server_addr)) < 0) {
        perror("Échec de la connexion");
        return -1;
    }
    
    return 0;
}

int client_authenticate(IoTClient *client) {
    // Recevoir le défi du serveur
    Message challenge_msg;
    if (receive_message(client->server_socket, &challenge_msg) < 0) {
        return -1;
    }
    
    if (challenge_msg.type != MSG_CHALLENGE) {
        fprintf(stderr, "Type de message inattendu: %d\n", challenge_msg.type);
        return -1;
    }
    
    Challenge *challenge = &challenge_msg.data.challenge;
    printf("Défi reçu: indices=%d,%d\n", challenge->indices[0], challenge->indices[1]);
    
    // Calculer la réponse
    Response response;
    compute_response(&client->vault, challenge, &response);
    
    // Envoyer la réponse au serveur
    Message response_msg = {MSG_RESPONSE, {.response = response}};
    if (send_message(client->server_socket, &response_msg) < 0) {
        return -1;
    }
    
    // Recevoir le résultat
    Message result_msg;
    if (receive_message(client->server_socket, &result_msg) < 0) {
        return -1;
    }
    
    if (result_msg.type == MSG_SUCCESS) {
        printf("Authentification: SUCCÈS\n");
        return 0;
    } else {
        printf("Authentification: ÉCHEC\n");
        return -1;
    }
}

void client_cleanup(IoTClient *client) {
    if (client->server_socket >= 0) {
        close(client->server_socket);
    }
}