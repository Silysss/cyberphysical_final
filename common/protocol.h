#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdio.h>

// Paramètres du papier [cite: 117, 130]
#define N_KEYS 4          // Nombre de clés dans le vault (n)
#define KEY_SIZE_BITS 128 // Taille des clés en bits (m)
#define KEY_SIZE_BYTES (KEY_SIZE_BITS / 8)
#define P_INDICES 2 // Nombre d'indices par défi (p < n)

// Désactive le buffering de printf pour Docker logs
#define LOG_INIT() setvbuf(stdout, NULL, _IONBF, 0);

#endif
