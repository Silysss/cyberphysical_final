# IoT Secure Vault Authentication

Implementation of the authentication protocol from the paper "Authentication of IoT Device and IoT Server Using Secure Vaults".

## Algorithm Overview

The protocol implements **mutual authentication** (3-way handshake) and **session key establishment** between an IoT device (client) and server:

1.  **M1 (Init)**: Client sends its `device_id` and a `session_id`.
2.  **M2 (Challenge)**: Server sends Challenge `C1` and nonce `r1`.
3.  **M3 (Response + Challenge)**:
    - Client computes key `k1` from `C1`.
    - Client generates random `t1`, Challenge `C2`, and nonce `r2`.
    - Client sends $\{Enc(k1, r1 \parallel t1 \parallel C2 \parallel r2)\}$ to the server.
4.  **M4 (Final Response)**:
    - Server decrypts M3 using `k1`, verifies `r1`, and extracts `t1` and `C2`.
    - Server computes `k2` from `C2` and generates random `t2`.
    - Server sends $\{Enc(k2 \oplus t1, r2 \parallel t2)\}$ to the client.
5.  **Session Key**: Both compute the session key **$t = t_1 \oplus t_2$**.

### Security Features
- **Mutual Authentication**: Both client and server identify each other using the vault.
- **AES-128-CBC Encryption**: All sensitive handshake components are encrypted.
- **Dynamic Session Key**: A unique key $t$ is established for each session.
- **Binding**: M4 is bound to M3 using $k_2 \oplus t_1$ as the encryption key.

### Protocol Parameters

| Parameter       | Value | Description                         |
| --------------- | ----- | ----------------------------------- |
| `N_KEYS`        | 4     | Number of keys in vault (n)         |
| `KEY_SIZE_BITS` | 128   | Key size in bits (m)                |
| `P_INDICES`     | 2     | Number of indices per challenge (p) |
| `AES_BLOCK_SIZE`| 16    | AES block size for encryption       |

## Project Structure

```
.
├── client/           # IoT device (client) code
│   ├── main.c        # Entry point
│   ├── iot_client.c  # Client logic
│   └── iot_client.h
├── server/           # Server code
│   ├── main.c        # Entry point
│   ├── iot_server.c  # Server logic
│   └── iot_server.h
├── common/           # Shared code
│   ├── protocol.h    # Protocol definitions
│   └── crypto.c      # Crypto primitives & network functions
│   └── generate_vault.c
├── tests/
│   ├── unit/         # Unit tests
│   └── integration/  # Integration tests
├── Makefile
└── docker-compose.yml
```

## Build & Run Instructions

### Prerequisites

- GCC compiler
- OpenSSL development libraries
- Docker & Docker Compose

### 1. Initial Setup

Before running the system, you must generate the shared secret vault:

```bash
make generate-vault
```

### 2. Running with Docker (Recommended)

The project is optimized for a containerized environment where the client and server run as persistent services.

```bash
# Start the system
make up

# In another terminal, trigger an authentication session
make trigger-auth

# Monitor the interaction
docker compose logs -f
```

> [!NOTE]
> The client now runs as a **daemon**. It will stay alive indefinitely and perform authentication only when it receives a `SIGUSR1` signal (sent via `make trigger-auth`).

### 3. Local Build (Manual)

```bash
# Build everything
make all

# Run server
./build/server_app

# Run client (daemon mode)
./build/client_app
# In another terminal: pkill -USR1 client_app
```

## Testing

```bash
# Run all tests (Unit + Integration)
make test
```

## Docker Networking

The client connects to the server using the service name `server`. The `Makefile` automatically handles non-root user permissions by passing `MY_UID` and `MY_GID` to the containers.

## Reference

Based on: "Authentication of IoT Device and IoT Server Using Secure Vaults" (Shah & Venkatesan)
