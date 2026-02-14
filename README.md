# IoT Secure Vault Authentication

Implementation of the authentication protocol from the paper "Authentication of IoT Device and IoT Server Using Secure Vaults".

## Algorithm Overview

The protocol implements mutual authentication between an IoT device (client) and server using a shared secret vault:

1. **Shared Secret**: Both parties possess an identical `SecureVault` containing `n` random keys of `m` bits each
2. **Challenge-Response**:
   - Server generates a challenge with `p` random key indices and a nonce
   - Client computes response by XORing the selected keys and the nonce
   - Server verifies the response using its copy of the vault

### Protocol Parameters

| Parameter       | Value | Description                         |
| --------------- | ----- | ----------------------------------- |
| `N_KEYS`        | 4     | Number of keys in vault (n)         |
| `KEY_SIZE_BITS` | 128   | Key size in bits (m)                |
| `P_INDICES`     | 2     | Number of indices per challenge (p) |

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

## Future Enhancements
- [x] Client Daemonization & Trigger mechanism
- [ ] Mutual authentication (3-way handshake)
- [ ] Session key establishment (PFS)
- [ ] Dynamic vault rotation (HMAC-based)
- [ ] AES encryption for challenge-response

## Reference

Based on: "Authentication of IoT Device and IoT Server Using Secure Vaults" (Shah & Venkatesan)
