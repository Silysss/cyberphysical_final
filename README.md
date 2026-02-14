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

## Build Instructions

### Prerequisites

- GCC compiler
- OpenSSL development libraries
- Docker & Docker Compose (for containerized deployment)

### Local Build

```bash
# Build everything
make all

# Build and run server locally
make run-server

# Build and run client locally (in another terminal)
make run-client
```

### Docker Build

```bash
# Build Docker images
docker compose build

# Run both containers
docker compose up

# Run in background
docker compose up -d

# View logs
docker compose logs -f

# Stop containers
docker compose down
```

## Testing

```bash
# Run unit tests
make unit-tests

# Run integration tests
make integration-tests

# Run all tests
make test
```

### Unit Tests

The unit tests verify:

- Random byte generation
- XOR operations
- Vault generation and persistence
- Challenge-response computation

### Integration Tests

The integration tests verify the complete authentication flow between simulated client and server.

## Vault Generation

Generate a new shared vault:

```bash
make generate-vault
```

This creates `common/vault.bin` containing 4 random 128-bit keys.

## Docker Networking

The client container connects to the server using the Docker service name `server` as the hostname. Both containers share the `iot_network` bridge network.

## Security Notes

- All random values are generated using OpenSSL's `RAND_bytes()` for cryptographic security
- The vault file should be securely distributed to both parties before deployment
- This MVP implementation does not include AES encryption (as per requirements)

## Future Enhancements

- Add TLS/SSL for transport encryption
- Implement vault rotation
- Add mutual authentication (client challenges server)
- Implement replay attack protection with timestamps

## Reference

Based on: "Authentication of IoT Device and IoT Server Using Secure Vaults"
