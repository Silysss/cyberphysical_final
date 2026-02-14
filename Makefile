CC = gcc
CFLAGS = -I./common -Wall
LDFLAGS = -lcrypto
BUILD_DIR = build

# ============================================================
# Main targets
# ============================================================

all: $(BUILD_DIR)/server_app $(BUILD_DIR)/client_app

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# ============================================================
# Applications
# ============================================================

$(BUILD_DIR)/server_app: server/main.c server/iot_server.c common/crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) server/main.c server/iot_server.c common/crypto.c -o $(BUILD_DIR)/server_app $(LDFLAGS)

$(BUILD_DIR)/client_app: client/main.c client/iot_client.c common/crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) client/main.c client/iot_client.c common/crypto.c -o $(BUILD_DIR)/client_app $(LDFLAGS)

# ============================================================
# Run commands (for Docker)
# ============================================================

run-server: $(BUILD_DIR)/server_app
	./$(BUILD_DIR)/server_app

run-client: $(BUILD_DIR)/client_app
	./$(BUILD_DIR)/client_app

# ============================================================
# Tools
# ============================================================

$(BUILD_DIR)/generate_vault: common/generate_vault.c common/crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) common/generate_vault.c common/crypto.c -o $(BUILD_DIR)/generate_vault $(LDFLAGS)

generate-vault: $(BUILD_DIR)/generate_vault
	./$(BUILD_DIR)/generate_vault
	cp common/vault.bin client/vault.bin
	cp common/vault.bin server/vault.bin
	@echo "✅ Vaults distribués dans client/ et server/"

# ============================================================
# Tests
# ============================================================

$(BUILD_DIR)/unit_tests: tests/unit/test_crypto.c common/crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/unit/test_crypto.c common/crypto.c -o $(BUILD_DIR)/unit_tests $(LDFLAGS)

$(BUILD_DIR)/integration_test: tests/integration/test_authentication.c common/crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) tests/integration/test_authentication.c common/crypto.c -o $(BUILD_DIR)/integration_test $(LDFLAGS)

unit-tests: $(BUILD_DIR)/unit_tests
	./$(BUILD_DIR)/unit_tests

integration-tests: $(BUILD_DIR)/integration_test
	./$(BUILD_DIR)/integration_test

test: unit-tests integration-tests

# ============================================================
# Docker workflow
# ============================================================

up:
	docker compose up --build -d

stop:
	docker compose down

logs:
	docker compose logs -f

trigger-auth:
	docker exec iot_device pkill -USR1 client_app

# ============================================================
# Cleanup
# ============================================================

clean:
	rm -rf $(BUILD_DIR)
	rm -f common/*.bin client/*.bin server/*.bin
	@echo "✨ Nettoyage (build & vaults) effectué"

# Nettoyage profond via Docker (si souci de permissions)
docker-clean:
	docker compose run --rm server rm -rf build

.PHONY: all run-server run-client generate-vault unit-tests integration-tests test up stop clean