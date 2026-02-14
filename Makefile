CC = gcc
CFLAGS = -I./common -Wall
LDFLAGS = -lcrypto
BUILD_DIR = build

# Sources
SERVER_SRCS = server/main.c server/iot_server.c common/crypto.c
CLIENT_SRCS = client/main.c client/iot_client.c common/crypto.c
TEST_CRYPTO_SRCS = tests/unit/test_crypto.c common/crypto.c
TEST_AUTH_SRCS = tests/integration/test_authentication.c common/crypto.c
GEN_VAULT_SRCS = common/generate_vault.c common/crypto.c

# Binaries
SERVER_APP = $(BUILD_DIR)/server_app
CLIENT_APP = $(BUILD_DIR)/client_app
UNIT_TESTS = $(BUILD_DIR)/unit_tests
INTEGRATION_TESTS = $(BUILD_DIR)/integration_test
GEN_VAULT = $(BUILD_DIR)/generate_vault

all: prepare $(SERVER_APP) $(CLIENT_APP) $(UNIT_TESTS) $(INTEGRATION_TESTS) $(GEN_VAULT)

prepare:
	mkdir -p $(BUILD_DIR)

$(SERVER_APP): $(SERVER_SRCS)
	$(CC) $(CFLAGS) $(SERVER_SRCS) -o $(SERVER_APP) $(LDFLAGS)

$(CLIENT_APP): $(CLIENT_SRCS)
	$(CC) $(CFLAGS) $(CLIENT_SRCS) -o $(CLIENT_APP) $(LDFLAGS)

$(UNIT_TESTS): $(TEST_CRYPTO_SRCS)
	$(CC) $(CFLAGS) $(TEST_CRYPTO_SRCS) -o $(UNIT_TESTS) $(LDFLAGS)

$(INTEGRATION_TESTS): $(TEST_AUTH_SRCS)
	$(CC) $(CFLAGS) $(TEST_AUTH_SRCS) -o $(INTEGRATION_TESTS) $(LDFLAGS)

$(GEN_VAULT): $(GEN_VAULT_SRCS)
	$(CC) $(CFLAGS) $(GEN_VAULT_SRCS) -o $(GEN_VAULT) $(LDFLAGS)

# Execution locale (HORS DOCKER)
run-server:
	MASTER_KEY=1234567890123456 VAULT_PATH=server/vault.bin ./$(SERVER_APP)

run-client:
	MASTER_KEY=1234567890123456 VAULT_PATH=client/vault.bin ./$(CLIENT_APP)

generate-vault: $(GEN_VAULT)
	MASTER_KEY=1234567890123456 ./$(GEN_VAULT)
	cp common/vault.bin client/vault.bin
	cp common/vault.bin server/vault.bin
	@echo "✅ Vaults distribués dans client/ et server/"

# Tests
unit-tests: $(UNIT_TESTS)
	./$(UNIT_TESTS)

integration-tests: $(INTEGRATION_TESTS)
	./$(INTEGRATION_TESTS)

test: unit-tests integration-tests

# Docker targets
up:
	docker compose up --build -d

stop:
	docker compose down

logs:
	docker compose logs -f

trigger-auth:
	docker compose kill -s SIGUSR1 iot_device
	@echo "🔔 Signal SIGUSR1 envoyé au client"

# Nettoyage
clean:
	rm -rf $(BUILD_DIR)
	rm -f common/*.bin client/*.bin server/*.bin
	@echo "✨ Nettoyage (build & vaults) effectué"

# Nettoyage profond via Docker (si souci de permissions)
docker-clean:
	docker compose run --rm server rm -rf build

# Documentation
doc:
	doxygen Doxyfile
	@echo "📚 Documentation générée dans docs/html/"

clean-doc:
	rm -rf docs
	@echo "🧹 Documentation supprimée"

.PHONY: all prepare run-server run-client generate-vault unit-tests integration-tests test up stop logs trigger-auth clean docker-clean doc clean-doc