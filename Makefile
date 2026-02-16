CC = gcc
CFLAGS = -I./common -Wall
LDFLAGS = -lcrypto
BUILD_DIR = build

# Fallback MASTER_KEY if not provided in environment
MASTER_KEY ?= 1234567890123456

# Sources
SERVER_SRCS = server/main.c server/iot_server.c common/crypto.c
CLIENT_SRCS = client/main.c client/iot_client.c common/crypto.c
TEST_CRYPTO_SRCS = tests/unit/test_crypto.c common/crypto.c
TEST_AUTH_SRCS = tests/integration/test_authentication.c common/crypto.c
GEN_VAULT_SRCS = common/generate_vault.c common/crypto.c

# Binaries
SERVER_APP = $(BUILD_DIR)/server_app.ex
CLIENT_APP = $(BUILD_DIR)/client_app.ex
UNIT_TESTS = $(BUILD_DIR)/unit_tests.ex
INTEGRATION_TESTS = $(BUILD_DIR)/integration_test.ex
GEN_VAULT = $(BUILD_DIR)/generate_vault.ex

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

# Local Execution
run-server: $(SERVER_APP)
	MASTER_KEY=$(MASTER_KEY) VAULT_PATH=server/vault.bin ./$(SERVER_APP)

run-client: $(CLIENT_APP)
	MASTER_KEY=$(MASTER_KEY) VAULT_PATH=client/vault.bin ./$(CLIENT_APP)

generate-vault: $(GEN_VAULT)
	MASTER_KEY=$(MASTER_KEY) ./$(GEN_VAULT)
	cp common/vault.bin client/vault.bin
	cp common/vault.bin server/vault.bin
	@echo "✅ Vaults distributed to client/ and server/"

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
	docker compose exec client pkill -USR1 client_app.ex
	@echo "🔔 SIGUSR1 signal sent to client via pkill"

# Cleanup
clean:
	rm -rf $(BUILD_DIR)
	rm -f common/*.bin client/*.bin server/*.bin
	@echo "✨ Cleanup (build & vaults) completed"

# Deep cleanup via Docker
docker-clean:
	docker compose run --rm server rm -rf build

# Documentation
doc:
	doxygen Doxyfile
	@echo "📚 Documentation generated in docs/html/"

clean-doc:
	rm -rf docs
	@echo "🧹 Documentation removed"

.PHONY: all prepare run-server run-client generate-vault unit-tests integration-tests test up stop logs trigger-auth clean docker-clean doc clean-doc
