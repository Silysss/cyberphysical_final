CC = gcc
CFLAGS = -I./common -Wall
BUILD_DIR = build

all: prepare $(BUILD_DIR)/server_app $(BUILD_DIR)/client_app

prepare:
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/server_app: server/main.c
	$(CC) $(CFLAGS) server/main.c -o $(BUILD_DIR)/server_app

$(BUILD_DIR)/client_app: client/main.c
	$(CC) $(CFLAGS) client/main.c -o $(BUILD_DIR)/client_app

# Commandes lancées par Docker
run-server: all
	./$(BUILD_DIR)/server_app

run-client: all
	./$(BUILD_DIR)/client_app

# Workflow local
up:
	docker compose up --build

stop:
	docker compose down

clean:
	rm -rf $(BUILD_DIR)
