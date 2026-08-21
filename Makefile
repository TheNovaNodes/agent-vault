.PHONY: all build test test-cov test-short test-race clean lint fmt run dev deploy init help

# === Variables ===
BINARY=agent-vault
ENV_BINARY=agent-vault-env
CLI_BINARY=agent-vault-cli
GO=go
GOFLAGS=-v
CONFIG=config.yaml

# === Default ===
.DEFAULT_GOAL := build

# === Help ===
help: ## Показать справку
	@echo "Lab Vault — секретный менеджер для AI-агентов"
	@echo ""
	@echo "Команды:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

# === Build ===
all: build

build: $(BINARY) $(ENV_BINARY) $(CLI_BINARY) ## Собрать все бинарники

$(BINARY): *.go
	$(GO) build $(GOFLAGS) -o $(BINARY) .

$(ENV_BINARY): cmd/agent-vault-env/*.go
	$(GO) build $(GOFLAGS) -o $(ENV_BINARY) ./cmd/agent-vault-env

$(CLI_BINARY): cmd/agent-vault-cli/*.go
	$(GO) build $(GOFLAGS) -o $(CLI_BINARY) ./cmd/agent-vault-cli

# === Test ===
test: ## Запустить все тесты (95+ тестов)
	$(GO) test $(GOFLAGS) ./...

test-cov: ## Тесты с покрытием
	$(GO) test $(GOFLAGS) -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html

test-short: ## Тесты без verbose
	$(GO) test -short ./...

test-race: ## Тесты с race detector
	$(GO) test -race $(GOFLAGS) ./...

# === Lint ===
lint: ## Линтер (go vet + golangci-lint если есть)
	$(GO) vet ./...
	@golangci-lint run ./... 2>/dev/null || echo "[lint] golangci-lint не установлен, go vet OK"

fmt: ## Форматирование кода
	$(GO)fmt -w .
	$(GO)imports -w . 2>/dev/null || true

# === Run ===
run: $(BINARY) ## Запуск сервера
	./$(BINARY) -config $(CONFIG)

dev: $(BINARY) ## Запуск в режиме разработки (с env override)
	VAULT_BOT_TOKEN=$${VAULT_BOT_TOKEN} \
	VAULT_ADMIN_TOKEN=$${VAULT_ADMIN_TOKEN} \
	./$(BINARY) -config $(CONFIG)

# === Clean ===
clean: ## Очистка артефактов сборки
	rm -f $(BINARY) $(ENV_BINARY) $(CLI_BINARY)
	rm -f coverage.out coverage.html
	rm -f *.bak *.bin

# === Deploy ===
deploy: build ## Деплой на сервер
	@echo "[deploy] stopping agent-vault..."
	@sudo systemctl stop agent-vault 2>/dev/null || true
	@echo "[deploy] copying binary..."
	sudo cp $(BINARY) /usr/local/bin/agent-vault
	@echo "[deploy] starting agent-vault..."
	sudo systemctl start agent-vault
	@echo "[deploy] checking status..."
	@sudo systemctl status agent-vault --no-pager || true

# === Init ===
init: $(BINARY) ## Инициализация vault (создание snapshot.enc)
	@echo "[init] Убедитесь что VAULT_PASSWORD установлен"
	./$(BINARY) -init
