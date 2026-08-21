---
name: Lab Vault
owner: DoctorM&Ai
type: service
status: production
priority: high
stack: [Go 1.22, tgbotapi v5, yaml.v3, ChaCha20-Poly1305]
version: "1.0.0"
path: projects/agent-vault
created: "2026-06-08"
updated: "2026-06-10"
---

# Lab Vault

Секретный менеджер для AI-агентов. Секреты хранятся в RAM, на диске — только зашифрованный снапшот.

## Назначение
Безопасная передача секретов (API keys, пароли, токены) AI-агентам Лаборатории без компрометации.

## Порт
`127.0.0.1:8301`

## Статус
✅ Production Ready (сервис работает, PID активен)

## Структура
- `main.go` (~900 строк) — сервер + TG бот
- `bot_test.go` (27 тестов) — тесты бота
- `main_test.go` (38 тестов) — тесты store, config, HTTP API
- `config.yaml` — конфиг + токены агентов
- `snapshot.enc` — снапшот секретов
- `cmd/agent-vault-env/` — CLI для лаборантов
- `cmd/agent-vault-cli/` — CLI для управления
- `docs/` — документация (ADR, API, архитектура)

## Тесты
65/65 тестов проходят. Покрытие >80%.

## Документация
- [README.md](README.md) — описание и быстрый старт
- [CHANGELOG.md](CHANGELOG.md) — история изменений
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — архитектура
- [docs/API.md](docs/API.md) — HTTP API спецификация
- [docs/ADR/](docs/ADR/) — Architecture Decision Records
