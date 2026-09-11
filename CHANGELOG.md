---
description: "agent-vault — история изменений"
type: changelog
last_reviewed: 2026-06-21
last_code_change: 2026-06-21
status: active
---

# Changelog

Все значимые изменения проекта agent-vault документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/),
версионирование — [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

## [1.0.0] - 2026-09-11

### Initial Open Source Release
- **Core Daemon**: In-memory secret management daemon with encrypted persistence (ChaCha20-Poly1305 + Argon2id).
- **Telegram Bot Control**: Interactive bot management with strict fail-closed authentication and confirmation dialogs.
- **Companion CLI Tools**:
  - `agent-vault-cli`: Administrative CLI for secret and token management.
  - `agent-vault-env`: Zero-exposure environment variable injector with strict variable sanitization.
  - `with-secret`: Subprocess execution wrapper with stream masking (Tech Preview).
- **Security & Concurrency**: RWMutex concurrency safety, leak-free IP rate limiting, regex-validated secret names (`^[a-zA-Z0-9_\-]+$`).
- **Comprehensive Test Suite**: Unit tests, FSM bot tests, CLI/env tests, and race detector passing.
- **License**: MIT License.


## [4.0.0] - 2026-08-26

### Added
- **Sealed Mode**: Шифрование секретов в оперативной памяти и снапшота на диске с использованием ChaCha20-Poly1305 и Argon2id KDF.
- **TLS Enforcement**: Строгий флаг `-dev` для тестового режима без TLS; в боевом режиме требуется TLS сертификат.
- **with-secret**: Утилита для выполнения команд с динамической маскировкой вывода секретов.
- **Graceful Concurrency**: Защита состояния сервера при запуске и шатдауне через `sync.RWMutex`.
- **Hardened Tests**: Доведение покрытия CLI и helper утилит до 85-92%.

### Added
- **Проекты** — группировка секретов в проекты через TG-бот (FSM: ID → имя → секреты)
- **Project tokens** — одноразовые токены доступа ко всем секретам проекта (SHA-256, TTL)
- **Управление проектами через TG-бот**: создание, просмотр, добавление секретов, замена секретов, удаление
- **`agent-vault-env --write-to <file>`** — запись всех секретов проекта в .env файл
- **HTTP API для проектов**: `GET /projects`, `POST /projects`, `GET|DELETE /project/:id`
- **HTTP API для project tokens**: `GET /project-tokens/:project_id`, `POST /project-tokens/:project_id`
- **Project token response** — `/access/:token` теперь возвращает `{project, project_id, secrets}` для project tokens
- **Персистентность проектов** — Project и ProjectToken сохраняются в config.yaml
- Тесты: bot_test.go (+8 тестов проектных операций), cmd/agent-vault-env/main_test.go (+5 тестов)
- `docs/ADR/ADR-007-projects.md` — ADR для проектного функционала

### Changed
- **agent-vault-env** — поддержка двух форматов ответа (single secret + project token)
- **Session struct** — добавлено поле `addSecretProjectID`
- **sendProjectView** — отображение секретов проекта + кнопки «Добавить секрет», «Заменить секреты»
- **Token cleanup** — `cleanupExpiredTokens` теперь также чистит expired project tokens

### Docs
- README.md — обновлён раздел быстрого старта (проекты, project tokens, --write-to)
- API.md — добавлены эндпоинты проектов и project token response
- ARCHITECTURE.md — обновлена модель данных (Project, ProjectToken), FSM-диаграмма, раздел CLI
- CHANGELOG.md — версия 3.0.0

## [2.0.0] - 2026-06-10

### Changed
- **CLI v2.0** — `agent-vault-cli` полностью переписан под реальный API (убраны несуществующие команды: projects, audit, token, rotate)
- **agent-vault-env** — теперь использует `/access/:token` вместо несуществующего `/secrets/{project}`
- **Telegram меню** — зарегистрированы актуальные команды `/start` и `/cancel` через `setMyCommands`

### Added
- Тесты для `agent-vault-cli` (17 тестов: doRequest, cmdHealth, cmdList, cmdGet, cmdSet, cmdDelete, cmdExport, printUsage, prettyPrint, integration flow)
- Тесты для `agent-vault-env` (5 тестов: access endpoint, invalid token, export format)
- `setMyCommands` вызывается при старте бота для регистрации команд в меню Telegram

### Fixed
- Удалён мёртвый код: CLI ссылался на несуществующие endpoints (`/projects`, `/audit`, `/agent/tokens`, `/secret/{name}`)
- API.md — исправлены примеры CLI, убраны ссылки на несуществующие команды
- ARCHITECTURE.md — обновлена секция CLI-утилит
- README.md — актуализирован быстрый старт и описание команд

### Tests
- 88 → 105+ тестов (добавлены CLI тесты)
- Покрытие: core 71%, CLI 52%

## [1.1.0] - 2026-06-10

### Security
- **ChaCha20-Poly1305 + Argon2id** — реальное шифрование снапшота (было plain JSON)
- **SHA-256 хеширование токенов** — токены не хранятся в plain text в config.yaml
- **Telegram Admin ID** — бот отвечает только администратору (поле `tg_admin_id`)
- **HTML-экранирование кавычек** — `escapeHTML` теперь экранирует `"` и `'`
- **HTTP timeout в CLI** — `agent-vault-cli` и `agent-vault-env` используют 10s timeout

### Fixed
- **Race condition** — `config.save()` вызывался вне критической секции `config.mu` (4 места исправлено)
- **Дублирование поля `Tokens`** — убрано из Config struct
- **Тесты токенов** — адаптированы к `hashToken()` (было plain text)

### Changed
- Переход с MarkdownV2 на HTML форматирование в Telegram-боте (исправлен баг `can't parse entities`)
- Токены не восстанавливались после перезапуска — добавлены yaml-теги в SecretToken
- `Send(CallbackConfig)` заменён на `Request()` для tgbotapi v5
- `TestEscapeMarkdown` → `TestEscapeHTML`

### Tests
- 65 → 88 unit-тестов
- Добавлены тесты: TG Admin ID, one-time токены, rate limiter, hash token, crypto encrypt/decrypt, escapeHTML с кавычками, config без Tokens field
- `go test -race` — clean (0 warnings)

### Docs
- `ARCHITECTURE.md` — обновлена секция безопасности, снапшота, модели данных
- `API.md` — исправлены примеры agent-vault-cli, добавлено описание SHA-256 хеширования
- `README.md` — обновлены числа, описание функций, env vars

## [1.0.0] - 2026-06-10

### Added
- Редизайн бота: 4 кнопки главного меню, 2-шаговый FSM (waiting_name → waiting_value)
- Автоматическая генерация токена при создании секрета
- Эндпоинт `/access/:token` для доступа по токену к конкретному секрету
- Эндпоинт `/export` для экспорта всех секретов (JSON)
- Эндпоинт `/health` для мониторинга (статус, количество секретов, uptime)
- Killswitch: `DELETE /secrets` — мгновенное удаление всех секретов
- Удаление токенов: wipe_tokens через бота
- Отзыв токенов при удалении секрета
- CLI-утилита `agent-vault-env` для получения секретов в env
- CLI-утилита `agent-vault-cli` для управления через командную строку
- 65 unit-тестов (bot_test.go: 27, main_test.go: 38)
- Makefile с целями build, test, test-cov, lint, clean
- Скрипт деплоя deploy.sh
- .gitignore для Go-проекта

### Security
- Секреты хранятся только в RAM
- Снапшот зашифрован ChaCha20-Poly1305
- Токены с TTL (720 часов / 30 дней по умолчанию)
- Аутентификация через X-Vault-Token header
- ConstantTimeCompare для сравнения токенов (защита от timing attack)
