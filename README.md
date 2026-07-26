---
description: "lab-vault — README"
type: readme
last_reviewed: 2026-06-21
last_code_change: 2026-06-21
status: active
---

# 🔐 Lab Vault

> **Владелец:** DoctorM&Ai | **Статус:** active | **Версия:** 3.0.0

## Описание

Lab Vault — безопасное хранилище секретов (API keys, пароли, токены) для AI-агентов. Секреты хранятся в RAM, на диске — только зашифрованный снапшот (ChaCha20-Poly1305). Управление через Telegram-бот с FSM-диалогом. Доступ по one-time токенам с TTL.

## Описание

Lab Vault — безопасное хранилище секретов (API keys, пароли, токены) для AI-агентов. Секреты хранятся в RAM, на диске — только зашифрованный снапшот (ChaCha20-Poly1305). Управление через Telegram-бот с FSM-диалогом. Доступ по one-time токенам с TTL.

**Ключевые возможности:**
- 2-шаговый FSM для создания секретов через TG-бот
- **Проекты** — группировка секретов, управление через TG-бот
- **Project tokens** — одноразовые токены доступа ко всем секретам проекта
- Автоматическая генерация one-time токенов доступа с TTL
- HTTP API для получения секретов (rate limited)
- Экспорт секретов, killswitch
- ChaCha20-Poly1305 + Argon2id шифрование снапшота
- SHA-256 хеширование токенов в конфиге
- Telegram Admin ID фильтрация
- 90+ unit + integration тестов, race condition safe

## Быстрый старт

### 1. Сборка

```bash
cd /root/LabDoctorM/projects/lab-vault
export PATH=/usr/local/go/bin:$PATH
make build
```

### 2. Конфигурация

```yaml
# config.yaml
listen_addr: 127.0.0.1:8301
tg_bot_token: "YOUR_BOT_TOKEN"       # или VAULT_BOT_TOKEN env
tg_admin_id: 123456789                # ваш Telegram ID
admin_token: "YOUR_ADMIN_TOKEN"       # или VAULT_ADMIN_TOKEN env
token_ttl_hours: 720                   # TTL токенов (30 дней), 0 = бессрочно
snapshot_path: ./snapshot.enc
```

### 3. Запуск

```bash
VAULT_PASSWORD="master-password" ./lab-vault -config config.yaml
```

**Переменные окружения:**
- `VAULT_PASSWORD` — мастер-пароль для шифрования снапшота
- `VAULT_ADMIN_TOKEN` — админ-токен (альтернатива config.yaml)
- `VAULT_BOT_TOKEN` — токен TG-бота (альтернатива config.yaml)

### 4. Добавление секретов (TG-бот)

```
/start → ➕ Создать → Имя секрета → Значение
```

Бот автоматически создаст секрет и сгенерирует токен доступа.

### 5. Использование (получение секрета)

```bash
# Через lab-vault-env (single secret)
eval $(lab-vault-env -token <token>)

# Через lab-vault-env (project token — все секреты проекта)
eval $(lab-vault-env -token <project-token>)

# Запись секретов проекта в .env файл
lab-vault-env -token <project-token> --write-to /path/to/.env

# Через curl
curl http://127.0.0.1:8301/access/<token>

# Через lab-vault-cli
lab-vault-cli get <name>
```

### 6. Работа с проектами (TG-бот)

```
/start → 📁 Проекты → ➕ Создать проект → ID → Имя → Выбрать секреты
```

**В карточке проекта:**
- 🔑 Создать токен — генерирует project token (одноразовый)
- ➕ Добавить секрет — добавить существующий секрет в проект
- ✏️ Заменить секреты — перевыбрать набор секретов проекта
- 🗑 Удалить проект — удаляет проект и все его токены

**Воркфлоу передачи секретов лаборанту:**
1. ЗавЛаб создаёт секреты через бот → группирует в проект
2. Генерирует project token → передаёт лаборанту в чате
3. Лаборант: `lab-vault-env -token <token> --write-to /projects/X/.env`
4. Токен сгорает после использования — секрет не появляется в чате

## Архитектура

```
ЗавЛаб → TG Bot → POST /secrets → Store (RAM) → snapshot.enc (ChaCha20-Poly1305)
                                    ↓
Агент → lab-vault-env / curl → GET /access/:token → Store
                                    ↓
                              Project Token → все секреты проекта
```

**Стек:** Go 1.22, tgbotapi v5, yaml.v3, ChaCha20-Poly1305

**Слои:**
- `Store` — потокобезопасное хранилище (sync.RWMutex)
- `Server` — HTTP API (net/http), 10 endpoints (включая проекты)
- `Bot` — Telegram Bot с FSM (проекты + секреты, multi-step диалоги)
- `Config` — YAML с атомарным сохранением (projects, project_tokens)
- `Project` / `ProjectToken` — группировка секретов и изолированный доступ

Подробнее: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Разработка

```bash
# Сборка
make build

# Все тесты (80+ тестов)
make test

# Тесты с покрытием
make test-cov

# Тесты с race detector
make test-race

# Линтер
make lint

# Очистка
make clean
```

**Тесты:** 80+ unit + integration тестов. Покрытие >70%. `go test -race` — clean.

## Деплой

```bash
./deploy.sh
```

Подробнее: [docs/DEPLOY.md](docs/DEPLOY.md)

**Health check:** `GET /health` → `{"status":"ok","secrets":N,"uptime":"..."}`

## Документация

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — архитектура и модель данных
- [docs/API.md](docs/API.md) — HTTP API спецификация
- [docs/ADR/](docs/ADR/) — Architecture Decision Records
- [CHANGELOG.md](CHANGELOG.md) — история изменений
