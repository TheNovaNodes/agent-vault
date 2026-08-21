# Архитектура Lab Vault

> Версия: 4.0.0 | Дата: 2026-06-14 | 
## Обзор

Lab Vault — **in-memory секретный менеджер** с Telegram-ботом интерфейсом. Главный принцип: секреты живут только в RAM, на диске — минимально необходимое (зашифрованный снапшот).

## Диаграмма компонентов

```
┌─────────────────────────────────────────────────────────────┐
│ main.go │
│ │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ │ Bot (TG) │───▶│ Store │◀───│Server (HTTP) │ │
│ │ FSM multi │ │ sync.RWMutex│ │ net/http │ │
│ │ HTML render│ │ sealedKey │ │ 13 endpoints │ │
│ │ │ │ audit │ │ │ │
│ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ │
│ │ │ │ │
│ ┌──────▼───────┐ ┌──────▼───────┐ ┌──────▼───────┐ │
│ │ Config │ │ SecretToken │ │ snapshot.enc │ │
│ │ YAML + mu │ │ Project │ │ JSON/blob │ │
│ │ +projects │ │ ProjectToken│ │ │ │
│ │ +AuditLog │ └──────────────┘ └──────────────┘ │
│ │ +cleanupStop│ │
│ └──────────────┘ ┌──────────────┐ │
│ │ AuditLogger │ ring buffer (1000) │
│ │ + mutex │ │
│ └──────────────┘ │
│ ┌──────────────┐ │
│ │ CleanupWorker│ background goroutine (1h interval) │
│ └──────────────┘ │
└─────────────────────────────────────────────────────────────┘

Внешние клиенты:
 ЗавЛаб ─────────▶ TG Bot ──────▶ POST /secrets ──────▶ Store
 POST /projects ──▶ Config
 Лаборант ───────▶ agent-vault-env ─▶ GET /access/:token ─▶ Store
 (env/ (single token → 1 secret)
 .env) (project token → N secrets)
```

## Слои и ответственности

### 1. Store (потокобезопасное хранилище)

**Файл:** `main.go`

**Ответственность:** CRUD операции с секретами в RAM. Поддерживает двухрежимную работу — sealed (значения зашифрованы в RAM) и legacy (plaintext).

```go
type Store struct {
 mu sync.RWMutex
 secrets map[string]*Secret
 sealedKey []byte // nil = legacy, non-nil = sealed mode
 audit *AuditLogger // nil = audit disabled
}
```

**Создание:** `NewStore(password string, audit ...*AuditLogger)` — variadic для обратной совместимости.

**Режимы работы:**
- **Sealed** (`VAULT_PASSWORD` задан): значения шифруются ChaCha20-Poly1305 перед записью в map, расшифровываются при чтении
- **Legacy** (`VAULT_PASSWORD` не задан): identity mode, значения хранятся как plaintext

**API:**
- `NewStore(vaultPassword)` — создание store, sealed mode если пароль задан
- `Set(name, value)` — создать/обновить (sealed: шифрует value)
- `Get(name)` — получить секрет (sealed: расшифровывает, возвращает копию)
- `Delete(name)` — удалить секрет
- `DeleteAll()` — killswitch
- `List()` — список всех секретов (sealed: расшифровывает каждый)
- `Count()` — количество секретов
- `isSealed()` — проверка режима
- `sealValue(plaintext)` — зашифровать значение (sealed: ChaCha20-Poly1305, legacy: identity)
- `unsealValue(sealed)` — расшифровать значение (sealed: decrypt, legacy: identity)

**Потокобезопасность:** `sync.RWMutex` — множественные читатели, эксклюзивный писатель.

**Sealed key derivation:** `deriveKey(password, fixed_salt)` → Argon2id → 32-byte key.
Фиксированная salt (`"agent-vault-sealed-key-salt-v1"`) — детерминистичный ключ для каждого инстанса.

### 2. Server (HTTP API)

**Файл:** `main.go`, строки 185-320

**Ответственность:** REST API для управления секретами.

**Эндпоинты (13):**

| Метод | Путь | Авторизация | Описание |
|-------|------|-------------|----------|
| GET | `/health` | Нет | Health check |
| GET | `/secrets` | Admin | Список секретов |
| POST | `/secrets` | Admin | Создать секрет |
| DELETE | `/secrets` | Admin | Killswitch |
| GET | `/export` | Admin | Экспорт JSON |
| GET | `/access/:token` | Token | Доступ по токену (single or project) |
| GET | `/secret/:name` | Admin | Чтение секрета по имени |
| DELETE | `/secret/:name` | Admin | Удалить секрет + токены |
| GET | `/projects` | Admin | Список проектов |
| POST | `/projects` | Admin | Создать проект |
| GET | `/project/:id` | Admin | Получить проект |
| DELETE | `/project/:id` | Admin | Удалить проект |
| GET | `/project-tokens/:project_id` | Admin | Токены проекта |
| POST | `/project-tokens/:project_id` | Admin | Создать токен проекта |
| GET | `/audit` | Admin | Аудит-лог (ring buffer) |
| DELETE | `/token/<hash>` | Admin | Отзыв токена по хешу |
| PUT | `/token/<hash>` | Admin | Ротация токена |

**Аутентификация:**
- Админ: `X-Vault-Token` header + `ConstantTimeCompare`
- Агент: токен из URL path, проверка в `config.SecretTokens`

**Таймауты:** ReadTimeout=5s, WriteTimeout=10s

**Graceful shutdown:** при получении SIGTERM/SIGINT — остановка cleanup worker, сохранение снапшота, завершение HTTP-сервера с 10-секундным таймаутом. Ошибка `ListenAndServe` логируется и вызывает `cancel()` контекста.

### 3. Bot (Telegram)

**Файл:** `main.go`, строки 330-700

**Ответственность:** Управление секретами через Telegram.

**Интерфейс botAPI:**
```go
type botAPI interface {
 Send(c tgbotapi.Chattable) (tgbotapi.Message, error)
 Request(c tgbotapi.Chattable) (*tgbotapi.APIResponse, error)
}
```

Интерфейс позволяет подменять реализацию в тестах (mock вместо *tgbotapi.BotAPI).

**FSM (Finite State Machine):**
```
[start] ──/start──▶ [main_menu]
[main_menu] ──«Создать»──▶ [waiting_name] ──text──▶ [waiting_value] ──text──▶ [main_menu] + token
[main_menu] ──«Проекты»──▶ [project_list]
[project_list] ──«Создать проект»──▶ [waiting_project_id]
[waiting_project_id] ──text──▶ [waiting_project_name]
[waiting_project_name] ──text──▶ [waiting_project_secrets]
[waiting_project_secrets] ──text──▶ [main_menu] + project created
[project_list] ──«📁 Название»──▶ [project_view]
[project_view] ──«Создать токен»──▶ project token generated
[project_view] ──«Добавить секрет»──▶ [add_secret:projectID] ──text──▶ [project_view]
[project_view] ──«Заменить секреты»──▶ [replace_secrets:projectID] ──text──▶ [project_view]
```

**Кнопки главного меню:**
- ➕ Создать — начать FSM создания секрета
- 📋 Секреты — список всех секретов
- 📁 Проекты — управление проектами
- 🗑 Удалить секреты — killswitch с подтверждением
- 🚫 Удалить токены — отзыв всех токенов

**Состояния FSM:**
- `stateWaitingProjectID` — ожидание ID проекта
- `stateWaitingProjectName` — ожидание имени проекта
- `stateWaitingProjectSecrets` — ожидание списка секретов (через запятую)
- `stateWaitingAddSecretName` — ожидание имени секрета для добавления в проект
- `stateWaitingReplaceSecrets` — ожидание нового списка секретов проекта

**Форматирование:** HTML (НЕ MarkdownV2 — был критический баг с экранированием).

### 4. Config (конфигурация)

**Файл:** `main.go`, строки 100-180

**Ответственность:** Загрузка/сохранение конфигурации из YAML.

```go
type Config struct {
 SnapshotPath string `yaml:"snapshot_path"`
 ListenAddr string `yaml:"listen_addr"`
 TGBotToken string `yaml:"tg_bot_token"`
 TGAdminID int64 `yaml:"tg_admin_id"`
 AdminToken string `yaml:"admin_token"`
 TokenTTLHours int `yaml:"token_ttl_hours"`
 SecretTokens map[string]*SecretToken `yaml:"secret_tokens"`
 Projects map[string]*Project `yaml:"projects"`
 ProjectTokens map[string]*ProjectToken `yaml:"project_tokens"`
 UseTLS bool `yaml:"use_tls"`
 TLSCertPath string `yaml:"tls_cert_path"`
 TLSKeyPath string `yaml:"tls_key_path"`
 AuditLog *AuditLogger `yaml:"-"`
 cleanupStop chan struct{} `yaml:"-"`
 mu sync.RWMutex `yaml:"-"`
}
```

**Приоритет конфигурации:** env vars > config.yaml > defaults

**Атомарное сохранение:** write to tmp + rename (crash-safe).

**Background Cleanup Worker:** запускается в `main()` через `cfg.startCleanupWorker(time.Hour)`. Периодически вызывает `cleanupRevokedTokens()` для удаления просроченных и отозванных токенов. Останавливается через `cfg.stopCleanupWorker()` при graceful shutdown.

### 5. AuditLogger (аудит-лог)

**Ответственность:** потокобезопасный ring buffer для логирования всех операций с секретами и токенами.

```go
type AuditLogger struct {
 mu sync.Mutex
 entries []AuditEntry
 maxSize int
}

type AuditEntry struct {
 Timestamp time.Time `json:"timestamp"`
 Action AuditAction `json:"action"`
 Target string `json:"target"`
 Actor string `json:"actor"`
 Details string `json:"details"`
}

type AuditAction string
```

**Действия:** `secret_create`, `secret_get`, `secret_delete`, `secret_update`, `secret_wipe`, `token_create`, `token_revoke`, `token_use`, `token_expire`, `access_granted`, `snapshot_save`, `snapshot_load`

**Размер:** по умолчанию 1000 записей (FIFO ring buffer). При переполнении старые записи перезаписываются.

**API:**
- `NewAuditLogger(maxSize)` — создание с заданным размером
- `Log(action, target, actor, details)` — добавление записи (thread-safe)
- `List()` — возврат всех записей от новых к старым

**Хранение:** только в RAM, не персистентится. Доступ через HTTP `GET /audit`.

### 6. SecretToken (токены доступа)

```go
type SecretToken struct {
 SecretName string `yaml:"secret_name"`
 Token string `yaml:"token"` // SHA-256 hex-хеш токена
 CreatedAt time.Time `yaml:"created_at"`
 ExpiresAt time.Time `yaml:"expires_at"` // zero = never
 Revoked bool `yaml:"revoked"`
}
```

**Генерация:** crypto/rand, 32 символа, alphanumeric charset.
**Хранение:** В config.yaml сохраняется SHA-256 хеш токена, не plain text.

**TTL:** Настраивается через `token_ttl_hours` (по умолчанию 720ч = 30 дней).

## Модель данных

```
Project ──1:N──▶ ProjectToken
 │ │
 │ ID (string, PK) │ ProjectID (string, FK)
 │ Name (string) │ Token (SHA-256 hex)
 │ SecretIDs [] │ CreatedAt, ExpiresAt, Revoked
 │ CreatedAt │
 │ │
 └── N:M ──────── Secret ──1:N──▶ SecretToken
 │
 ├── Name (string, PK)
 ├── Value (string, encrypted at rest)
 └── UpdatedAt (time.Time)
```

**Project** группирует секреты по `SecretIDs` (N:M — один секрет может быть в нескольких проектах).

**ProjectToken** даёт доступ ко всем секретам проекта через один вызов `/access/:token`.

**SecretToken** даёт доступ к одному конкретному секрету.

## Снапшот

**Путь:** `snapshot_path` в конфиге (по умолчанию `./snapshot.enc`).

### Форматы

| Режим | Формат snapshot | Шифрование |
|-------|----------------|------------|
| **Sealed** (VAULT_PASSWORD задан) | JSON `{name: {name, value(encrypted hex), updated_at}}` | Нет (значения уже зашифрованы в store) |
| **Legacy** (VAULT_PASSWORD не задан) | Бинарный `[salt(16)][nonce(12)][ciphertext]` | ChaCha20-Poly1305 всего JSON |

### Sealed mode

**Сохранение (shutdown):**
1. `json.Marshal(store.secrets)` — значения уже зашифрованы (hex)
2. `os.WriteFile(snapshotPath, data, 0600)`

**Загрузка (startup):**
1. `os.ReadFile(snapshotPath)`
2. Пробовать `json.Unmarshal(data, &secrets)` → успех: sealed format
3. При ошибке: fallback на `decryptSnapshot(data, password)` → legacy format
4. Legacy: расшифрованные секреты → `store.Set(name, value)` → перешифровка в sealed format
5. При следующем save → sealed format

### Legacy mode

**Сохранение:**
1. `json.Marshal(store.secrets)` — plaintext values
2. `encryptSnapshot(data, password)` → ChaCha20-Poly1305 → file

**Загрузка:**
1. `decryptSnapshot(data, password)` → JSON → `map[string]*Secret`

### Криптография

```go
func deriveKey(password string, salt []byte) []byte // Argon2id → 32-byte key
func encryptSnapshot(data, password) []byte // JSON → ChaCha20-Poly1305 → file
func decryptSnapshot(data, password) ([]byte, error) // file → ChaCha20-Poly1305 → JSON
```

**Sealed value format:** `[nonce(12)][ciphertext+tag]` → hex encode → хранить в `Secret.Value`

**Nonce:** Уникальный для каждого seal операции (crypto/rand). Хранится вместе с ciphertext.

## CLI-утилиты

### agent-vault-env

**Путь:** `cmd/agent-vault-env/main.go`

**Назначение:** Получение секретов по токену. Поддерживает оба типа токенов.

**Single secret token** → `export NAME=value`:
```bash
eval $(agent-vault-env -token <token>)
```

**Project token** → все секреты проекта:
```bash
eval $(agent-vault-env -token <project-token>)
```

**Запись в .env файл** (только для project tokens):
```bash
agent-vault-env -token <project-token> --write-to /path/to/.env
```

**Флаги:**
- `-token` — токен доступа (или `VAULT_TOKEN` env)
- `-addr` — адрес vault (default: `http://127.0.0.1:8301`)
- `-write-to` — путь к .env файлу для записи секретов проекта
- `-raw` — вывод в JSON вместо export-формата
- `-retries` — количество повторов при ошибках (default: 3)
- `-timeout` — таймаут запроса (default: 10s)

**Retry:** эконенциальный backoff при 5xx и 429.

**Форматы ответа:**
1. Single secret: `{"name": "...", "value": "...", "updated_at": "..."}`
2. Project token: `{"project": "...", "project_id": "...", "secrets": {...}}`

Тело читается один раз, затем парсится в оба формата.

### agent-vault-cli

**Путь:** `cmd/agent-vault-cli/main.go`

**Назначение:** Администрирование vault через командную строку (список, создание, удаление, экспорт).

**Команды:** `health`, `list`, `get`, `set`, `delete`, `wipe`, `export`, `version`

```bash
agent-vault-cli list
agent-vault-cli set db_pass secret123
agent-vault-cli export
```

## Project и ProjectToken (модели)

### Project

```go
type Project struct {
 ID string `json:"id" yaml:"-"`
 Name string `json:"name"`
 SecretIDs []string `json:"secret_ids" yaml:"secret_ids"`
 CreatedAt time.Time `json:"created_at" yaml:"created_at"`
}
```

- `ID` — уникальный идентификатор (slug), не сохраняется в YAML как ключ мапы
- `SecretIDs` — список имён секретов, входящих в проект (N:M)
- Хранится в `Config.Projects map[string]*Project`

### ProjectToken

```go
type ProjectToken struct {
 ProjectID string `json:"project_id" yaml:"project_id"`
 Token string `json:"token" yaml:"token"` // SHA-256 hash
 CreatedAt time.Time `json:"created_at" yaml:"created_at"`
 ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"` // zero = never
 Revoked bool `json:"revoked" yaml:"revoked"`
}
```

- При создании генерируется случайный токен (crypto/rand, 32 символа)
- В config.yaml сохраняется SHA-256 хеш, оригинал показывается один раз
- One-time: отзывается после первого успешного использования
- TTL наследуется от `token_ttl_hours` из конфигурации
- Хранится в `Config.ProjectTokens map[string]*ProjectToken`

## Безопасность

1. **Sealed Secrets (RAM encryption)** — значения секретов зашифрованы ChaCha20-Poly1305 в RAM при заданном `VAULT_PASSWORD`
2. **In-memory хранение** — секреты живут только в RAM
3. **ChaCha20-Poly1305 + Argon2id** — шифрование снапшота на диске (legacy) и sealed values в store
4. **SHA-256 хеширование токенов** — токены не хранятся в plain text в config.yaml
5. **ConstantTimeCompare** — защита от timing attack при сравнении токенов
6. **One-time токены** — инвалидация после первого использования (endpoint `/access/`)
7. **TTL токенов** — автоматическое истечение через N часов
8. **Бот с TG Admin ID** — бот отвечает только администратору (если задан `tg_admin_id`)
9. **Rate limiting** — 10 req/min на IP для `/access/:token`
10. **Blast radius** — утечка одного токена = утечка одного секрета
11. **Killswitch** — мгновенное удаление всех секретов
12. **HTML-эскапирование** — защита от XSS в именах и значениях секретов
13. **Audit Log** — полное логирование всех операций (CRUD секретов, создание/отзыв/использование токенов, доступ, snapshot save/load)

### Sealed key security

- Ключ НИКОГДА не записывается на диск
- Ключ генерируется из `VAULT_PASSWORD` через Argon2id с фиксированной salt при каждом старте
- При отсутствии `VAULT_PASSWORD` — legacy mode (plaintext в RAM)
- `Get()` возвращает копию, мутация не влияет на store

## Ограничения

- Нет индекса по проекту (O(n) при поиске токенов проекта)
- HTTP API без TLS (предполагается использование внутри приватной сети)
- Аудит-лог только в памяти (ring buffer, не персистентится, до 1000 записей)
- Project tokens не поддерживают частичный доступ — всё или ничего
- Cleanup worker interval фиксирован (1 час), не настраивается через конфиг
