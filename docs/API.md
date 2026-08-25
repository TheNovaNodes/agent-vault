# Lab Vault HTTP API

> Версия: 4.0.0 | Базовый URL: `http://127.0.0.1:8301` | Обновлено: 2026-06-14

## Аутентификация

Два типа доступа:

**Админ:** Header `X-Vault-Token: <admin-token>`
- Полный доступ к управлению секретами

**Токен доступа:** URL path `GET /access/:token`
- One-time токен для получения конкретного секрета
- Rate limited: 10 req/min на IP

## Эндпоинты

### Health Check

```
GET /health
```

**Авторизация:** не требуется.

**Ответ:**
```json
{
 "status": "ok",
 "secrets": 5,
 "uptime": "2h15m30s"
}
```

**Коды:**
- 200 — сервис работает

---

### Список секретов

```
GET /secrets
```

**Авторизация:** Admin (X-Vault-Token header).

**Ответ:**
```json
[
 {
 "name": "smtp_password",
 "value": "secret123",
 "updated_at": "2026-06-10T12:30:00Z"
 }
]
```

**Коды:**
- 200 — успешно
- 401 — не авторизован (отсутствует/неверный токен)

---

### Создать/обновить секрет

```
POST /secrets
Content-Type: application/json
X-Vault-Token: <admin-token>
```

**Тело запроса:**
```json
{
 "name": "smtp_password",
 "value": "secret123"
}
```

**Ответ:**
```json
{
 "status": "created",
 "name": "smtp_password"
}
```

**Коды:**
- 200 — успешно создано/обновлено
- 400 — отсутствует name или value
- 403 — запрещено (пустой admin token)
- 401 — не авторизован

---

### Удалить все секреты (killswitch)

```
DELETE /secrets
X-Vault-Token: <admin-token>
```

**Ответ:**
```json
{
 "status": "deleted"
}
```

**Коды:**
- 200 — все секреты удалены
- 403 — запрещено

**Внимание:** Необратимая операция. В боте требуется подтверждение.

---

### Экспорт секретов

```
GET /export
X-Vault-Token: <admin-token>
```

**Заголовки ответа:**
```
Content-Type: application/json
Content-Disposition: attachment; filename="vault-export.json"
```

**Ответ:**
```json
{
 "smtp_password": "secret123",
 "api_key": "abc123"
}
```

**Коды:**
- 200 — успешно
- 401 — не авторизован

---

### Доступ по токену

```
GET /access/:token
```

**Авторизация:** Токен в URL path.

**Ответ:**
```json
{
 "name": "smtp_password",
 "value": "secret123",
 "updated_at": "2026-06-10T12:30:00Z"
}
```

**Коды:**
- 200 — секрет найден
- 400 — токен не указан
- 403 — токен неверный, отозван или истёк
- 404 — секрет не найден

**Проверки токена:**
1. Токен существует в `config.SecretTokens`
2. `Revoked == false`
3. `ExpiresAt` не истекло (если задано)
4. Rate limit: 10 req/min на IP

**One-time:** Токен автоматически отзывается после первого успешного использования.

## Проекты

### Получить все проекты

```
GET /projects
X-Vault-Token: <admin-token>
```

**Ответ:**
```json
[
 {
 "id": "myapp",
 "name": "My App",
 "secret_ids": ["db_pass", "api_key"],
 "created_at": "2026-06-12T10:00:00Z"
 }
]
```

**Коды:** 200, 401

---

### Создать проект

```
POST /projects
Content-Type: application/json
X-Vault-Token: <admin-token>
```

**Тело:**
```json
{"id": "myapp", "name": "My App"}
```

**Ответ:**
```json
{"status": "created", "id": "myapp", "name": "My App"}
```

**Коды:** 200, 400, 409 (уже существует), 401

---

### Получить проект

```
GET /project/:id
X-Vault-Token: <admin-token>
```

**Ответ:**
```json
{
 "id": "myapp",
 "name": "My App",
 "secret_ids": ["db_pass", "api_key"],
 "secrets": [
 {"name": "db_pass", "updated_at": "2026-06-10T12:30:00Z"},
 {"name": "api_key", "updated_at": "2026-06-11T08:15:00Z"}
 ],
 "created_at": "2026-06-12T10:00:00Z"
}
```

**Коды:** 200, 404

---

### Удалить проект

```
DELETE /project/:id
X-Vault-Token: <admin-token>
```

Удаляет проект и все его токены.

**Коды:** 200, 404

---

### Список токенов проекта

```
GET /project-tokens/:project_id
X-Vault-Token: <admin-token>
```

**Ответ:** массив `ProjectToken` объектов.

---

### Создать токен проекта

```
POST /project-tokens/:project_id
X-Vault-Token: <admin-token>
```

**Ответ:**
```json
{
 "token": "abc123...xyz",
 "project_id": "myapp",
 "expires_at": "2026-07-12T10:00:00Z"
}
```

**Коды:** 200, 404

Оригинал токена показывается только один раз. В config.yaml сохраняется SHA-256 хеш.

---

### Доступ по project token

```
GET /access/:token
```

**Ответ (project token):**
```json
{
 "project": "My App",
 "project_id": "myapp",
 "secrets": {
 "db_pass": {"name": "db_pass", "value": "secret123", "updated_at": "2026-06-10T12:30:00Z"},
 "api_key": {"name": "api_key", "value": "key456", "updated_at": "2026-06-11T08:15:00Z"}
 }
}
```

**Коды:** 200, 403, 404

Project token — одноразовый, отзывается بعد первого использования.

---

### Аудит-лог

```
GET /audit
X-Vault-Token: <admin-token>
```

**Авторизация:** Admin.

**Ответ:** массив записей аудита (от новых к старым, до 1000 записей):
```json
[
 {
 "timestamp": "2026-06-14T10:30:00Z",
 "action": "token_create",
 "target": "smtp_password",
 "actor": "api",
 "details": "rotated from a1b2c3d4"
 },
 {
 "timestamp": "2026-06-14T10:25:00Z",
 "action": "secret_get",
 "target": "smtp_password",
 "actor": "token:a1b2...",
 "details": ""
 }
]
```

**Коды:**
- 200 — успешно (пустой массив `[]` если аудит отключён)

**Действия (action):** `secret_create`, `secret_get`, `secret_delete`, `secret_update`, `secret_wipe`, `token_create`, `token_revoke`, `token_use`, `token_expire`, `access_granted`, `snapshot_save`, `snapshot_load`

---

### Отзыв токена по хешу

```
DELETE /token/<hash>
X-Vault-Token: <admin-token>
```

**Авторизация:** Admin.

Отзывает токен (SecretToken или ProjectToken) по SHA-256 хешу. Токен помечается как revoked и немедленно удаляется из store через `cleanupRevokedTokens`.

**Ответ:**
```json
{"status": "revoked"}
```

**Коды:**
- 200 — токен отозван
- 401 — не авторизован
- 404 — токен не найден

---

### Ротация токена

```
PUT /token/<hash>
X-Vault-Token: <admin-token>
```

**Аторизация:** Admin.

**Атомарная операция:** отзывает старый токен + создаёт новый с тем же таргетом (секрет или проект). Тип токена (SecretToken/ProjectToken) определяется автоматически.

**Ответ:**
```json
{
 "token": "new_random_token_32chars",
 "expires_at": "2026-07-14T10:30:00Z",
 "rotated": true
}
```

Оригинал нового токена показывается **только один раз** — в этом ответе.

**Коды:**
- 200 — успешно, новый токен в теле
- 401 — не авторизован
- 404 — токен не найден или уже отозван
- 500 — ошибка генерации токена

---

## Токены доступа

### Создание токена (через бот)

При создании секрета через TG-бот токен генерируется автоматически.
Вручную — через кнопку "🔑 Создать токен" в карточке секрета.

### Структура токена

```go
type SecretToken struct {
 SecretName string // Имя секрета
 Token string // SHA-256 hex-хеш (64 hex-символа)
 CreatedAt time.Time // Дата создания
 ExpiresAt time.Time // Дата истечения (zero = бессрочно)
 Revoked bool // Отозван
}
```

### Генерация токена

```go
token, _ := randomToken(32) // crypto/rand, 32 символа
hash := hashToken(token) // SHA-256 → 64 hex-символа
```

В config.yaml хранится **хеш** токена, не оригинал. Оригинал показывается только один раз при создании.

### TTL

По умолчанию: 720 часов (30 дней). Настраивается через `token_ttl_hours` в config.yaml.

### Отзыв токенов

- Через API: `DELETE /token/<hash>` — отзыв конкретного токена по хешу
- Через бот: "🚫 Отозвать все токены" в карточке секрета
- Через бот: "🚫 Удалить токены" в главном меню (все токены)
- Автоматически: при удалении секрета, при использовании (one-time), background cleanup worker

### Ротация токенов

```
PUT /token/<hash> → {token: "new_token", rotated: true}
```

Атомарная операция: старый отзывается, новый создаётся с тем же таргетом. TTL наследуется от `token_ttl_hours`.

## Примеры использования

### curl

```bash
# Health check
curl http://127.0.0.1:8301/health

# Создать секрет
curl -X POST http://127.0.0.1:8301/secrets \
 -H "X-Vault-Token: <admin-token>" \
 -H "Content-Type: application/json" \
 -d '{"name":"api_key","value":"secret456"}'

# Получить по токену
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8301/access

# Экспорт
curl http://127.0.0.1:8301/export \
 -H "X-Vault-Token: <admin-token>"

# Killswitch
curl -X DELETE http://127.0.0.1:8301/secrets \
 -H "X-Vault-Token: <admin-token>"

# Отозвать токен по хешу
curl -X DELETE http://127.0.0.1:8301/token/<hash> \
 -H "X-Vault-Token: <admin-token>"

# Ротация токена (отозвать старый + создать новый)
curl -X PUT http://127.0.0.1:8301/token/<hash> \
 -H "X-Vault-Token: <admin-token>"

# Аудит-лог
curl http://127.0.0.1:8301/audit \
 -H "X-Vault-Token: <admin-token>"
```

### agent-vault-env

```bash
# Получить секрет в env (single secret)
eval $(agent-vault-env -token <token>)

# Получить все секреты проекта в env (project token)
eval $(agent-vault-env -token <project-token>)

# Записать секреты проекта в .env файл
agent-vault-env -token <project-token> --write-to /path/to/.env

# Raw JSON output
agent-vault-env -token <token> --raw

# Custom vault address
agent-vault-env -addr http://127.0.0.1:8301 -token <token>
```

### agent-vault-cli

```bash
# Health check
agent-vault-cli health

# Список секретов
agent-vault-cli list

# Получить секрет
agent-vault-cli get api_key

# Создать/обновить секрет
agent-vault-cli set api_key secret123

# Удалить секрет
agent-vault-cli delete api_key

# Экспорт
agent-vault-cli export

# Killswitch
agent-vault-cli wipe
```
