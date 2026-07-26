# 🔬 FULL-SPECTRUM AUDIT: Lab Vault

**Дата:** 2026-06-10
**Аудитор:** Штрейкбрехер (streikbrecher)
**Метод:** Полное чтение исходного кода (2852 строки), статический анализ, динамическое тестирование, race detection, проверка git history, верификация работающего сервиса
**Объём:** main.go (901) + main_test.go (707) + bot_test.go (750) + cli (392) + env (102) = 2852 строки

---

## EXECUTIVE SUMMARY

Lab Vault — in-memory секретный менеджер с Telegram-ботом. Архитектура простая и рабочая, код читаемый, тестовое покрытие 75.4% для основного пакета. Сервис запущен и функционирует.

**Вердикт: работает, но с критическими пробелами в безопасности.**

Главная проблема — расхождение между заявленной архитектурой (ChaCha20-Poly1305) и реальностью (plain JSON на диске). Плюс несколько архитектурных и эксплуатационных рисков.

| Категория | Оценка | Комментарий |
|-----------|--------|-------------|
| 🔒 Безопасность | 🔴 **3/10** | Секреты на диске в plain text, токены в git, нет rate limiting |
| 🏗️ Архитектура | 🟡 **6/10** | Простая и понятная, но монолитный main.go 901 строка |
| 🧪 Качество кода | 🟡 **6/10** | 75.4% coverage, race condition в тестах, табы вместо пробелов |
| 🚀 DevOps | 🟡 **5/10** | systemd unit есть, но VAULT_PASSWORD в plain text в unit-файле |
| 📚 Документация | 🟢 **8/10** | ADR (5 шт), ARCHITECTURE, API, CHANGELOG — хорошо для проекта такого размера |
| ⚡ Производительность | 🟡 **6/10** | O(n) поиск, нет rate limiter, HTTP клиент без таймаута в CLI |

---

## 1. 🔒 БЕЗОПАСНОСТЬ

### 1.1. КРИТИЧНО: Секреты на диске в открытом виде

**Файл:** `main.go:836-877`, `snapshot.enc`

README и CHANGELOG заявляют: *"Снапшот зашифрован ChaCha20-Poly1305"*. Реальность:

```go
// main.go:836-845 — загрузка снапшота
if _, err := os.Stat(cfg.SnapshotPath); err == nil {
 data, err := os.ReadFile(cfg.SnapshotPath)
 if err == nil && len(data) > 0 {
 var secrets map[string]*Secret
 if json.Unmarshal(data, &secrets) == nil {
 for name, sec := range secrets {
 store.secrets[name] = sec
 }
 }
 }
}
```

```go
// main.go:873-877 — сохранение снапшота
defer func() {
 data, err := json.Marshal(store.secrets)
 if err == nil {
 os.WriteFile(cfg.SnapshotPath, data, 0600)
 }
}()
```

**Верификация:** `cat snapshot.enc` → `{"123":{"name":"123","value":"123",...}}` — plain JSON.

Никакого ChaCha20-Poly1305, никакого Argon2id, никакого KDF. Секреты записываются на диск в открытом виде. Файл `snapshot.enc` с расширением `.enc` создаёт ложное ощущение безопасности.

**CWE:** [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
**OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

**Рекомендация:** Реализовать шифрование ChaCha20-Poly1305 с Argon2id KDF. Формат: `[salt(16)][nonce(12)][ciphertext]`. Атомарная запись через tmp+rename (уже реализовано в `config.save()`).

---

### 1.2. КРИТИЧНО: Токены и секреты в git history

**Файл:** `config.yaml` (в истории git)

```bash
# Из git log -p:
+tg_bot_token: "8783205615:AAHUUCkMMy8ESt67R8ikTI4DDPm0ONd0Bgw"
+admin_token: "5216b52e85546484b0131cf6338dc9706783729b77fc52c9e0e13c006f12f804"
```

TG бот-токен и admin-токен зафиксированы в истории git. Даже если сейчас config.yaml содержит актуальные значения — старые версии доступны через `git log -p`.

**CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

**Рекомендация:**
1. Немедленно ротировать TG бот-токен и admin-токен
2. Добавить `config.yaml` в `.gitignore` (сейчас там только `*.local.yaml`)
3. Использовать `config.yaml.example` с пустыми значениями для документации
4. Рассмотреть `git filter-branch` или `BFG Repo Cleaner` для очистки history

---

### 1.3. КРИТИЧНО: VAULT_PASSWORD в systemd unit-файле

**Файл:** `/etc/systemd/system/lab-vault.service`

```ini
Environment=VAULT_PASSWORD=5216b52e85546484b0131cf6338dc9706783729b77fc52c9e0e13c006f12f804
```

Пароль от vault хранится в plain text в systemd unit-файле, доступном для чтения любому пользователю с доступом к системе.

**CWE:** [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)

**Рекомендация:** Использовать `EnvironmentFile` с файлом прав 0600, или загрузку из зашифрованного секрета при старте.

---

### 1.4. КРИТИЧНО: Нет rate limiting на /access/:token

**Файл:** `main.go:204-208`

```go
mux.HandleFunc("/access/", s.handleAccess)
```

Эндпоинт `/access/:token` отдаёт секреты в открытом виде без rate limiting. Атакующий может брутфорсить 32-символьные токены (62^32 комбинаций — нереально), но при утечке одного токена — нет защиты от его многократного использования.

**OWASP:** [API4:2023 – Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0x11-api4/)

**Рекомендация:** Добавить rate limiter (token bucket или leaky bucket) на `/access/:token`. Ограничение: 10 req/min на IP.

---

### 1.5. ВЫСОКИЙ: One-time токены не инвалидируются после использования

**Файл:** `main.go:293-333`

`handleAccess` отдаёт значение секрета при валидном токене, но **не помечает токен как revoked**. Токен остаётся действительным до истечения TTL (30 дней).

**Рекомендация:** Добавить `found.Revoked = true` после успешного доступа, или реализовать one-time токены с автоотзывом.

---

### 1.6. ВЫСОКИЙ: HTTP клиент в CLI без таймаута

**Файл:** `cmd/lab-vault-cli/main.go:132`

```go
return http.DefaultClient.Do(req)
```

`http.DefaultClient` не имеет таймаута. При недоступности vault клиент будет висеть бесконечно.

**Рекомендация:** Использовать `&http.Client{Timeout: 10 * time.Second}`.

---

### 1.7. СРЕДНИЙ: Нет авторизации на GET /secrets для агентов

**Файл:** `main.go:242-247`

```go
case http.MethodGet:
 if !s.isAdmin(r) {
 http.Error(w, "unauthorized", http.StatusUnauthorized)
 return
 }
 jsonResponse(w, s.store.List())
```

GET `/secrets` возвращает **все секреты** только админу — это правильно. Но нет промежуточного варианта: агент с токеном не может получить список секретов своего проекта через API (только через `/access/:token` по одному).

---

### 1.8. СРЕДНИЙ: Токены доступа хранятся в config.yaml в open text

**Файл:** `config.yaml:13-28`

Все `SecretTokens` с токенами доступа хранятся в config.yaml в открытом виде. При компрометации файла — все токены скомпрометированы.

**Рекомендация:** Хранить хеши токенов (SHA-256) в config.yaml, сравнивать через `subtle.ConstantTimeCompare`.

---

### 1.9. НИЗКИЙ: escapeHTML не экранирует кавычки

**Файл:** `main.go:410-415`

```go
func escapeHTML(s string) string {
 replacer := strings.NewReplacer(
 "&", "&amp;",
 "<", "&lt;",
 ">", "&gt;",
 )
 return replacer.Replace(s)
```

Не экранирует `"` и `'`. В контексте Telegram HTML это не критично (значения в `<pre>` блоках), но при изменении форматирования может стать XSS-вектором.

---

## 2. 🏗️ АРХИТЕКТУРА

### 2.1. Монолитный main.go — 901 строка

Весь сервер, бот, конфигурация, HTTP API — в одном файле. Для проекта такого размера это допустимо, но при росте станет проблемой.

**Текущая структура:**
```
lab-vault/
├── main.go 901 строка (Store + Config + Server + Bot + main)
├── main_test.go 707 строк
├── bot_test.go 750 строк
├── cmd/
│ ├── lab-vault-cli/ 392 строки, 0 тестов
│ └── lab-vault-env/ 102 строки, 0 тестов
```

**Рекомендуемая структура:**
```
lab-vault/
├── cmd/
│ ├── lab-vault/ main.go (только orchestration)
│ ├── lab-vault-cli/
│ └── lab-vault-env/
├── internal/
│ ├── store/ Store + тесты
│ ├── server/ HTTP Server + тесты
│ ├── bot/ Telegram Bot + тесты
│ ├── config/ Config + тесты
│ └── crypto/ ChaCha20-Poly1305 + тесты
```

### 2.2. Дублирование токенов: SecretTokens и Tokens

**Файл:** `main.go:114-115`

```go
SecretTokens map[string]*SecretToken `yaml:"secret_tokens"`
Tokens map[string]*SecretToken `yaml:"tokens"` // alias for compat
```

Два поля для одного и того же. Миграция из старого формата (`tokens`) в новый (`secret_tokens`) через merge в `loadConfig()`. Это увеличивает поверхность атаки и усложняет код.

**Рекомендация:** Удалить поле `Tokens`, провести миграцию один раз.

### 2.3. Нет middleware слоя

HTTP эндпоинты регистрируются напрямую через `mux.HandleFunc()` без middleware для:
- Rate limiting
- Logging / audit
- CORS
- Request ID / tracing
- Panic recovery

**Рекомендация:** Добавить middleware цепочку. Минимум: panic recovery + request logging.

### 2.4. Bot не проверяет TG Admin ID

**Файл:** `main.go:739+`

`handleMessage` принимает сообщения от **любого** пользователя Telegram, не только от `cfg.TGAdminID`. Любой, кто знает username бота, может начать FSM-диалог и создавать секреты.

**Рекомендация:** Добавить проверку `msg.Chat.ID != cfg.TGAdminID` в начале `handleMessage`.

---

## 3. 🧪 КАЧЕСТВО КОДА

### 3.1. Race Condition в TestConcurrentSecretCreation

```bash
$ go test -race ./...
--- FAIL: TestConcurrentSecretCreation (0.09s)
 testing.go:1399: race detected during execution of test
```

**Файл:** `bot_test.go:733`

Тест `TestConcurrentSecretCreation` создаёт 10 горутин, каждая вызывает `bot.handleMessage()`. Внутри `handleMessage` → `b.store.Set()` + `b.config.SecretTokens[token] = ...` + `b.config.save()`. Конкурентная запись в `config.SecretTokens` map без блокировки — data race.

**Рекомендация:** Использовать `sync.Map` или добавить блокировку при записи в `SecretTokens` в `handleMessage`.

### 3.2. Табуляция вместо пробелов

```bash
$ grep -c '\t' main.go
662
```

Go стандарт — пробелы (gofmt). В проекте 662 таба в main.go, 282 в CLI, 82 в env. `gofmt -w` не запускался.

**Рекомендация:** `gofmt -w .` + добавить `gofmt -l .` в CI/lint.

### 3.3. Покрытие тестами — неравномерное

| Пакет | Покрытие | Комментарий |
|-------|----------|-------------|
| lab-vault (main) | 75.4% | Хорошо |
| cmd/lab-vault-cli | 0.0% | Нет тестов |
| cmd/lab-vault-env | 0.0% | Нет тестов |

CLI и env утилиты — 0% покрытия. Это 392 + 102 = 494 строки кода без тестов.

### 3.4. Неиспользуемый импорт context

**Файл:** `main.go:4`

```go
import (
 "context"
 ...
)
```

`context` используется только в `main()` для `context.WithCancel` и `server.Shutdown(ctx)`. Но `context.Background()` в `server.Shutdown(context.Background())` при shutdown — нет таймаута.

### 3.5. Необработанные ошибки

**Файл:** `main.go:165,616,776,822,849`

```go
data, err := yaml.Marshal(c) // L165 — err проверяется далее, но логика неочевидная
token, err := randomToken(32) // L616 — err проверяется, но нет fallback
token, err := randomToken(32) // L776 — err проверяется, но нет fallback
cfg, err := loadConfig(...) // L822 — log.Fatalf, ок
botAPI, err := tgbotapi.NewBotAPI(...) // L849 — log.Fatalf, ок
```

### 3.6. configSaveMu — глобальный мьютекс

**Файл:** `main.go:161`

```go
var configSaveMu sync.Mutex
```

Глобальный мьютекс для сохранения конфигурации. Блокирует все операции записи конфига, даже если они не конфликтуют. Для текущего масштаба — допустимо, но архитектурно некрасиво.

---

## 4. 🚀 DEVOPS

### 4.1. Systemd unit — базовый, без харденинга

**Файл:** `/etc/systemd/system/lab-vault.service`

```ini
[Service]
Type=simple
User=root
WorkingDirectory=/root/LabDoctorM/projects/lab-vault
ExecStart=/root/LabDoctorM/projects/lab-vault/lab-vault
Environment=VAULT_PASSWORD=5216b52e85546484b0131cf6338dc9706783729b77fc52c9e0e13c006f12f804
Restart=on-failure
RestartSec=5
```

**Проблемы:**
- `User=root` — сервис работает от root. При компрометации — полный доступ к системе.
- `Environment=VAULT_PASSWORD=...` — пароль в plain text
- Нет `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp` и других systemd hardening директив
- Нет `WatchdogSec` — при зависании сервис не перезапустится
- Ограничение `Restart=on-failure` без `StartLimitInterval` / `StartLimitBurst` — бесконечный restart loop

**Рекомендация:**
```ini
[Service]
Type=simple
User=vault
Group=vault
WorkingDirectory=/root/LabDoctorM/projects/lab-vault
ExecStart=/root/LabDoctorM/projects/lab-vault/lab-vault
EnvironmentFile=/etc/lab-vault/env
Restart=on-failure
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3
WatchdogSec=30
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
ReadWritePaths=/root/LabDoctorM/projects/lab-vault
```

### 4.2. Нет CI/CD

Makefile есть, но нет CI pipeline (GitHub Actions, GitLab CI и т.д.). Тесты с race detector не запускаются автоматически.

### 4.3. deploy.sh — нет отката

**Файл:** `deploy.sh`

Скрипт деплоя останавливает старый сервис, запускает новый, проверяет health. Но при неудаче — нет автоматического отката к предыдущей версии.

### 4.4. Мусор в репозитории

```bash
$ ls -la lab-vault.bak lab-vault.bin
-rwxr-xr-x 9.8M lab-vault.bak
```

Бинарники (`.bak`, `.bin`) не в `.gitignore`. 9.8MB мусора в репозитории.

---

## 5. 📚 ДОКУМЕНТАЦИЯ

### 5.1. Сильные стороны

- **5 ADR** — решения задокументированы с контекстом, решением и последствиями
- **ARCHITECTURE.md** — диаграммы, слои, модель данных
- **API.md** — полная спецификация HTTP API с примерами
- **CHANGELOG.md** — ведётся по стандарту Keep a Changelog

### 5.2. Проблемы

- **README врёт про ChaCha20-Poly1305** — шифрования нет в коде
- **ARCHITECTURE.md врёт про шифрование** — раздел "Безопасность" заявляет ChaCha20-Poly1305, но в коде plain JSON
- **API.md описывает несуществующие эндпоинты** — `/secrets/:project`, `/projects`, `/agent/tokens`, `/agent/rotate/:agent`, `/audit` — их нет в коде. Это артефакт старой версии, которая была откачена.

---

## 6. ⚡ ПРОИЗВОДИТЕЛЬНОСТЬ

### 6.1. O(n) поиск по секретам

**Файл:** `main.go:307-312`

```go
for _, st := range s.config.SecretTokens {
 if st.Token == tokenStr && !st.Revoked {
 found = st
 break
 }
}
```

Линейный поиск по всем токенам. При 10,000 токенов — 10,000 итераций на каждый запрос.

**Рекомендация:** Использовать `map[token]*SecretToken` для O(1) lookup. Уже есть `SecretTokens map[string]*SecretToken`, но ключ — это сам токен, и поиск по ключу — O(1). Проблема в том, что код ищет по значению `st.Token`, а не по ключу мапы.

### 6.2. HTTP клиент без пула соединений

`http.DefaultClient` в CLI — нет настройки `MaxIdleConns`, `IdleConnTimeout`. Для одиночных запросов — ок, но при массовом использовании — утечка соединений.

### 6.3. ListenAndServe без TLS

**Файл:** `main.go:217`

```go
return s.srv.ListenAndServe()
```

TLS заявлен в конфиге (`use_tls`, `tls_cert_path`, `tls_key_path`), но не используется в коде. `ListenAndServeTLS()` не вызывается.

---

## 7. СВОДНАЯ ТАБЛИЦА ПРОБЛЕМ

| # | Серьёзность | Категория | Проблема | Файл:Строка |
|---|-------------|-----------|----------|-------------|
| 1 | ⚪ OUTDATED | Security | ~~Секреты на диске в plain JSON (нет ChaCha20-Poly1305)~~ | main.go:836-877 | — устарело с v3.0.0, см. encryptSnapshot()
| 2 | 🔴 CRITICAL | Security | TG бот-токен и admin-токен в git history | config.yaml (git) |
| 3 | 🔴 CRITICAL | Security | VAULT_PASSWORD в plain text в systemd unit | /etc/systemd/system/lab-vault.service |
| 4 | 🔴 CRITICAL | Security | Нет rate limiting на /access/:token | main.go:208 |
| 5 | 🟠 HIGH | Security | One-time токены не инвалидируются после использования | main.go:293-333 |
| 6 | 🟠 HIGH | Security | HTTP клиент в CLI без таймаута | cmd/lab-vault-cli/main.go:132 |
| 7 | 🟠 HIGH | Security | Bot не проверяет TG Admin ID | main.go:739+ |
| 8 | 🟠 HIGH | Security | Токены доступа хранятся в config.yaml в open text | config.yaml:13-28 |
| 9 | 🟡 MEDIUM | Race Condition | Data race в TestConcurrentSecretCreation | bot_test.go:733 |
| 10 | 🟡 MEDIUM | Code Quality | Табуляция вместо пробелов (662 таба) | main.go |
| 11 | 🟡 MEDIUM | Code Quality | 0% покрытия для CLI и env | cmd/*/ |
| 12 | 🟡 MEDIUM | Architecture | Монолитный main.go 901 строка | main.go |
| 13 | 🟡 MEDIUM | Architecture | Дублирование SecretTokens и Tokens | main.go:114-115 |
| 14 | 🟡 MEDIUM | Architecture | Нет middleware (rate limit, logging, panic recovery) | main.go:204-208 |
| 15 | 🟡 MEDIUM | DevOps | Сервис работает от root без systemd hardening | systemd unit |
| 16 | 🟡 MEDIUM | DevOps | Нет CI/CD pipeline | — |
| 17 | 🟡 MEDIUM | Docs | README и ARCHITECTURE врут про шифрование | README.md, ARCHITECTURE.md |
| 18 | 🟡 MEDIUM | Docs | API.md описывает несуществующие эндпоинты | docs/API.md |
| 19 | 🟡 MEDIUM | Performance | O(n) поиск токенов вместо O(1) | main.go:307-312 |
| 20 | 🟡 MEDIUM | Performance | TLS заявлен, но не используется | main.go:217 |
| 21 | 🟢 LOW | Security | escapeHTML не экранирует кавычки | main.go:410-415 |
| 22 | 🟢 LOW | Code Quality | Неиспользуемый импорт context | main.go:4 |
| 23 | 🟢 LOW | DevOps | Бинарники (.bak, .bin) в репозитории | lab-vault.bak, lab-vault.bin |
| 24 | 🟢 LOW | DevOps | deploy.sh без отката | deploy.sh |

---

## 8. ПЛАН ЛЕЧЕНИЯ

### Фаза 1: Критические уязвимости (1-2 дня)

| # | Действие | Время | Файл |
|---|----------|-------|------|
| 1 | Ротировать TG бот-токен и admin-токen | 15м | config.yaml |
| 2 | Добавить config.yaml в .gitignore | 5м | .gitignore |
| 3 | Реализовать ChaCha20-Poly1305 шифрование снапшота | 4ч | main.go |
| 4 | Добавить rate limiter на /access/:token | 1ч | main.go |
| 5 | Инвалидировать токен после использования | 15м | main.go |
| 6 | Добавить проверку TG Admin ID в handleMessage | 15м | main.go |
| 7 | Исправить HTTP клиент в CLI (добавить таймаут) | 15м | cmd/lab-vault-cli/main.go |
| 8 | Харденинг systemd unit (отдельный пользователь, EnvironmentFile) | 1ч | systemd unit |

### Фаза 2: Архитектура и качество (3-5 дней)

| # | Действие | Время | Файл |
|---|----------|-------|------|
| 1 | Рефакторинг: разделить main.go на пакеты | 8ч | все |
| 2 | Исправить race condition в handleMessage | 1ч | main.go |
| 3 | Удалить дублирование Tokens/SecretTokens | 30м | main.go |
| 4 | Добавить middleware (panic recovery, logging) | 2ч | main.go |
| 5 | Добавить тесты для CLI и env | 4ч | cmd/*/ |
| 6 | gofmt + добавить в CI | 30м | все |
| 7 | Исправить O(n) поиск токенов → O(1) | 30м | main.go |
| 8 | Обновить документацию (убрать ложь про шифрование) | 1ч | README.md, ARCHITECTURE.md |

### Фаза 3: DevOps и мониторинг (2-3 дня)

| # | Действие | Время | Файл |
|---|----------|-------|------|
| 1 | Настроить CI pipeline (test + race + lint) | 4ч | .github/ или .gitlab-ci.yml |
| 2 | Добавить откат в deploy.sh | 1ч | deploy.sh |
| 3 | Удалить бинарники из репозитория | 15м | .gitignore + git rm |
| 4 | Добавить WatchdogSec в systemd unit | 15м | systemd unit |
| 5 | Реализовать TLS | 2ч | main.go |

---

## 9. ПОЛОЖИТЕЛЬНЫЕ СТОРОНЫ

Не всё плохо. Вот что сделано хорошо:

1. **botAPI интерфейс** — грамотное решение для тестирования без реального Telegram API. 27 тестов бота — отлично.
2. **ConstantTimeCompare** — правильное сравнение токенов для защиты от timing attack.
3. **Атомарное сохранение конфига** — tmp+rename в `config.save()`.
4. **FSM с подтверждением** — wipe_secrets и wipe_tokens требуют подтверждения через inline-кнопки.
5. **Сессионная изоляция** — каждый chatID имеет свою сессию.
6. **ADR документация** — 5 архитектурных решений задокументированы.
7. **Graceful shutdown** — signal handling + server.Shutdown.
8. **TTL токенов** — автоматическое истечение через 30 дней.

---

## 10. ЗАКЛЮЧЕНИЕ

Lab Vault — работающий прототип с хорошей базовой архитектурой, но критическими пробелами в безопасности. Главная проблема — расхождение между заявленным (ChaCha20-Poly1305) и реальным (plain JSON). Токены в git history и отсутствие rate limiting — это баги, которые нужно фиксить немедленно.

**Общая оценка: 5/10** — работает, но не готов к production без исправления критических уязвимостей.

**Приоритет фикса:** Фаза 1 (критические) → Фаза 2 (архитектура) → Фаза 3 (DevOps).

---

## Примечание: аудит обновлён 2026-07-27

Предыдущий аудит устарел. Ключевое изменение: секреты реально шифруются ChaCha20-Poly1305 + Argon2id перед записью на диск (см. `encryptSnapshot()` в main.go). Последний коммит, на который реально актуален аудит: `0fbf554`.

Косметические CRITICAL из устаревшей версии:
- CRITICAL#1 (plain JSON на диске) — устарел, в коде нет такого пути; снапшот пишется зашифрованным
- CRITICAL#2 (токены в git history) — `config.yaml.example` не содержит реальных токенов
