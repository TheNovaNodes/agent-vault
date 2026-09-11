# ADR-004: Использование Request() вместо Send() для callback answer

## Статус
Accepted

## Контекст

При нажатии inline-кнопки Telegram ожидает callback answer.
Изначально использовался `Send(CallbackConfig)`:
```go
bot.api.Send(tgbotapi.NewCallback(cb.ID, ""))
```

В tgbotapi v5 `Send(CallbackConfig)` возвращает `(Message, error)`,
но Telegram API для callback answer возвращает `bool`, не `Message`.
Это приводило к ошибке парсинга ответа.

## Решение

Замена на `Request()`:
```go
bot.api.Request(tgbotapi.NewCallback(cb.ID, ""))
```

`Request()` возвращает `(*tgbotapi.APIResponse, error)` и корректно
обрабатывает `bool` ответ от Telegram.

## Последствия

**Положительные:**
- Callback answers работают корректно
- Нет ошибок парсинга ответа Telegram

**Отрицательные:**
- Нет
