# ADR-002: Интерфейс botAPI для тестирования

## Статус
Accepted

## Контекст

Telegram-бот использует `tgbotapi.BotAPI` для отправки сообщений.
Прямое использование конкретного типа делает тестирование невозможным
без реального Telegram API.

## Решение

Введён минимальный интерфейс:
```go
type botAPI interface {
 Send(c tgbotapi.Chattable) (tgbotapi.Message, error)
 Request(c tgbotapi.Chattable) (*tgbotapi.APIResponse, error)
}
```

`tgbotapi.BotAPI` реализует этот интерфейс неявно.

В тестах используется mock:
```go
type mockBotAPI struct {
 sent []tgbotapi.Chattable
}
```

## Последствия

**Положительные:**
- 27 тестов бота без реального Telegram API
- Быстрые тесты (нет сетевых вызовов)
- Проверка логики FSM, callback handler, форматирования

**Отрицательные:**
- Интерфейс покрывает только 2 метода (Send, Request)
- При добавлении новых методов tgbotapi — нужно расширять интерфейс
