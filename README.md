---
description: "lab-vault — README"
type: readme
last_reviewed: 2026-06-21
last_code_change: 2026-06-21
status: active
---

# 🔐 Lab Vault

![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white)
![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)

> **Владелец:** DoctorM&Ai | **Статус:** active | **Версия:** 3.0.0

Lab Vault — это защищенное и потокобезопасное хранилище секретов (API keys, пароли, токены) для AI-агентов.
Проект позволяет администраторам управлять секретами через интуитивный интерфейс Telegram-бота (используя FSM-диалоги), группировать их в проекты и выдавать одноразовые токены с ограничением времени жизни (TTL) для AI-агентов.
Секреты защищены передовым шифрованием на диске (ChaCha20-Poly1305 + Argon2id).

## 📚 Документация для разработчиков

Техническая документация, полезная для онбординга новых участников команды:

- 🏗️ **[Архитектура проекта и Потоки данных](docs/architecture.md)** — описание компонентов, шифрования, хеширования токенов и FSM логики.
- 🔌 **[API Reference](docs/api-reference.md)** — документация по HTTP-эндпоинтам, санитизации и rate limiting.
- 🚀 **[Развертывание (Deployment)](docs/deployment.md)** — инструкции по деплою (включая Makefile и systemd), переменные окружения и настройка.

## Краткий быстрый старт
```bash
make build
cp config.yaml.example config.yaml
VAULT_PASSWORD="master-password" ./lab-vault -config config.yaml
```
Подробности доступны в [инструкции по развертыванию](docs/deployment.md).
