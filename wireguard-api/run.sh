#!/bin/bash

# Скрипт для запуска WireGuard API

# Активируем виртуальное окружение если оно существует
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Запускаем API
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

