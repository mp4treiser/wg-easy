# Быстрый старт с Docker Compose

## 1. Подготовка

```bash
cd wireguard-api
mkdir -p data
```

## 2. Запуск

```bash
# Продакшн
docker-compose up -d

# Или для разработки
docker-compose -f docker-compose.dev.yml up
```

## 3. Инициализация интерфейса

```bash
curl -X POST http://localhost:8000/api/config/interface \
  -H "Content-Type: application/json" \
  -d '{
    "port": 51820,
    "ipv4_cidr": "10.8.0.0/24",
    "endpoint": "YOUR_SERVER_IP_OR_DOMAIN",
    "dns": "8.8.8.8, 8.8.4.4"
  }'
```

**Замените `YOUR_SERVER_IP_OR_DOMAIN` на ваш IP или домен!**

## 4. Создание первого пира

```bash
curl -X POST http://localhost:8000/api/peers/ \
  -H "Content-Type: application/json" \
  -d '{"name": "my-device"}'
```

## 5. Получение конфигурации пира

```bash
# Получить ID пира из предыдущего ответа, например 1
curl http://localhost:8000/api/peers/1/config/text
```

## Полезные команды

```bash
# Просмотр логов
docker-compose logs -f

# Остановка
docker-compose down

# Перезапуск
docker-compose restart

# Просмотр метрик
curl http://localhost:8000/api/metrics/
```

## Проверка работы WireGuard

```bash
# В контейнере
docker exec wireguard-api wg show

# На хосте (если WireGuard установлен)
sudo wg show
```

## API документация

После запуска откройте в браузере:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

