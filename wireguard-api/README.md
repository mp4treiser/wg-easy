# WireGuard Management API

Простой REST API на FastAPI для управления WireGuard пирами на Ubuntu сервере.

## Возможности

- ✅ Добавление пиров
- ✅ Удаление пиров
- ✅ Получение метрик по подключению (трафик, скорость, статус)
- ✅ Получение ключей и конфигурационных параметров
- ✅ Автоматическое назначение IP адресов
- ✅ Генерация ключей

## Требования

- Ubuntu (или другой Linux дистрибутив)
- Python 3.8+
- WireGuard установлен и настроен
- Права root для записи в `/etc/wireguard/`

## Установка

### Docker Compose (Рекомендуется)

API интегрирован в основной `docker-compose.yml` проекта wg-easy.

1. Из корневой директории проекта запустите:

```bash
docker-compose up -d
```

Это запустит оба сервиса:
- `wg-easy` - основной веб-интерфейс (порт 5000)
- `wireguard-api` - REST API (порт 8000)

2. Инициализируйте WireGuard интерфейс через API (если нужно):

```bash
curl -X POST http://localhost:8000/api/config/interface \
  -H "Content-Type: application/json" \
  -d '{
    "port": 51820,
    "ipv4_cidr": "10.8.0.0/24",
    "endpoint": "your-server-ip-or-domain.com",
    "dns": "8.8.8.8, 8.8.4.4"
  }'
```

**Важно:** 
- Оба сервиса используют один и тот же volume `etc_wireguard` для конфигурации WireGuard
- Если wg-easy уже настроен, API автоматически получит доступ к существующим конфигурациям
- Замените `your-server-ip-or-domain.com` на реальный IP адрес или домен вашего сервера

### Вариант 2: Локальная установка

1. Установите WireGuard (если еще не установлен):

```bash
sudo apt update
sudo apt install wireguard wireguard-tools -y
```

2. Клонируйте или скопируйте проект:

```bash
cd wireguard-api
```

3. Установите зависимости Python:

```bash
python3 -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate
pip install -r requirements.txt
```

4. Инициализируйте базу данных и интерфейс:

При первом запуске API автоматически создаст базу данных. Но перед использованием нужно инициализировать WireGuard интерфейс:

```bash
# Запустите API
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# В другом терминале инициализируйте интерфейс
curl -X POST http://localhost:8000/api/config/interface \
  -H "Content-Type: application/json" \
  -d '{
    "port": 51820,
    "ipv4_cidr": "10.8.0.0/24",
    "endpoint": "your-server-ip-or-domain.com",
    "dns": "8.8.8.8, 8.8.4.4"
  }'
```

## Запуск

### Docker Compose

Из корневой директории проекта:

```bash
# Запуск всех сервисов (wg-easy + wireguard-api)
docker-compose up -d

# Просмотр логов wireguard-api
docker-compose logs -f wireguard-api

# Просмотр логов всех сервисов
docker-compose logs -f

# Остановка
docker-compose down

# Пересборка только wireguard-api
docker-compose build wireguard-api
docker-compose up -d wireguard-api
```

### Локально (разработка)

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Локально (продакшн с systemd)

Создайте файл `/etc/systemd/system/wireguard-api.service`:

```ini
[Unit]
Description=WireGuard Management API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/wireguard-api
Environment="PATH=/path/to/wireguard-api/venv/bin"
ExecStart=/path/to/wireguard-api/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

Затем:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wireguard-api
sudo systemctl start wireguard-api
```

## API Endpoints

### Пиры (Peers)

#### Создать пир
```bash
POST /api/peers/
Content-Type: application/json

{
  "name": "my-peer",
  "ipv4_address": "10.8.0.2",  # опционально, будет назначен автоматически
  "allowed_ips": ["0.0.0.0/0"],  # опционально
  "persistent_keepalive": 25  # опционально
}
```

#### Получить все пиры
```bash
GET /api/peers/
```

#### Получить пир по ID
```bash
GET /api/peers/{peer_id}
```

#### Удалить пир
```bash
DELETE /api/peers/{peer_id}
```

#### Получить конфигурацию пира (ключи и параметры)
```bash
GET /api/peers/{peer_id}/config
```

### Метрики

#### Получить метрики всех пиров
```bash
GET /api/metrics/
```

#### Получить метрики конкретного пира
```bash
GET /api/metrics/{peer_id}
```

Ответ включает:
- `transfer_rx` / `transfer_tx` - байты получено/отправлено
- `transfer_rx_mb` / `transfer_tx_mb` - мегабайты
- `latest_handshake` - время последнего handshake
- `endpoint` - IP адрес пира
- `is_connected` - статус подключения

### Конфигурация

#### Получить конфигурацию интерфейса
```bash
GET /api/config/interface
```

#### Инициализировать интерфейс
```bash
POST /api/config/interface
Content-Type: application/json

{
  "port": 51820,
  "ipv4_cidr": "10.8.0.0/24",
  "endpoint": "your-server.com",
  "dns": "8.8.8.8, 8.8.4.4"
}
```

## Примеры использования

### Создать пир и получить конфигурацию

```bash
# Создать пир
PEER_RESPONSE=$(curl -X POST http://localhost:8000/api/peers/ \
  -H "Content-Type: application/json" \
  -d '{"name": "my-laptop"}')

PEER_ID=$(echo $PEER_RESPONSE | jq -r '.id')

# Получить конфигурацию для клиента
curl http://localhost:8000/api/peers/$PEER_ID/config
```

### Получить метрики

```bash
# Все пиры
curl http://localhost:8000/api/metrics/

# Конкретный пир
curl http://localhost:8000/api/metrics/1
```

## Структура проекта

```
wireguard-api/
├── app/
│   ├── __init__.py
│   ├── main.py              # Главный файл FastAPI приложения
│   ├── models.py            # Pydantic модели
│   ├── database.py          # Работа с SQLite базой данных
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── peers.py         # Эндпоинты для управления пирами
│   │   ├── metrics.py       # Эндпоинты для метрик
│   │   └── config.py        # Эндпоинты для конфигурации
│   └── utils/
│       ├── __init__.py
│       └── wireguard.py     # Утилиты для работы с WireGuard
├── requirements.txt
└── README.md
```

## Безопасность

⚠️ **Важно:**

1. API должен запускаться с правами root для записи в `/etc/wireguard/`
2. В продакшне используйте HTTPS и аутентификацию
3. Не экспонируйте API в интернет без защиты
4. Рассмотрите использование reverse proxy (nginx) с аутентификацией

## Docker

### Структура Docker Compose

- `docker-compose.yml` - для продакшн использования
- `docker-compose.dev.yml` - для разработки с hot reload

### Важные замечания для Docker

1. **Privileged mode**: Контейнер запускается в privileged режиме для доступа к WireGuard
2. **Network host**: Используется host network mode для работы с WireGuard интерфейсом
3. **Volumes**: 
   - `/etc/wireguard` монтируется для доступа к конфигурации WireGuard
   - `./data` монтируется для хранения базы данных SQLite

### Альтернативная конфигурация (без privileged)

Если вы хотите избежать privileged режима, можете использовать `cap_add`:

```yaml
cap_add:
  - NET_ADMIN
  - SYS_MODULE
devices:
  - /dev/net/tun
```

Но это может не работать на всех системах, поэтому privileged режим более надежен.

## Troubleshooting

### Ошибка "Permission denied"
- **Docker**: Убедитесь, что контейнер запущен с `privileged: true`
- **Локально**: Убедитесь, что API запущен с правами root или пользователь имеет доступ к `/etc/wireguard/`

### Ошибка "Interface not found"
Убедитесь, что WireGuard интерфейс инициализирован через `/api/config/interface`

### Метрики не обновляются
Проверьте, что WireGuard интерфейс запущен:
- **Docker**: `docker exec wireguard-api wg show`
- **Локально**: `sudo wg show`

### Проблемы с сетью в Docker
Если WireGuard не работает в Docker, убедитесь что:
1. Используется `network_mode: host`
2. Контейнер запущен с `privileged: true`
3. WireGuard модуль загружен в ядро хоста: `lsmod | grep wireguard`

## Лицензия

MIT

