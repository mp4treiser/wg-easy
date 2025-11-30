#!/bin/bash

# Примеры использования WireGuard Management API

API_URL="http://localhost:8000"

echo "=== WireGuard Management API Examples ==="
echo ""

# 1. Проверка здоровья
echo "1. Проверка здоровья API:"
curl -s "$API_URL/health" | jq .
echo ""

# 2. Инициализация интерфейса
echo "2. Инициализация WireGuard интерфейса:"
echo "Замените YOUR_SERVER_IP на реальный IP или домен!"
# curl -X POST "$API_URL/api/config/interface" \
#   -H "Content-Type: application/json" \
#   -d '{
#     "port": 51820,
#     "ipv4_cidr": "10.8.0.0/24",
#     "endpoint": "YOUR_SERVER_IP",
#     "dns": "8.8.8.8, 8.8.4.4"
#   }' | jq .
echo ""

# 3. Получение конфигурации интерфейса
echo "3. Получение конфигурации интерфейса:"
curl -s "$API_URL/api/config/interface" | jq .
echo ""

# 4. Создание пира
echo "4. Создание нового пира:"
PEER_RESPONSE=$(curl -s -X POST "$API_URL/api/peers/" \
  -H "Content-Type: application/json" \
  -d '{"name": "test-peer"}')
echo "$PEER_RESPONSE" | jq .

PEER_ID=$(echo "$PEER_RESPONSE" | jq -r '.id')
echo "Создан пир с ID: $PEER_ID"
echo ""

# 5. Получение всех пиров
echo "5. Список всех пиров:"
curl -s "$API_URL/api/peers/" | jq .
echo ""

# 6. Получение конфигурации пира (JSON)
echo "6. Конфигурация пира (JSON):"
curl -s "$API_URL/api/peers/$PEER_ID/config" | jq .
echo ""

# 7. Получение конфигурации пира (текст)
echo "7. Конфигурация пира (текст для клиента):"
curl -s "$API_URL/api/peers/$PEER_ID/config/text"
echo ""
echo ""

# 8. Получение метрик всех пиров
echo "8. Метрики всех пиров:"
curl -s "$API_URL/api/metrics/" | jq .
echo ""

# 9. Получение метрик конкретного пира
echo "9. Метрики пира $PEER_ID:"
curl -s "$API_URL/api/metrics/$PEER_ID" | jq .
echo ""

# 10. Удаление пира (раскомментируйте для использования)
# echo "10. Удаление пира:"
# curl -X DELETE "$API_URL/api/peers/$PEER_ID"
# echo "Пир удален"
# echo ""

echo "=== Примеры завершены ==="

