# nVPN

nVPN - это клиент-серверное VPN-приложение на C++ с собственным протоколом, разработанное для обхода блокировок в странах с цензурой интернета (Россия, Китай, Иран и др.).

## Особенности

- **Собственный протокол** с обфускацией трафика
- **Шифрование**: AES-256-GCM и XChaCha20-Poly1305
- **Обфускация**: маскировка под TLS 1.3, HTTP/2, WebSocket
- **Key Exchange**: X25519 (Curve25519)
- **TUN/TAP интерфейс** для туннелирования трафика
- **UDP и TCP** поддержка
- **Domain Fronting** для обхода DPI

## Требования

- C++17 совместимый компилятор (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.16+
- OpenSSL 1.1.1+
- Linux или macOS (Windows поддержка ограничена)

## Установка зависимостей

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev git net-tools iptables
```

### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake openssl-devel git iptables

# Fedora
sudo dnf install -y cmake gcc-c++ openssl-devel git iptables
```

### macOS
```bash
brew install cmake openssl git
```

## Сборка

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

### Сборка на macOS
```bash
cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl
make -j$(sysctl -n hw.ncpu)
```

## Установка

```bash
sudo make install
```

## Настройка

### Настройка сервера

#### 1. Создание директорий
```bash
sudo mkdir -p /etc/nvpn
sudo mkdir -p /var/log/nvpn
```

#### 2. Генерация SSL-сертификатов
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout /etc/nvpn/server.key \
    -out /etc/nvpn/server.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=vpn.example.com"
sudo chmod 600 /etc/nvpn/server.key
```

#### 3. Конфигурация сервера
Скопируйте `config/server.conf` в `/etc/nvpn/` и отредактируйте:
```bash
sudo cp config/server.conf /etc/nvpn/
sudo nano /etc/nvpn/server.conf
```

#### 4. Настройка системы
```bash
# Включение IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Настройка NAT (замените eth0 на ваш интерфейс)
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

#### 5. Systemd сервис (опционально)
```bash
sudo cp systemd/nvpn-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nvpn-server
sudo systemctl start nvpn-server
```

### Настройка клиента

#### 1. Создание директории
```bash
sudo mkdir -p /etc/nvpn
```

#### 2. Конфигурация клиента
Скопируйте `config/client.conf` в `/etc/nvpn/` и отредактируйте:
```bash
sudo cp config/client.conf /etc/nvpn/
sudo nano /etc/nvpn/client.conf
```

Измените `server_host` на IP-адрес или домен вашего сервера.

#### 3. Systemd сервис (опционально)
```bash
sudo cp systemd/nvpn-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nvpn-client
```

## Использование

### Сервер

**Запуск вручную:**
```bash
sudo nvpn_server -c /etc/nvpn/server.conf
```

**С параметрами командной строки:**
```bash
sudo nvpn_server -b 0.0.0.0 -p 8443 -n 10.8.0.0/24
```

**Управление через systemd:**
```bash
sudo systemctl start nvpn-server
sudo systemctl stop nvpn-server
sudo systemctl restart nvpn-server
sudo systemctl status nvpn-server
```

### Клиент

**Запуск вручную:**
```bash
sudo nvpn_client -c /etc/nvpn/client.conf
```

**С параметрами командной строки:**
```bash
sudo nvpn_client -s vpn.example.com -p 8443 --redirect-gateway
```

**Управление через systemd:**
```bash
sudo systemctl start nvpn-client
sudo systemctl stop nvpn-client
sudo systemctl status nvpn-client
```

### Проверка подключения

```bash
# Проверка интерфейса TUN
ip addr show tun0

# Проверка маршрутов
ip route show

# Проверка соединения
ping 10.8.0.1
curl ifconfig.me
```

## Архитектура

```
┌─────────────────────────────────────────────────────────────┐
│                         КЛИЕНТ                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ TUN Dev  │───▶│  Crypto  │───▶│ Network  │───▶ Internet │
│  └──────────┘    └──────────┘    └──────────┘              │
│       ▲               ▲               ▲                    │
│       │               │               │                      │
│  ┌────┴────┐    ┌────┴────┐    ┌────┴────┐                 │
│  │IP Packets│    │AES-256  │    │Obfuscation│                │
│  │Handler   │    │GCM      │    │(TLS/WS)  │                │
│  └─────────┘    └─────────┘    └─────────┘                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         СЕРВЕР                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Network  │───▶│  Crypto  │───▶│ TUN Dev  │              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       ▲               ▲               ▲                      │
│       │               │               │                      │
│  ┌────┴────┐    ┌────┴────┐    ┌────┴────┐                 │
│  │Deobfus-  │    │AES-256  │    │Route to  │                 │
│  │cation    │    │GCM      │    │Internet  │                 │
│  └─────────┘    └─────────┘    └─────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

## Протокол

### Handshake

1. Клиент генерирует X25519 ключевую пару
2. Отправляет публичный ключ на сервер
3. Сервер генерирует свою ключевую пару
4. Вычисляется shared secret
5. Ключи сессии выводятся через HKDF

### Обфускация

#### TLS 1.3 Mode
- Пакеты маскируются под TLS Application Data
- Используются реальные TLS record headers
- SNI может быть настроен для маскировки

#### HTTP/2 Mode
- Пакеты оборачиваются в HTTP/2 DATA frames
- Поддержка HEADERS frames для handshake
- Может использовать domain fronting

#### WebSocket Mode
- Пакеты отправляются как WebSocket binary frames
- Реальный WebSocket handshake
- Маскирование данных

## Безопасность

- **Perfect Forward Secrecy** (PFS) через ephemeral keys
- **Authenticated Encryption** (AEAD)
- **Anti-replay protection** через sequence numbers
- **Certificate pinning** для предотвращения MITM

## Лицензия

MIT License

## Отказ от ответственности

Этот проект предназначен для образовательных целей и защиты приватности. 
Используйте ответственно и в соответствии с законодательством вашей страны.
