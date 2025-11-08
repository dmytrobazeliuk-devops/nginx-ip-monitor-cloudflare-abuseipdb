# Nginx IP Monitor with Cloudflare and AbuseIPDB

Автоматичний моніторинг та бан підозрілих IP-адрес на основі аналізу nginx логів з інтеграцією Cloudflare та AbuseIPDB.

## Особливості

- 🔍 **Аналіз nginx логів** - автоматичне виявлення підозрілої активності
- 🛡️ **Інтеграція з AbuseIPDB** - перевірка IP на репутацію та репортування
- ☁️ **Блокування в Cloudflare** - автоматичне блокування на рівні аккаунту або зон
- 🤖 **Розпізнавання ботів** - ігнорування легальних пошукових ботів
- ⏰ **Автоматичне видалення старих банів** - бани автоматично видаляються через 60 днів
- 📊 **Детальне логування** - повна історія дій

## Вимоги

- Python 3.7+
- nginx з доступом до лог-файлів
- Cloudflare API Token з правами на блокування IP
- AbuseIPDB API Key (опціонально)

## Встановлення

1. Клонуйте репозиторій:
```bash
git clone https://github.com/dmytrobazeliuk-devops/nginx-ip-monitor-cloudflare-abuseipdb.git
cd nginx-ip-monitor-cloudflare-abuseipdb
```

2. Встановіть залежності:
```bash
pip install -r requirements.txt
```

3. Налаштуйте змінні оточення:
```bash
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"
export LOG_FILE="/var/log/nginx/access.log"
export LOG_OUTPUT="/var/log/nginx-ip-monitor.log"
export BANNED_IPS_FILE="./banned_ips.txt"
export BANS_DATABASE_FILE="./bans_database.json"
```

Або створіть файл `.env`:
```bash
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
LOG_FILE=/var/log/nginx/access.log
LOG_OUTPUT=/var/log/nginx-ip-monitor.log
BANNED_IPS_FILE=./banned_ips.txt
BANS_DATABASE_FILE=./bans_database.json
```

## Налаштування

### Пороги для бану

Ви можете налаштувати пороги через змінні оточення:

- `MIN_REQUESTS_FOR_ANALYSIS` - мінімальна кількість запитів для аналізу (за замовчуванням: 5)
- `MIN_404_ERRORS` - мінімальна кількість помилок 404 для підозри (за замовчуванням: 2)
- `MIN_UNIQUE_PATHS` - мінімальна кількість унікальних шляхів (за замовчуванням: 5)
- `ABUSEIPDB_CONFIDENCE_THRESHOLD` - мінімальний рівень довіри AbuseIPDB у відсотках (за замовчуванням: 30)
- `BAN_EXPIRY_DAYS` - кількість днів до автоматичного видалення бану (за замовчуванням: 60)

### Білий список IP

Додайте IP-адреси до білого списку в коді (змінна `WHITELIST_IPS`):

```python
WHITELIST_IPS = [
    "127.0.0.1",
    "::1",
    "your.server.ip"
]
```

## Використання

### Запуск вручну

```bash
python3 nginx_ip_monitor.py
```

### Налаштування systemd сервісу

1. Створіть файл `/etc/systemd/system/nginx-ip-monitor.service`:

```ini
[Unit]
Description=Nginx IP Monitor - Automatic IP banning based on logs
After=network.target

[Service]
Type=oneshot
User=root
Environment="ABUSEIPDB_API_KEY=your_key"
Environment="CLOUDFLARE_API_TOKEN=your_token"
Environment="LOG_FILE=/var/log/nginx/access.log"
Environment="LOG_OUTPUT=/var/log/nginx-ip-monitor.log"
Environment="BANNED_IPS_FILE=/path/to/banned_ips.txt"
Environment="BANS_DATABASE_FILE=/path/to/bans_database.json"
ExecStart=/usr/bin/python3 /path/to/nginx_ip_monitor.py
StandardOutput=journal
StandardError=journal
```

2. Створіть timer `/etc/systemd/system/nginx-ip-monitor.timer`:

```ini
[Unit]
Description=Run nginx IP monitor every 5 minutes
Requires=nginx-ip-monitor.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
Unit=nginx-ip-monitor.service

[Install]
WantedBy=timers.target
```

3. Активуйте та запустіть:

```bash
systemctl daemon-reload
systemctl enable nginx-ip-monitor.timer
systemctl start nginx-ip-monitor.timer
```

## Критерії бану

IP буде забанений якщо:

1. **Доступ до чутливих файлів** - будь-який доступ до `.env`, `.git`, `wp-config.php` тощо
2. **Висока репутація в AbuseIPDB** - confidence score >= порогу (за замовчуванням 30%)
3. **Підозріла поведінка**:
   - Багато помилок 404 (>= 2)
   - Багато унікальних шляхів (>= 5)
   - Комбінація кількох факторів

## Логування

Всі події логуються в файл, вказаний в `LOG_OUTPUT`. Приклад:

```
2025-11-08 17:00:00 - [INFO] Starting nginx IP monitor
2025-11-08 17:00:01 - [INFO] BANNING IP 192.168.1.100: AbuseIPDB confidence: 45%; Multiple 404 errors: 15
2025-11-08 17:00:02 - [INFO] Successfully blocked 192.168.1.100 in Cloudflare
2025-11-08 17:00:03 - [INFO] nginx IP monitor completed successfully
```

## Безпека

⚠️ **ВАЖЛИВО**: Ніколи не публікуйте API ключі в репозиторій! Використовуйте змінні оточення або файли конфігурації, які не включені в git.

## Ліцензія

MIT License

## Автор

Dmytro Bazeliuk

## Посилання

- [AbuseIPDB API Documentation](https://www.abuseipdb.com/api)
- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
