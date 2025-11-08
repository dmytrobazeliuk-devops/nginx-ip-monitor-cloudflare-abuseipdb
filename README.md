# Nginx IP Monitor with Cloudflare and AbuseIPDB

Automated monitoring and banning of suspicious IP addresses based on nginx log analysis with Cloudflare and AbuseIPDB integration.

## Features

- 🔍 **Nginx log analysis** - automatic detection of suspicious activity
- 🛡️ **AbuseIPDB integration** - IP reputation checking and reporting
- ☁️ **Cloudflare blocking** - automatic blocking at account or zone level
- 🤖 **Bot recognition** - ignores legitimate search engine bots
- ⏰ **Automatic old ban removal** - bans are automatically removed after 60 days
- 📊 **Detailed logging** - complete action history

## Requirements

- Python 3.7+
- nginx with access to log files
- Cloudflare API Token with IP blocking permissions
- AbuseIPDB API Key (optional)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/dmytrobazeliuk-devops/nginx-ip-monitor-cloudflare-abuseipdb.git
cd nginx-ip-monitor-cloudflare-abuseipdb
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export CLOUDFLARE_API_TOKEN="your_cloudflare_api_token"
export LOG_FILE="/var/log/nginx/access.log"
export LOG_OUTPUT="/var/log/nginx-ip-monitor.log"
export BANNED_IPS_FILE="./banned_ips.txt"
export BANS_DATABASE_FILE="./bans_database.json"
```

Or create a `.env` file:
```bash
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token
LOG_FILE=/var/log/nginx/access.log
LOG_OUTPUT=/var/log/nginx-ip-monitor.log
BANNED_IPS_FILE=./banned_ips.txt
BANS_DATABASE_FILE=./bans_database.json
```

## Configuration

### Ban Thresholds

You can configure thresholds via environment variables:

- `MIN_REQUESTS_FOR_ANALYSIS` - minimum number of requests for analysis (default: 5)
- `MIN_404_ERRORS` - minimum number of 404 errors for suspicion (default: 2)
- `MIN_UNIQUE_PATHS` - minimum number of unique paths (default: 5)
- `ABUSEIPDB_CONFIDENCE_THRESHOLD` - minimum AbuseIPDB confidence level in percentage (default: 30)
- `BAN_EXPIRY_DAYS` - number of days until automatic ban removal (default: 60)

### IP Whitelist

Add IP addresses to the whitelist in the code (variable `WHITELIST_IPS`):

```python
WHITELIST_IPS = [
    "127.0.0.1",
    "::1",
    "your.server.ip"
]
```

## Usage

### Manual Run

```bash
python3 nginx_ip_monitor.py
```

### Systemd Service Setup

1. Create file `/etc/systemd/system/nginx-ip-monitor.service`:

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

2. Create timer `/etc/systemd/system/nginx-ip-monitor.timer`:

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

3. Enable and start:

```bash
systemctl daemon-reload
systemctl enable nginx-ip-monitor.timer
systemctl start nginx-ip-monitor.timer
```

## Ban Criteria

An IP will be banned if:

1. **Access to sensitive files** - any access to `.env`, `.git`, `wp-config.php`, etc.
2. **High AbuseIPDB reputation** - confidence score >= threshold (default 30%)
3. **Suspicious behavior**:
   - Many 404 errors (>= 2)
   - Many unique paths (>= 5)
   - Combination of multiple factors

## Logging

All events are logged to the file specified in `LOG_OUTPUT`. Example:

```
2025-11-08 17:00:00 - [INFO] Starting nginx IP monitor
2025-11-08 17:00:01 - [INFO] BANNING IP 192.168.1.100: AbuseIPDB confidence: 45%; Multiple 404 errors: 15
2025-11-08 17:00:02 - [INFO] Successfully blocked 192.168.1.100 in Cloudflare
2025-11-08 17:00:03 - [INFO] nginx IP monitor completed successfully
```

## Security

⚠️ **IMPORTANT**: Never publish API keys in the repository! Use environment variables or configuration files that are not included in git.

## License

MIT License

## Author

Dmytro Bazeliuk

## Links

- [Portfolio Website](https://devsecops.cv)
- [AbuseIPDB API Documentation](https://www.abuseipdb.com/api)
- [Cloudflare API Documentation](https://developers.cloudflare.com/api/)
