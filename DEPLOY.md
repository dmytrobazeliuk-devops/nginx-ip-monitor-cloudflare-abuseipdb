# Інструкція для публікації на GitHub

Репозиторій готовий і знаходиться в `/tmp/nginx-ip-monitor-cloudflare-abuseipdb`

## Варіант 1: Через веб-інтерфейс GitHub

1. Перейдіть на https://github.com/new
2. Назва репозиторію: `nginx-ip-monitor-cloudflare-abuseipdb`
3. Виберіть "Public"
4. НЕ створюйте README, .gitignore або LICENSE (вони вже є)
5. Натисніть "Create repository"
6. Виконайте команди, які покаже GitHub (або нижче)

## Варіант 2: Через командний рядок

```bash
cd /tmp/nginx-ip-monitor-cloudflare-abuseipdb
git push -u origin main
```

Якщо використовуєте SSH (рекомендовано):
```bash
git remote set-url origin git@github.com:dmytrobazeliuk-devops/nginx-ip-monitor-cloudflare-abuseipdb.git
git push -u origin main
```

## Варіант 3: Через GitHub CLI

```bash
cd /tmp/nginx-ip-monitor-cloudflare-abuseipdb
gh auth login
gh repo create dmytrobazeliuk-devops/nginx-ip-monitor-cloudflare-abuseipdb --public --source=. --remote=origin --push
```
