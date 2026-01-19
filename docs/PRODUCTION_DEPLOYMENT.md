# Chrontainer Production Deployment Guide

This guide covers deploying Chrontainer in a production environment with proper security hardening.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Docker Deployment (Recommended)](#docker-deployment-recommended)
3. [Systemd Deployment](#systemd-deployment)
4. [Environment Configuration](#environment-configuration)
5. [Reverse Proxy Setup](#reverse-proxy-setup)
6. [Security Checklist](#security-checklist)
7. [Backup and Recovery](#backup-and-recovery)
8. [Monitoring](#monitoring)

---

## Prerequisites

- Docker 20.10+ (for Docker deployment)
- Python 3.11+ (for systemd deployment)
- Nginx or Caddy (recommended for HTTPS)
- 512MB+ RAM
- 1GB+ disk space

---

## Docker Deployment (Recommended)

### 1. Create Environment File

```bash
cd /opt/chrontainer
cp .env.example .env
```

### 2. Generate Secure Secret Key

```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env
```

### 3. Configure Environment Variables

Edit `.env`:

```bash
# Required: Generate with the command above
SECRET_KEY=your-secure-random-key-here

# Flask Environment
FLASK_ENV=production

# Application Port
PORT=5000

# Database Path
DATABASE_PATH=/data/chrontainer.db

# Rate Limiting (requests per minute per IP)
RATE_LIMIT_PER_MINUTE=60

# Session Security
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax

# Force HTTPS (set to true if NOT using reverse proxy)
FORCE_HTTPS=false

# Logging
LOG_LEVEL=INFO
```

### 4. Build and Run with Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  chrontainer:
    build: .
    container_name: chrontainer
    restart: unless-stopped
    ports:
      - "5000:5000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data:/data
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - FLASK_ENV=production
      - LOG_LEVEL=INFO
      - RATE_LIMIT_PER_MINUTE=60
      - SESSION_COOKIE_SECURE=true
      - SESSION_COOKIE_HTTPONLY=true
    networks:
      - chrontainer_network

networks:
  chrontainer_network:
    driver: bridge
```

Start the container:

```bash
docker-compose up -d
```

### 5. Verify Deployment

```bash
docker logs chrontainer
curl http://localhost:5000/login
```

---

## Systemd Deployment

For non-Docker deployments:

### 1. Install System Dependencies

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv docker.io
```

### 2. Create Application Directory

```bash
sudo mkdir -p /opt/chrontainer
sudo cp -r * /opt/chrontainer/
cd /opt/chrontainer
```

### 3. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env with your secure configuration
```

### 5. Install Systemd Service

```bash
sudo cp chrontainer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable chrontainer
sudo systemctl start chrontainer
```

### 6. Check Status

```bash
sudo systemctl status chrontainer
sudo journalctl -u chrontainer -f
```

---

## Environment Configuration

### Required Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECRET_KEY` | Flask session encryption key | ⚠️ Insecure default | **YES** |
| `DATABASE_PATH` | SQLite database file path | `/data/chrontainer.db` | No |

### Security Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SESSION_COOKIE_SECURE` | Require HTTPS for cookies | `false` |
| `SESSION_COOKIE_HTTPONLY` | Prevent JavaScript cookie access | `true` |
| `SESSION_COOKIE_SAMESITE` | CSRF protection level | `Lax` |
| `FORCE_HTTPS` | Redirect HTTP to HTTPS | `false` |
| `RATE_LIMIT_PER_MINUTE` | API rate limit per IP | `60` |

### Application Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Application port | `5000` |
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `FLASK_ENV` | Flask environment | `production` |

### Gunicorn Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GUNICORN_WORKERS` | Number of worker processes | `CPU*2+1` |

---

## Reverse Proxy Setup

### Nginx Configuration

Create `/etc/nginx/sites-available/chrontainer`:

```nginx
server {
    listen 80;
    server_name chrontainer.example.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name chrontainer.example.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/chrontainer.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chrontainer.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy Settings
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Logging
    access_log /var/log/nginx/chrontainer_access.log;
    error_log /var/log/nginx/chrontainer_error.log;
}
```

Enable site:

```bash
sudo ln -s /etc/nginx/sites-available/chrontainer /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Caddy Configuration

Create `Caddyfile`:

```
chrontainer.example.com {
    reverse_proxy localhost:5000

    # Headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
    }

    # Logging
    log {
        output file /var/log/caddy/chrontainer.log
    }
}
```

Start Caddy:

```bash
sudo caddy run --config Caddyfile
```

---

## Security Checklist

### Before Going to Production

- [ ] **Change default admin password** immediately after first login
- [ ] **Set SECRET_KEY** to a secure random value (64+ characters)
- [ ] **Enable HTTPS** via reverse proxy (Nginx/Caddy)
- [ ] **Set SESSION_COOKIE_SECURE=true** after enabling HTTPS
- [ ] **Restrict Docker socket access** (consider using socket-proxy)
- [ ] **Enable firewall** (allow only 22, 80, 443)
- [ ] **Set up automated backups** for `/data/chrontainer.db`
- [ ] **Configure log rotation**
- [ ] **Enable Discord notifications** (optional but recommended)
- [ ] **Review rate limits** based on expected usage
- [ ] **Update all system packages**

### Docker Socket Security

⚠️ **Warning**: Mounting Docker socket gives full control over the host system.

**Option 1: Socket Proxy (Recommended)**

Use [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy):

```yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    container_name: docker-socket-proxy
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CONTAINERS=1
      - IMAGES=1
      - POST=1
    networks:
      - chrontainer_network

  chrontainer:
    # ... existing config ...
    volumes:
      - ./data:/data
      # Remove docker.sock mount
    environment:
      # Use proxy instead
      - DOCKER_HOST=tcp://socket-proxy:2375
```

**Option 2: Read-Only Mount**

Mount socket as read-only (limits functionality):

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

---

## Backup and Recovery

### Automated Backup Script

Create `/opt/chrontainer/backup.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/backup/chrontainer"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
cp /data/chrontainer.db "$BACKUP_DIR/chrontainer_$DATE.db"

# Keep only last 30 days
find "$BACKUP_DIR" -name "chrontainer_*.db" -mtime +30 -delete

echo "Backup completed: chrontainer_$DATE.db"
```

Add to crontab:

```bash
# Daily backup at 3 AM
0 3 * * * /opt/chrontainer/backup.sh >> /var/log/chrontainer_backup.log 2>&1
```

### Recovery

```bash
# Stop Chrontainer
sudo systemctl stop chrontainer

# Restore database
cp /backup/chrontainer/chrontainer_YYYYMMDD_HHMMSS.db /data/chrontainer.db

# Start Chrontainer
sudo systemctl start chrontainer
```

---

## Monitoring

### Health Check Endpoint

Add to your monitoring system:

```bash
curl -f http://localhost:5000/login || alert_admin
```

### Log Monitoring

Monitor application logs:

```bash
# Docker
docker logs -f chrontainer

# Systemd
sudo journalctl -u chrontainer -f
```

### Resource Monitoring

Check resource usage:

```bash
# Docker
docker stats chrontainer

# System
htop
```

### Common Issues

| Issue | Solution |
|-------|----------|
| High memory usage | Reduce `GUNICORN_WORKERS` |
| Slow responses | Check rate limits, increase workers |
| Database locked | Check for concurrent access |
| Container actions fail | Verify Docker socket permissions |

---

## Upgrading

### Docker Deployment

```bash
cd /opt/chrontainer
git pull
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Systemd Deployment

```bash
cd /opt/chrontainer
source venv/bin/activate
git pull
pip install -r requirements.txt
sudo systemctl restart chrontainer
```

---

## Support

- **Documentation**: https://github.com/yourusername/chrontainer
- **Issues**: https://github.com/yourusername/chrontainer/issues
- **Security**: Report vulnerabilities privately to security@example.com

---

## License

See LICENSE file in the repository.
