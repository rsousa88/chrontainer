# Chrontainer Security Guide

This document outlines the security features, best practices, and considerations for running Chrontainer in production.

## Table of Contents

1. [Security Features](#security-features)
2. [Threat Model](#threat-model)
3. [Configuration Best Practices](#configuration-best-practices)
4. [Authentication & Authorization](#authentication--authorization)
5. [Network Security](#network-security)
6. [Docker Socket Security](#docker-socket-security)
7. [Input Validation](#input-validation)
8. [Security Headers](#security-headers)
9. [Rate Limiting](#rate-limiting)
10. [Secrets Management](#secrets-management)
11. [Audit Logging](#audit-logging)
12. [Security Checklist](#security-checklist)

---

## Security Features

Chrontainer v0.2.0+ includes the following security features:

### Authentication
- ✅ **Flask-Login** session-based authentication
- ✅ **bcrypt** password hashing with salt
- ✅ **Secure session cookies** (HttpOnly, SameSite)
- ✅ **Login rate limiting** (10 attempts/minute per IP)

### CSRF Protection
- ✅ **Flask-WTF CSRF tokens** on all state-changing operations
- ✅ **SameSite cookies** for additional protection

### Input Validation
- ✅ **Strict validation** of container IDs, names, cron expressions
- ✅ **URL validation** for Docker hosts and webhooks
- ✅ **Sanitization** of all user inputs
- ✅ **Length limits** on all string inputs

### Security Headers
- ✅ **X-Content-Type-Options**: nosniff
- ✅ **X-Frame-Options**: SAMEORIGIN
- ✅ **X-XSS-Protection**: 1; mode=block
- ✅ **Referrer-Policy**: strict-origin-when-cross-origin
- ✅ **Strict-Transport-Security** (when HTTPS enabled)

### Rate Limiting
- ✅ **Global rate limit**: 60 requests/minute per IP (configurable)
- ✅ **Login rate limit**: 10 attempts/minute per IP
- ✅ **Per-endpoint limits** on sensitive operations

### Encryption
- ✅ **Database password hashing** with bcrypt
- ✅ **Session encryption** with SECRET_KEY
- ⏳ **HTTPS** (via reverse proxy - recommended)

---

## Threat Model

### In Scope

Chrontainer is designed to protect against:

1. **Unauthorized Access**
   - Unauthenticated users accessing the application
   - Brute force password attacks
   - Session hijacking

2. **Injection Attacks**
   - SQL injection via parameterized queries
   - Command injection via input validation
   - XSS via output escaping

3. **CSRF Attacks**
   - State-changing operations without valid CSRF tokens

4. **Information Disclosure**
   - Sensitive data in logs (passwords filtered)
   - Directory traversal attacks
   - Enumeration attacks (rate limiting)

### Out of Scope

Chrontainer **cannot** protect against:

1. **Host Compromise**
   - If the Docker host is compromised, attacker has full control
   - Docker socket access = root access

2. **Physical Access**
   - Direct database access on the server
   - Reading environment files (.env)

3. **Supply Chain Attacks**
   - Compromised Docker images
   - Malicious Python packages

4. **DDoS Attacks**
   - Large-scale distributed attacks (use Cloudflare/CDN)

5. **Social Engineering**
   - Users sharing passwords
   - Phishing attacks

---

## Configuration Best Practices

### 1. Secret Key Management

**CRITICAL**: Always set a secure SECRET_KEY in production.

```bash
# Generate a secure key
python3 -c "import secrets; print(secrets.token_hex(32))"

# Set in .env
SECRET_KEY=your-generated-key-here
```

**Never**:
- ❌ Use the default dev key in production
- ❌ Commit SECRET_KEY to version control
- ❌ Share SECRET_KEY between environments
- ❌ Use short or predictable keys

### 2. Session Security

Enable secure cookies when using HTTPS:

```bash
SESSION_COOKIE_SECURE=true      # Requires HTTPS
SESSION_COOKIE_HTTPONLY=true    # Prevents JavaScript access
SESSION_COOKIE_SAMESITE=Lax     # CSRF protection
```

### 3. HTTPS Configuration

**Always use HTTPS in production.**

Option 1: Reverse Proxy (Recommended)
```bash
FORCE_HTTPS=false  # Let Nginx/Caddy handle HTTPS
```

Option 2: Direct HTTPS
```bash
FORCE_HTTPS=true   # Chrontainer enforces HTTPS
```

### 4. Rate Limiting

Adjust based on your usage:

```bash
# Conservative (small team)
RATE_LIMIT_PER_MINUTE=30

# Default (medium team)
RATE_LIMIT_PER_MINUTE=60

# Permissive (large team/automation)
RATE_LIMIT_PER_MINUTE=120
```

### 5. Logging

Set appropriate log level:

```bash
# Production (recommended)
LOG_LEVEL=INFO

# Debugging
LOG_LEVEL=DEBUG  # ⚠️ May expose sensitive data

# Minimal
LOG_LEVEL=WARNING
```

---

## Authentication & Authorization

### Default Credentials

**⚠️ CRITICAL**: Change the default admin password immediately!

```
Username: admin
Password: admin
```

### Password Policy

Current implementation:
- ✅ bcrypt hashing with automatic salt
- ✅ No plaintext password storage
- ⏳ No password complexity requirements (planned)
- ⏳ No password expiration (planned)
- ⏳ No password history (planned)

**Recommendations**:
- Use strong passwords (12+ characters, mixed case, numbers, symbols)
- Use unique passwords (not reused from other services)
- Consider using a password manager
- Change passwords periodically

### Role-Based Access Control (RBAC)

Current roles:
- **admin**: Full access (manage schedules, hosts, settings, users)
- **viewer**: Read-only access (planned - not yet implemented)

### Session Management

- Sessions expire on browser close (no persistent login)
- Sessions are invalidated on logout
- Sessions are encrypted with SECRET_KEY
- One session per user (no concurrent logins)

---

## Network Security

### Firewall Configuration

Allow only necessary ports:

```bash
# UFW example
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP (redirect to HTTPS)
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
```

### Reverse Proxy Security

Benefits of using Nginx/Caddy:
- ✅ SSL/TLS termination
- ✅ DDoS mitigation
- ✅ Request buffering
- ✅ Additional access control
- ✅ WAF integration (optional)

### Docker Network Isolation

Use Docker networks to isolate Chrontainer:

```yaml
networks:
  chrontainer_network:
    driver: bridge
    internal: false  # Needs internet for webhooks
```

---

## Docker Socket Security

### The Risk

**⚠️ Mounting `/var/run/docker.sock` gives root-equivalent access!**

With Docker socket access, an attacker can:
- Start privileged containers
- Mount host filesystem
- Execute commands as root
- Read sensitive data
- Destroy the system

### Mitigation Strategies

#### Option 1: Socket Proxy (Recommended)

Use [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy):

```yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    container_name: docker-socket-proxy
    restart: unless-stopped
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      CONTAINERS: 1    # Allow container operations
      IMAGES: 1        # Allow image operations
      POST: 1          # Allow POST requests
      NETWORKS: 0      # Deny network operations
      VOLUMES: 0       # Deny volume operations
      EXEC: 0          # Deny exec operations
    networks:
      - chrontainer_network
```

#### Option 2: Read-Only Socket

Limit to read-only operations:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

**Limitations**:
- Cannot restart containers
- Cannot start/stop containers
- Cannot update containers
- Can only list containers

#### Option 3: Separate Management Host

Run Chrontainer on a dedicated management host:
- Separate from production containers
- Limited blast radius if compromised
- Use remote Docker API via TCP (with socket-proxy)

---

## Input Validation

All user inputs are validated:

### Container IDs
- Format: 12 or 64 hexadecimal characters
- Regex: `^[a-f0-9]{12}$|^[a-f0-9]{64}$`

### Container Names
- Max length: 255 characters
- Allowed: `a-zA-Z0-9_.-`
- Must start with alphanumeric

### Cron Expressions
- Format: 5 fields (minute hour day month day_of_week)
- Validated by APScheduler CronTrigger

### URLs
- Max length: 2048 characters
- Schemes: http, https, unix, tcp
- Format validation: Basic URL pattern

### Discord Webhooks
- Must start with: `https://discord.com/api/webhooks/`
- Length validated

### All Strings
- Null bytes removed
- Control characters stripped
- Max length enforced
- Trimmed whitespace

---

## Security Headers

### Enabled by Default

```http
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
```

### When HTTPS is Enabled

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### Content Security Policy

When `FORCE_HTTPS=true`:

```
default-src 'self';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
img-src 'self' data: https:;
```

**Note**: `unsafe-inline` is required for inline scripts/styles in templates. Consider moving to external files in future versions.

---

## Rate Limiting

### Global Limits

Default: 60 requests/minute per IP

Configure in `.env`:
```bash
RATE_LIMIT_PER_MINUTE=60
```

### Endpoint-Specific Limits

#### Login Endpoint
- **10 requests/minute** per IP
- Prevents brute force attacks
- Returns 429 Too Many Requests

#### API Endpoints
- Inherit global limit (60/minute)
- Consider stricter limits for sensitive operations

### Bypassing Rate Limits

Rate limits can be bypassed by:
- Using multiple IPs (distributed attack)
- Waiting for rate limit window to reset
- Using authenticated requests (same limit applies)

**Mitigation**:
- Use Cloudflare or similar CDN
- Implement account-level rate limits (future)
- Monitor failed login attempts

---

## Secrets Management

### Current Implementation

- ✅ SECRET_KEY via environment variable
- ✅ Discord webhook URL in database (encrypted session)
- ✅ Passwords hashed with bcrypt
- ⏳ No secrets in logs (passwords filtered)

### Best Practices

1. **Never commit secrets to Git**
   - Use `.gitignore` for `.env`
   - Scan commits with `git-secrets`

2. **Use environment variables**
   - Load from `.env` file
   - Override in production

3. **Rotate secrets regularly**
   - Change SECRET_KEY periodically
   - Update webhook URLs if compromised

4. **Backup securely**
   - Encrypt database backups
   - Store backups off-site
   - Restrict backup access

---

## Audit Logging

### Current Logging

Chrontainer logs:
- ✅ User login/logout
- ✅ Container actions (start, stop, restart)
- ✅ Schedule creation/deletion
- ✅ Host connection attempts
- ✅ Errors and exceptions

### Log Storage

**Docker**:
```bash
docker logs chrontainer
```

**Systemd**:
```bash
journalctl -u chrontainer
```

### Log Rotation

**Docker** (in docker-compose.yml):
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

**Systemd**:
Managed automatically by journald.

### What's NOT Logged

- ❌ Passwords (never logged)
- ❌ SECRET_KEY
- ❌ Full Discord webhook URLs (only domain)

---

## Security Checklist

### Pre-Production

- [ ] Change default admin password
- [ ] Set unique SECRET_KEY (64+ chars)
- [ ] Enable HTTPS via reverse proxy
- [ ] Set SESSION_COOKIE_SECURE=true
- [ ] Configure firewall (close unnecessary ports)
- [ ] Use socket-proxy for Docker access
- [ ] Set appropriate rate limits
- [ ] Configure log rotation
- [ ] Set up automated backups
- [ ] Review ROADMAP for known issues

### Ongoing Maintenance

- [ ] Monitor logs for suspicious activity
- [ ] Update Chrontainer regularly
- [ ] Rotate SECRET_KEY periodically (e.g., quarterly)
- [ ] Review user accounts and permissions
- [ ] Test backup restoration procedure
- [ ] Keep host system updated
- [ ] Renew SSL certificates
- [ ] Audit cron schedules for anomalies

### Incident Response

If you suspect a security breach:

1. **Immediately**:
   - Disconnect Chrontainer from network
   - Stop the Docker container
   - Review recent logs

2. **Investigate**:
   - Check database for unauthorized changes
   - Review failed login attempts
   - Check container action logs
   - Examine scheduled tasks

3. **Remediate**:
   - Change all passwords
   - Rotate SECRET_KEY
   - Restore from known-good backup
   - Update Chrontainer to latest version

4. **Report**:
   - File GitHub issue (if vulnerability found)
   - Email security@example.com for sensitive issues

---

## Reporting Security Vulnerabilities

**Do NOT open public GitHub issues for security vulnerabilities.**

Instead:
1. Email: security@example.com
2. Include: Description, steps to reproduce, impact
3. Wait for response before public disclosure

We aim to respond within 48 hours and patch within 7 days.

---

## Future Security Enhancements

Planned for future versions:

- [ ] Two-factor authentication (2FA)
- [ ] API key authentication
- [ ] User management UI (add/remove users)
- [ ] Password complexity requirements
- [ ] Password expiration
- [ ] Failed login lockout
- [ ] Audit log export
- [ ] Database encryption at rest
- [ ] OAuth2 integration (GitHub, Google)
- [ ] Webhook signature verification
- [ ] IP whitelist/blacklist
- [ ] Account-level rate limiting
- [ ] Security vulnerability scanning (Dependabot)

---

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/2.3.x/security/)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

**Last Updated**: 2026-01-19
**Version**: 0.2.0
