# Upgrade Guide: v0.2.0 Production Hardening

This guide will help you upgrade Chrontainer to v0.2.0 with production hardening features.

## What's New in v0.2.0

### Security Enhancements
- ✅ **CSRF Protection** - Flask-WTF protects against cross-site request forgery
- ✅ **Rate Limiting** - 60 requests/min globally, 10/min for login (configurable)
- ✅ **Input Validation** - Comprehensive validation of all user inputs
- ✅ **Security Headers** - X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
- ✅ **Environment Config** - Secure configuration via .env files
- ✅ **HTTPS Support** - Optional HTTPS enforcement via Flask-Talisman

### Production Features
- ✅ **Gunicorn WSGI Server** - Production-ready server with auto-scaling workers
- ✅ **Systemd Support** - Service file for non-Docker deployments
- ✅ **Comprehensive Docs** - Production deployment and security guides

### Breaking Changes
⚠️ **Important**: This update requires rebuilding the Docker image.

## Upgrade Steps

### For Docker Deployment

1. **SSH into your Raspberry Pi**
   ```bash
   ssh user-host-ip
   cd /home/pi/chrontainer
   ```

2. **Pull the latest code**
   ```bash
   git pull
   ```

3. **Stop the current container**
   ```bash
   docker-compose down
   ```

4. **Create environment file (optional but recommended)**
   ```bash
   cp .env.example .env

   # Generate a secure SECRET_KEY
   python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env

   # Edit .env and set your preferences
   nano .env
   ```

   Recommended settings:
   ```bash
   SECRET_KEY=<generated-key-here>
   FLASK_ENV=production
   LOG_LEVEL=INFO
   RATE_LIMIT_PER_MINUTE=60
   SESSION_COOKIE_HTTPONLY=true
   SESSION_COOKIE_SAMESITE=Lax
   # SESSION_COOKIE_SECURE=true  # Only if using HTTPS
   ```

5. **Update docker-compose.yml to use .env (optional)**

   Edit `docker-compose.yml`:
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
       env_file:
         - .env  # Load from .env file
       environment:
         # Override specific vars if needed
         - FLASK_ENV=production
       networks:
         - chrontainer_network

   networks:
     chrontainer_network:
       driver: bridge
   ```

6. **Rebuild and start the container**
   ```bash
   # Rebuild with new dependencies
   docker-compose build --no-cache

   # Start the container
   docker-compose up -d
   ```

7. **Verify the upgrade**
   ```bash
   # Check container logs
   docker logs chrontainer

   # Should see:
   # - "Starting Chrontainer WSGI server..."
   # - "Chrontainer is ready. Listening on 0.0.0.0:5000"
   # - No errors about missing modules
   ```

8. **Test the application**
   ```bash
   # Test from command line
   curl http://192.168.1.100:5000/login

   # Or visit in browser:
   # http://192.168.1.100:5000
   ```

9. **Change default password (if not done already)**
   - Log in with `admin` / `admin`
   - ⚠️ **IMPORTANT**: This feature is not yet implemented
   - For now, keep using strong network security

## Post-Upgrade Configuration

### Rate Limiting

If you experience rate limit errors, adjust in `.env`:
```bash
RATE_LIMIT_PER_MINUTE=120  # Increase from default 60
```

Rebuild and restart:
```bash
docker-compose down
docker-compose up -d --build
```

### HTTPS Setup (Recommended for Production)

See `docs/PRODUCTION_DEPLOYMENT.md` for complete Nginx/Caddy setup.

Quick Nginx setup:
1. Install certbot and get SSL certificate
2. Configure Nginx reverse proxy (see docs)
3. Update `.env`:
   ```bash
   SESSION_COOKIE_SECURE=true
   ```
4. Restart Chrontainer

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'flask_wtf'"

**Solution**: Rebuild the Docker image
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Issue: "429 Too Many Requests"

**Cause**: Rate limiting triggered (10 failed logins or 60 requests/min)

**Solution**: Wait 1 minute or increase `RATE_LIMIT_PER_MINUTE` in `.env`

### Issue: "CSRF token missing"

**Cause**: API calls without CSRF token

**Solution**:
- For browser usage: Should work automatically
- For API usage: Login endpoint is exempt from CSRF
- Other endpoints: Include CSRF token in headers

### Issue: Container won't start

**Check logs**:
```bash
docker logs chrontainer
```

**Common causes**:
- Missing SECRET_KEY (warning message - will use default)
- Port 5000 already in use
- Docker socket permission issues
- Invalid .env configuration

### Issue: Performance degradation

**Check worker count**:
```bash
docker logs chrontainer | grep workers
```

**Adjust in .env**:
```bash
GUNICORN_WORKERS=4  # Set based on your CPU count
```

## Rollback Procedure

If you need to rollback to the previous version:

1. **Stop current container**
   ```bash
   docker-compose down
   ```

2. **Checkout previous version**
   ```bash
   git checkout <previous-commit-hash>
   ```

3. **Rebuild and start**
   ```bash
   docker-compose up -d --build
   ```

4. **Verify**
   ```bash
   docker logs chrontainer
   ```

## What's Next

After upgrading, consider:

1. ✅ **Set up automated backups** (see `docs/PRODUCTION_DEPLOYMENT.md`)
2. ✅ **Configure HTTPS** via reverse proxy
3. ✅ **Review security guide** (`docs/SECURITY.md`)
4. ✅ **Enable Discord notifications** (if not already)
5. ✅ **Set up monitoring** (health checks, log monitoring)

## New Files in v0.2.0

- `.env.example` - Environment configuration template
- `wsgi.py` - WSGI entry point for Gunicorn
- `gunicorn.conf.py` - Gunicorn configuration
- `chrontainer.service` - Systemd service file
- `docs/PRODUCTION_DEPLOYMENT.md` - Production deployment guide
- `docs/SECURITY.md` - Security best practices guide

## Documentation

- **Production Deployment**: See `docs/PRODUCTION_DEPLOYMENT.md`
- **Security Guide**: See `docs/SECURITY.md`
- **Roadmap**: See `ROADMAP.md` for what's next

## Support

- **Issues**: https://github.com/yourusername/chrontainer/issues
- **Discussions**: https://github.com/yourusername/chrontainer/discussions

---

**Version**: v0.2.0
**Date**: 2026-01-19
**Priority**: High (Security Update)
