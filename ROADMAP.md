# Chrontainer Roadmap

## Current Status: v0.1.0 (MVP)
✅ Single Docker host support
✅ Basic web UI for container management
✅ Cron-based restart scheduling
✅ SQLite persistence
✅ Activity logs
✅ Deployed on Raspberry Pi 5

---

## Phase 1: Core Features & Multi-Host Support (v0.2.0)
**Priority: High | Timeline: 2-3 weeks**

### 1.1 Multi-Host Docker Support
- [ ] Add docker hosts table (host_id, name, url, enabled)
- [ ] Host management UI (add/edit/delete hosts)
- [ ] Support TCP connections (`tcp://synology-ip:2376`)
- [ ] Test connection button for each host
- [ ] Aggregate containers view across all hosts
- [ ] Filter containers by host in UI
- [ ] Store host_id with schedules

**Technical Notes:**
- Use `docker.DockerClient(base_url='tcp://host:2376')` for remote hosts
- Need to handle connection failures gracefully
- Consider SSH tunnel support for secure connections

### 1.2 Enhanced Actions
- [ ] Start action scheduling (not just manual)
- [ ] Stop action scheduling
- [ ] Pause/unpause container actions
- [ ] Container logs viewer in UI
- [ ] Exec commands in containers (optional)

### 1.3 Basic API
- [ ] API authentication (API keys)
- [ ] RESTful endpoints for schedules (CRUD)
- [ ] RESTful endpoints for containers (list, actions)
- [ ] API documentation (Swagger/OpenAPI)
- [ ] Webhook support for external triggers

**API Endpoints:**
```
GET    /api/v1/hosts
POST   /api/v1/hosts
GET    /api/v1/containers
GET    /api/v1/schedules
POST   /api/v1/schedules
PUT    /api/v1/schedules/:id
DELETE /api/v1/schedules/:id
POST   /api/v1/containers/:id/restart
POST   /api/v1/containers/:id/start
POST   /api/v1/containers/:id/stop
```

---

## Phase 2: Notifications & Authentication (v0.3.0)
**Priority: High | Timeline: 1-2 weeks**

### 2.1 Discord Notifications
- [ ] Add notification settings to UI
- [ ] Discord webhook configuration per schedule (or global)
- [ ] Rich embeds with container info, action, status
- [ ] @mention support for failures
- [ ] Test notification button
- [ ] Notification templates (success, failure, warning)

**Discord Embed Example:**
```
✅ Schedule Executed
Container: sonarr
Action: restart
Host: raspberry-pi
Status: Success
Time: 2026-01-16 03:00:00
```

### 2.2 Authentication
- [ ] User accounts table (username, password_hash, role)
- [ ] Login/logout pages
- [ ] Session management
- [ ] Basic auth support (username/password)
- [ ] OAuth support (GitHub, Google - optional)
- [ ] Role-based access control (admin, viewer)
- [ ] API key management per user

**Security:**
- Use bcrypt for password hashing
- Flask-Login for session management
- Consider Flask-Security or Authlib

### 2.3 Additional Notifications (Optional)
- [ ] Email notifications (SMTP)
- [ ] Slack webhooks
- [ ] Telegram bot
- [ ] ntfy.sh support
- [ ] Custom webhook support

---

## Phase 3: Monitoring & Health (v0.4.0)
**Priority: Medium | Timeline: 2-3 weeks**

### 3.1 Container Health Monitoring
- [ ] Display container health status
- [ ] CPU/Memory usage metrics
- [ ] Uptime tracking
- [ ] Auto-restart on health check failure
- [ ] Health check history
- [ ] Alert on container down/unhealthy

### 3.2 Dashboard Improvements
- [ ] Statistics page (schedules run, success rate, etc.)
- [ ] Container uptime charts
- [ ] Recent activity feed
- [ ] Search/filter containers
- [ ] Dark mode toggle
- [ ] Mobile responsive design

### 3.3 Advanced Scheduling
- [ ] One-time schedules (run once, then delete)
- [ ] Schedule dependencies (restart A, then restart B)
- [ ] Conditional schedules (only if container is running)
- [ ] Retry logic on failure
- [ ] Schedule groups (restart multiple containers)
- [ ] Timezone support per schedule

---

## Phase 4: Production Hardening (v1.0.0)
**Priority: High | Timeline: 1 week**

### 4.1 Security
- [x] Generate secure SECRET_KEY
- [ ] Environment-based configuration
- [ ] HTTPS support (reverse proxy ready)
- [ ] Rate limiting on API endpoints
- [ ] Input validation and sanitization
- [ ] SQL injection prevention (parameterized queries)
- [ ] CSRF protection
- [ ] Security headers

### 4.2 Deployment
- [ ] Production WSGI server (Gunicorn/uWSGI)
- [ ] Nginx/Caddy reverse proxy config examples
- [ ] SSL/TLS certificate setup guide
- [ ] Docker Compose production template
- [ ] Environment variable documentation
- [ ] Systemd service file (non-Docker deployment)

### 4.3 Database & Backup
- [ ] Database migration system (Alembic)
- [ ] Automated daily backups
- [ ] Backup to external storage (NAS, S3)
- [ ] Database optimization (indexes)
- [ ] Log rotation
- [ ] Retention policies for logs

### 4.4 Monitoring & Observability
- [ ] Prometheus metrics endpoint
- [ ] Grafana dashboard template
- [ ] Application logging (structured logs)
- [ ] Error tracking (Sentry integration)
- [ ] Health check endpoint (`/health`)
- [ ] Version info endpoint (`/api/version`)

---

## Phase 5: Advanced Features (v2.0.0+)
**Priority: Low | Timeline: Future**

### 5.1 Advanced Automation
- [ ] Container image update detection
- [ ] Auto-pull and restart on new image
- [ ] Compose stack management
- [ ] Docker Swarm support
- [ ] Kubernetes support (future)

### 5.2 Integrations
- [ ] n8n workflow triggers
- [ ] Home Assistant integration
- [ ] Ansible playbook execution
- [ ] GitOps support (pull schedules from repo)

### 5.3 UI/UX Enhancements
- [ ] Drag-and-drop schedule builder
- [ ] Container grouping/tagging
- [ ] Bulk operations
- [ ] Schedule templates library
- [ ] Import/export schedules
- [ ] Browser notifications

### 5.4 Multi-Tenancy
- [ ] Organization/team support
- [ ] Shared schedules
- [ ] Permission management
- [ ] Audit logs

---

## Maintenance & Technical Debt

### Ongoing
- [ ] Unit tests (pytest)
- [ ] Integration tests
- [ ] E2E tests (Playwright/Selenium)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Documentation updates
- [ ] Performance optimization
- [ ] Code refactoring
- [ ] Dependency updates
- [ ] Security audits

---

## Quick Wins (Can be done anytime)
- [ ] Favicon and branding
- [ ] Better error messages
- [ ] Loading indicators in UI
- [ ] Keyboard shortcuts
- [ ] Container stats in tooltip
- [ ] Copy schedule to clipboard
- [ ] Example cron expressions in UI
- [ ] Link to crontab.guru for help
- [ ] Add filters and sorts to the table in web UI (similar to what dockpeek has)
- [ ] Dark mode

---

## Decision Log

### Multi-Host Implementation Approaches:
**Option A:** Store all host configs in database
**Option B:** Configuration file (YAML)
**Option C:** Docker Swarm/Kubernetes native

**Decision:** Option A (database) - easier to manage via UI

### Authentication Approach:
**Option A:** Build custom auth system
**Option B:** Use Flask-Security
**Option C:** OAuth only

**Decision:** Start with Option A (simple), add OAuth later

### Database Choice:
**Current:** SQLite (fine for single instance)
**Future:** Consider PostgreSQL for multi-instance deployments

---

## Version Numbering
- **v0.x.x** - Pre-release, breaking changes expected
- **v1.0.0** - First stable release (production-ready)
- **v2.0.0+** - Major features, breaking changes

---

## Contributing
Want to contribute? Check out issues tagged with:
- `good-first-issue` - Easy wins for new contributors
- `help-wanted` - Features that need implementation
- `bug` - Known bugs to fix

---

## Feedback & Suggestions
Open an issue or discussion on GitHub with your ideas!
