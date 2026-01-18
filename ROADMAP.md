# Chrontainer Roadmap

## Current Status: v0.2.0-dev (Multi-Host Support)
✅ Single Docker host support
✅ Basic web UI for container management
✅ Cron-based restart scheduling
✅ SQLite persistence
✅ Activity logs
✅ Deployed on Raspberry Pi 5
✅ Multi-host Docker support
✅ Discord notifications
✅ Comprehensive documentation

---

## Phase 1: Core Features & Multi-Host Support (v0.2.0)
**Priority: High | Status: In Progress**

### 1.1 Multi-Host Docker Support ✅ COMPLETED
- [x] Add docker hosts table (host_id, name, url, enabled)
- [x] Host management UI (add/edit/delete hosts)
- [x] Support TCP connections (`tcp://host:2375` via socket-proxy)
- [x] Test connection button for each host
- [x] Aggregate containers view across all hosts
- [x] Show host badges in container list
- [x] Store host_id with schedules
- [x] Docker socket proxy setup documentation
- [x] Security best practices documentation

**Implementation Notes:**
- ✅ Used `DockerHostManager` class with connection caching
- ✅ Socket-proxy required for remote hosts (security)
- ✅ Graceful handling of connection failures
- ⏳ SSH tunnel support - planned for future

### 1.2 Enhanced Actions ✅ COMPLETED
- [x] Start action scheduling (not just manual)
- [x] Stop action scheduling
- [x] Pause/unpause container actions
- [x] Pause/unpause manual buttons in UI
- [x] Container logs viewer in UI with refresh and configurable tail
- [ ] Exec commands in containers (deferred - security concerns)

**Implementation Notes:**
- ✅ All container actions (restart, start, stop, pause, unpause) support both manual and scheduled execution
- ✅ Action selection dropdown in schedule modal
- ✅ Logs viewer with dark theme, line count selection (50-1000), and refresh capability
- ✅ Discord notifications for all actions
- ⏳ Exec deferred due to security implications

### 1.3 Basic API (Partially Completed)
- [ ] API authentication (API keys)
- [x] RESTful endpoints for schedules (CRUD)
- [x] RESTful endpoints for containers (list, actions)
- [x] RESTful endpoints for hosts management
- [x] RESTful endpoints for settings
- [ ] API documentation (Swagger/OpenAPI)
- [ ] Webhook support for external triggers
- [ ] API versioning (currently no /v1 prefix)

**Current API Endpoints:**
```
# Containers
GET    /api/containers
POST   /api/container/<id>/restart
POST   /api/container/<id>/start
POST   /api/container/<id>/stop

# Schedules
POST   /api/schedule
DELETE /api/schedule/<id>
POST   /api/schedule/<id>/toggle

# Hosts
GET    /api/hosts
POST   /api/hosts
DELETE /api/hosts/<id>
POST   /api/hosts/<id>/test

# Settings
GET    /api/settings
POST   /api/settings/discord
POST   /api/settings/discord/test
```

**TODO:**
- Add API authentication layer
- Add OpenAPI/Swagger documentation
- Consider adding /api/v1 prefix for versioning

---

## Phase 2: Notifications & Authentication (v0.3.0)
**Priority: High | Status: Partially Completed**

### 2.1 Discord Notifications ✅ COMPLETED
- [x] Add notification settings to UI
- [x] Discord webhook configuration (global)
- [x] Rich embeds with container info, action, status, color-coded
- [x] Test notification button
- [x] Notifications for manual and scheduled actions
- [ ] Per-schedule webhook override (optional enhancement)
- [ ] @mention support for failures
- [ ] Notification templates (currently hardcoded)

**Implementation Notes:**
- ✅ Settings page with webhook URL configuration
- ✅ Color-coded embeds: blue (info), green (success), red (error)
- ✅ Includes container name, action, host, timestamp
- ✅ Integrated into all container actions (start, stop, restart)

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
- [x] Favicon and branding
- [ ] Better error messages
- [x] Loading indicators in UI
- [ ] Keyboard shortcuts
- [x] Container stats in tooltip
- [ ] Copy schedule to clipboard
- [x] Example cron expressions in UI (in schedule modal)
- [x] Link to crontab.guru for help (mentioned in UI)

---

## Additional features to consider
- [ ] [UI/UX] Add filters and sorts to the table in web UI (similar to what dockpeek has)
- [ ] [UI/UX] Dark mode
- [ ] [Updates] Be able to check for updates to containers and directly update them from the web UI (similar to dockpeek)
- [ ] [Hosts] Ability to edit hosts
- [ ] [UI/UX] Ability to add tags to containers and then allow filtering by tag
- [ ] [UI/UX] Add column to dashboard table that show the name of the stack that a container belongs to
- [ ] [UI/UX] Ability to add a web UI URL to each container in the table, so users can quickly open the container interface from the dashboard
- [ ] [UI/UX] Add links to registry and github/code and/or docs next to each image (like dockpeek)
- [ ] [Monitoring] Host metrics dashboard page
- [ ] [Monitoring] If possible, include resource usage from each container (not sure if this data is provided through the docker API but it would be awesome to have at least the RAM usage in real-time or near real-time)
- [ ] [UI/UX] Include a version label in the UI
- [ ] If possible, add the IP address of each container in a new column in the table

---

## Issues/Improvements
- [x] [UI/UX] Increase the width of the logs modal (900px → 1200px)
- [x] [UI/UX] Increase the width of the logs modal even more (80% or 90% of total width)
- [x] [UI/UX] After opening the logs modal, the scroll is still being done in the main body. The logs control should be automatically selected so the scroll can work without having to click in it (auto-focus added)
  - [x] UPDATE: This is not fixed yet, the focus is still not being applied to the logs modal content and scroll is only working in the logs content after a click
- [x] [UI/UX] Clicking outside of the logs modal should close it (backdrop click handler added)
- [x] [Bug] some container images are not identified (in the dashboard table just says 'unknown' in the image column). Fixed with fallback logic: tags → Config.Image → short image ID

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
