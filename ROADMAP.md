# Chrontainer Roadmap

## Current Status: v0.2.0 (Production Ready)
✅ Single Docker host support
✅ Basic web UI for container management
✅ Cron-based scheduling (restart, start, stop, pause, unpause)
✅ SQLite persistence
✅ Activity logs
✅ Deployed on Raspberry Pi 5
✅ Multi-host Docker support
✅ Discord notifications
✅ Authentication (login/logout with bcrypt)
✅ Container tags with colors
✅ Container update management (check + update)
✅ Dark mode
✅ Mobile responsive design
✅ Production hardening (CSRF, rate limiting, security headers)
✅ Comprehensive documentation

---

## Phase 1: Core Features & Multi-Host Support (v0.2.0)
**Priority: High | Status: COMPLETED**

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
POST   /api/container/<id>/pause
POST   /api/container/<id>/unpause
GET    /api/container/<id>/<host_id>/logs

# Schedules
POST   /api/schedule
DELETE /api/schedule/<id>
POST   /api/schedule/<id>/toggle

# Hosts
GET    /api/hosts
POST   /api/hosts
PUT    /api/hosts/<id>
DELETE /api/hosts/<id>
POST   /api/hosts/<id>/test

# Tags
GET    /api/tags
POST   /api/tags
DELETE /api/tags/<id>
GET    /api/containers/<id>/<host_id>/tags
POST   /api/containers/<id>/<host_id>/tags
DELETE /api/containers/<id>/<host_id>/tags/<tag_id>

# Web UI URLs
GET    /api/containers/<id>/<host_id>/webui
POST   /api/containers/<id>/<host_id>/webui

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
**Priority: High | Status: Partially Completed (Discord + Basic Auth done)**

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

### 2.2 Authentication ✅ PARTIALLY COMPLETED
- [x] User accounts table (username, password_hash, role)
- [x] Login/logout pages
- [x] Session management (Flask-Login)
- [x] Basic auth support (username/password with bcrypt)
- [ ] OAuth support (GitHub, Google - optional)
- [x] Role-based access control (admin, viewer - basic implementation)
- [ ] API key management per user

**Security (Implemented):**
- ✅ bcrypt for password hashing
- ✅ Flask-Login for session management
- ✅ Rate limiting on login (10/min)
- ✅ CSRF protection via Flask-WTF

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
- [x] Search/filter containers (name, status, host, stack, tags)
- [x] Dark mode toggle (with localStorage persistence)
- [x] Mobile responsive design (3 breakpoints: desktop, tablet, mobile)

### 3.3 Advanced Scheduling
- [ ] One-time schedules (run once, then delete)
- [ ] Schedule dependencies (restart A, then restart B)
- [ ] Conditional schedules (only if container is running)
- [ ] Retry logic on failure
- [ ] Schedule groups (restart multiple containers)
- [ ] Timezone support per schedule

---

## Phase 4: Production Hardening (v1.0.0)
**Priority: High | Status: COMPLETED (Security & Deployment done)**

### 4.1 Security ✅ COMPLETED
- [x] Generate secure SECRET_KEY
- [x] Environment-based configuration (.env support)
- [x] HTTPS support (reverse proxy ready via Flask-Talisman)
- [x] Rate limiting on API endpoints (Flask-Limiter)
- [x] Input validation and sanitization (comprehensive validators)
- [x] SQL injection prevention (parameterized queries)
- [x] CSRF protection (Flask-WTF)
- [x] Security headers (X-Frame-Options, X-Content-Type-Options, etc.)

### 4.2 Deployment ✅ COMPLETED
- [x] Production WSGI server (Gunicorn)
- [x] Nginx/Caddy reverse proxy config examples
- [x] SSL/TLS certificate setup guide
- [x] Docker Compose production template
- [x] Environment variable documentation (.env.example)
- [x] Systemd service file (non-Docker deployment)

**Implementation Notes:**
- ✅ Gunicorn WSGI server with automatic worker scaling
- ✅ Environment-based configuration with python-dotenv
- ✅ CSRF protection via Flask-WTF on all POST endpoints
- ✅ Flask-Talisman for HTTPS enforcement (optional)
- ✅ Flask-Limiter for rate limiting (60/min global, 10/min login)
- ✅ Comprehensive input validation (container IDs, names, URLs, cron)
- ✅ Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- ✅ Sanitization of all user inputs (remove control chars, length limits)
- ✅ Login endpoint rate limited to prevent brute force
- ✅ All sensitive endpoints require authentication
- ✅ Complete production deployment documentation
- ✅ Security best practices guide

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
- [x] Container grouping/tagging (custom tags with colors)
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
- [x] Better error messages
- [x] Loading indicators in UI
- [x] Keyboard shortcuts (?, r, f, m, t, c, Esc)
- [x] Container stats in tooltip
- [x] Copy schedule to clipboard
- [x] Example cron expressions in UI (in schedule modal)
- [x] Link to crontab.guru for help (mentioned in UI)

---

# Human Feedback
## High Priority Bugs
- [x] [...] (removed already implemented items from this list)
- [x] For containers in the synology NAS host (connected through socket-proxy), I'm getting the following error when checking for updates: "Registry error: 403 Client Error for http://192.168.1.100:2375/v1.43/distribution/dockpeek/dockpeek:latest/json: Forbidden ("b'<html><body><h1>403 Forbidden</h1>\nRequest forbidden by administrative rules.\n</body></html>'")"

## Immediate Improvements
- [x] [...] (removed already implemented items from this list)
- [x] [Feature] Show containers current version. I want to see the actual version (e.g. v2.3.7) and not the tag (e.g. latest)
- [x] [Feature] Show new version if update available (check for updates + update button). I want to see the actual version (e.g. v2.3.7) and not the tag (e.g. latest)
- [x] [Feature] Remove the tag from the image (e.g. SOME_IMAGE:latest -> SOME_IMAGE)
- [x] [Feature] Ability to select multiple containers and apply actions to the selection (applicable actions only)
- [x] [Dev] Add another sample docker-compose file to create the container but connect to a macvlan network and using a static IP address
- [x] [UI/UX] Replace common 'Actions' column by a common set of buttons on top. The buttons will execute for all selected containers. This assumes that the selection of containers feature is already implemented. Logs action is the exception as it doesn't make much sense to be applied to multiple containers at once. Keep the Logs and the Check (update) buttons in the table, but make them smaller and integrated similar to the link to docker hub and github. This would be especially important in smaller screens, to minimize the amount of horizontal scrolling. As an alternative add a dropdown with all quick actions
- [x] [UI/UX] Set Tags and Web UI buttons can also be made smaller and similar to the previous buttons. Let's call these Quick Actions and group all these buttons in a single column with just an icon and a tooltip. This would be especially important in smaller screens, to minimize the amount of horizontal scrolling. As an alternative add a dropdown with all quick actions
- [x] [UI/UX] Standardize tooltips so the app uses the fast, custom tooltip system consistently
- [x] [UI/UX] I haven't seen any container with status unhealthy. If you're not showing these additional status yet, implement it

## Low Priority Improvements
- [ ] [Monitoring] Host metrics dashboard page
- [ ] [Monitoring] If possible, include resource usage from each container (not sure if this data is provided through the docker API but it would be awesome to have at least the RAM usage in real-time or near real-time)

## Evolutions (long term, after stabilization of core features)
- [ ] The app could evolve into a full-featured container management app (inspired in Portainer but leaner, better and easier to use and with responsive UI):
  - [ ] 1. list/create/update/delete stacks/projects/another term?, using docker compose directly in the app
  - [ ] 2. list/create/update/delete containers (container page with all details, including a compose file automatically maintained by the system based on the details of the container, even for containers created without compose)
  - [ ] 3. list/create/update/delete networks (including macvlan's for supported hosts)
  - [ ] 4. list/delete images
  - [ ] 5. list/delete volumes
  - [ ] 6. quickly delete unused stacks, containers, images and volumes (prune action?)

---

# Versioning
## Recent Additions (v0.2.0)

### Custom Tags System ✅
- Create/delete global tags with custom colors
- Assign multiple tags to containers
- Tag filtering in table
- Color-coded tag badges
- Database: `tags` and `container_tags` tables

### Web UI URLs ✅
- Set custom Web UI URL per container
- Auto-read from Docker label (`chrontainer.webui.url`)
- Manual URLs take precedence over labels
- Globe icon (🌐) for quick access
- Opens in new tab
- Database: `container_webui_urls` table

### Image Registry & Documentation Links ✅
- Auto-generated links from image names
- Registry links (Docker Hub, ghcr.io, gcr.io)
- GitHub links for known publishers
- Documentation links (linuxserver, etc.)
- Icons: 📦 (registry), GitHub logo, 📚 (docs)

### Enhanced Table & Filtering ✅
- Stack column (Docker Compose project name)
- IP Address column with numeric sorting
- Tags column with inline badges
- Web UI column with quick links
- Filter by: name, status, host, stack, tags
- Sort by: name, host, stack, IP, status, image
- Clear filters button
- Manage Tags button

### Dark Mode ✅
- Toggle button in header (🌙/☀️)
- CSS variables for theme consistency
- LocalStorage persistence
- Smooth transitions

### Host Management Improvements ✅
- Edit host functionality
- PUT /api/hosts/<id> endpoint
- Connection test before saving changes

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
