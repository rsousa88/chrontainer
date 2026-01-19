# Chrontainer - Project Structure

```
chrontainer/
├── app/
│   └── main.py              # Main Flask application & scheduler logic (~3200 lines)
├── templates/
│   ├── index.html           # Main dashboard UI (~2700 lines)
│   ├── login.html           # Authentication page (~185 lines)
│   ├── hosts.html           # Docker host management (~230 lines)
│   ├── settings.html        # Settings UI (Discord, ntfy, API keys, webhooks) (~1230 lines)
│   ├── logs.html            # Activity logs page (~175 lines)
│   ├── metrics.html         # Host metrics dashboard (~320 lines)
│   └── error.html           # Error page (~80 lines)
├── tests/                   # pytest test suite
│   ├── __init__.py
│   ├── conftest.py          # Test fixtures (app, client, authenticated_client)
│   ├── test_auth.py         # Tests for authentication endpoints
│   ├── test_health.py       # Tests for /health and /api/version endpoints
│   ├── test_ntfy.py         # Tests for ntfy settings endpoints
│   ├── test_schedules.py    # Tests for schedule endpoints
│   ├── test_stats.py        # Tests for container stats endpoints
│   ├── test_api_keys.py     # Tests for API key management and auth
│   ├── test_webhooks.py     # Tests for webhook endpoints
│   └── test_host_metrics.py # Tests for host metrics endpoints
├── migrations/              # Alembic database migrations
│   ├── env.py               # Migration environment config
│   ├── script.py.mako       # Migration script template
│   ├── README               # Migration instructions
│   └── versions/
│       ├── 001_initial_schema.py  # Baseline schema migration
│       ├── 002_add_one_time_schedules.py # One-time schedule support
│       └── 003_add_api_keys.py    # API keys + webhooks tables
├── .github/
│   └── workflows/
│       └── ci.yml           # GitHub Actions CI pipeline
├── static/                  # (empty - CSS is inline in templates)
├── data/                    # Created at runtime
│   └── chrontainer.db       # SQLite database (auto-created)
├── docs/
│   ├── PRODUCTION_DEPLOYMENT.md  # Production setup guide
│   └── SECURITY.md          # Security documentation
├── wsgi.py                  # Production WSGI entry point
├── gunicorn.conf.py         # Gunicorn configuration
├── Dockerfile               # Container build instructions
├── docker-compose.yml       # Easy deployment configuration
├── docker-compose.ghcr.yml  # Deployment using GHCR image (latest tag)
├── docker-compose.macvlan.yml # Deployment with macvlan + static IP (example)
├── docker-compose.macvlan.ghcr.yml # GHCR image on macvlan (example)
├── requirements.txt         # Python dependencies
├── pytest.ini               # pytest configuration
├── alembic.ini              # Alembic configuration
├── README.md                # Full documentation
├── DEPLOYMENT.md            # Quick deployment guide
├── ROADMAP.md               # Feature roadmap & status
├── TRACKING_LOG.md          # Session change tracking
├── CLAUDE.md                # AI assistant context file
├── .gitignore              # Git ignore rules
└── .dockerignore           # Docker ignore rules
```

## Key Files

### `app/main.py` (~3200 lines)
- Flask web server with Flask-Login authentication
- Docker SDK integration (multi-host support)
- APScheduler for cron jobs
- SQLite database management
- REST API endpoints
- Container control functions (restart, start, stop, pause, unpause, update)
- Input validation and sanitization
- Discord webhook notifications
- API key authentication and webhooks
- Host metrics endpoints
- Rate limiting and CSRF protection

### `templates/index.html` (~2700 lines)
- Main dashboard interface
- Container list with status, tags, IP, stack columns
- Schedule management UI
- Multiple modals (schedule, logs, tags, web UI)
- Dark mode support with CSS variables
- Mobile responsive design (3 breakpoints)
- Client-side filtering and sorting
- Keyboard shortcuts
- JavaScript for API interactions

### `templates/login.html` (~185 lines)
- Login form with CSRF protection
- Default credentials warning
- Gradient background styling

### `templates/hosts.html` (~230 lines)
- Add/edit/delete Docker hosts
- Connection testing
- Enable/disable hosts

### `templates/settings.html` (~1230 lines)
- Discord + ntfy settings
- API key management
- Webhook management
- Host management and account password change

### `templates/metrics.html` (~320 lines)
- Host metrics dashboard (CPU, memory, disk usage)
- Metrics cards per host with auto-refresh

### `templates/logs.html` (~175 lines)
- Activity log viewer
- Shows all scheduled & manual actions
- Status indicators with timestamps

### `docker-compose.yml`
- Single-file deployment
- Volume mounts for Docker socket
- Persistent data storage
- Environment configuration

### `docker-compose.ghcr.yml`
- Deploy using the GHCR image (latest tag)
- Same volume and environment setup as the default compose

### `docker-compose.macvlan.yml`
- Static IP deployment with macvlan networking

### `docker-compose.macvlan.ghcr.yml`
- GHCR image deployment on macvlan network

### `Dockerfile`
- Multi-architecture support (ARM64 + AMD64)
- Minimal Python 3.11 base
- Optimized for Raspberry Pi

## Database Schema

### `hosts` table
```sql
- id: INTEGER PRIMARY KEY (1 = Local, cannot be deleted)
- name: TEXT UNIQUE
- url: TEXT (unix://... or tcp://...)
- enabled: INTEGER (0 or 1)
- color: TEXT (hex color)
- last_seen: TIMESTAMP
- created_at: TIMESTAMP
```

### `schedules` table
```sql
- id: INTEGER PRIMARY KEY
- host_id: INTEGER (FK to hosts)
- container_id: TEXT (Docker container ID)
- container_name: TEXT
- action: TEXT (restart/start/stop/pause/unpause)
- cron_expression: TEXT (5-part cron)
- one_time: INTEGER (0 or 1)
- run_at: TIMESTAMP (for one-time schedules)
- enabled: INTEGER (0 or 1)
- created_at: TIMESTAMP
- last_run: TIMESTAMP
- next_run: TIMESTAMP
```

### `logs` table
```sql
- id: INTEGER PRIMARY KEY
- schedule_id: INTEGER (FK to schedules, nullable for manual)
- host_id: INTEGER (FK to hosts)
- container_name: TEXT
- action: TEXT
- status: TEXT (success/error)
- message: TEXT
- timestamp: TIMESTAMP
```

### `settings` table
```sql
- key: TEXT PRIMARY KEY (e.g., 'discord_webhook_url')
- value: TEXT
- updated_at: TIMESTAMP
```

### `tags` table
```sql
- id: INTEGER PRIMARY KEY
- name: TEXT UNIQUE
- color: TEXT (hex color, default '#3498db')
- created_at: TIMESTAMP
```

### `container_tags` table (many-to-many)
```sql
- id: INTEGER PRIMARY KEY
- container_id: TEXT
- host_id: INTEGER
- tag_id: INTEGER (FK to tags, CASCADE delete)
- created_at: TIMESTAMP
- UNIQUE(container_id, host_id, tag_id)
```

### `container_webui_urls` table
```sql
- id: INTEGER PRIMARY KEY
- container_id: TEXT
- host_id: INTEGER
- url: TEXT
- created_at: TIMESTAMP
- updated_at: TIMESTAMP
- UNIQUE(container_id, host_id)
```

### `users` table
```sql
- id: INTEGER PRIMARY KEY
- username: TEXT UNIQUE
- password_hash: TEXT (bcrypt)
- role: TEXT ('admin' or 'viewer')
- created_at: TIMESTAMP
- last_login: TIMESTAMP
```

### `api_keys` table
```sql
- id: INTEGER PRIMARY KEY
- user_id: INTEGER (FK to users)
- name: TEXT
- key_hash: TEXT (SHA256)
- key_prefix: TEXT
- permissions: TEXT ('read', 'write', 'admin')
- last_used: TIMESTAMP
- expires_at: TIMESTAMP
- created_at: TIMESTAMP
```

### `webhooks` table
```sql
- id: INTEGER PRIMARY KEY
- name: TEXT
- token: TEXT UNIQUE
- container_id: TEXT (optional)
- host_id: INTEGER (optional)
- action: TEXT
- enabled: INTEGER (0 or 1)
- last_triggered: TIMESTAMP
- trigger_count: INTEGER
- created_at: TIMESTAMP
```

## Technology Stack

- **Backend**: Flask 3.0 (Python web framework)
- **Authentication**: Flask-Login + bcrypt
- **Security**: Flask-WTF (CSRF), Flask-Talisman (headers), Flask-Limiter (rate limiting)
- **Scheduler**: APScheduler 3.10 (cron-like job scheduling)
- **Docker**: Docker SDK 6.1 (container management)
- **Database**: SQLite 3 (embedded database)
- **Frontend**: Vanilla JavaScript + CSS (no frameworks)
- **Container**: Python 3.11-slim (multi-arch: ARM64 + AMD64)
- **WSGI Server**: Gunicorn (production)

## Memory Footprint

Estimated resource usage on Raspberry Pi 5:
- **RAM**: ~50-80 MB
- **CPU**: <1% idle, <5% during operations
- **Disk**: ~150 MB (image) + database growth
- **Network**: Minimal (local Docker socket only)

## Security Model

1. **Docker Socket Access**: Read-only mount (`ro` flag)
2. **Database**: Local SQLite file in mounted volume
3. **Web UI**: Session authentication via Flask-Login
4. **API**: Session auth or API key (`X-API-Key`) with read/write/admin permissions

## Development Notes

- **Restart Safe**: Schedules reload from database on startup
- **Stateless**: No in-memory state between restarts
- **Error Handling**: All container operations logged to database
- **Extensible**: Easy to add new actions or features

## Testing Checklist

- [ ] Container lists correctly on dashboard
- [ ] Manual restart/start/stop works
- [ ] Schedule creation validates cron syntax
- [ ] Schedules execute at correct times
- [ ] Enable/disable toggle works
- [ ] Schedule deletion removes from scheduler
- [ ] Logs record all actions
- [ ] Database persists after container restart
- [ ] Works on ARM64 (Raspberry Pi)
- [ ] Docker socket permissions correct

## Future Enhancements (v0.3.0+)

1. **Advanced Authentication**
   - ✅ API key authentication
   - OAuth integration (GitHub, Google)
   - Granular role-based permissions

2. **Additional Notifications**
   - Email alerts (SMTP)
   - Slack webhooks
   - ✅ ntfy.sh support
   - Custom webhook templates

3. **Monitoring & Health**
   - Container health monitoring
   - ✅ Host metrics dashboard (CPU, RAM, disk)
   - ✅ Container resource usage
   - Auto-restart on health check failure

4. **Advanced Scheduling**
   - One-time schedules (run once)
   - Schedule dependencies (A then B)
   - Scheduled container updates
   - Bulk operations (multi-select)

5. **Database & DevOps**
   - ✅ Alembic migrations
   - Backup/restore schedules
   - ✅ pytest test suite (31 tests)
   - ✅ CI/CD pipeline (GitHub Actions)

## Performance Optimization

- Database indexes on frequently queried fields
- Connection pooling for Docker SDK
- Lazy loading for container lists
- Caching container metadata

## Known Limitations

1. **Basic RBAC**: Only admin/viewer roles (no granular permissions)
2. **Limited API permissions**: API keys support only read/write/admin scopes
3. **Single action per schedule**: Can't chain multiple container actions
4. **No health monitoring**: No container health checks or auto-restart on failure
5. **No scheduled updates**: Container updates are manual only (no scheduled auto-update)
