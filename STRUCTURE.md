# Chrontainer - Project Structure

```
chrontainer/
├── app/
│   └── main.py              # Main Flask application & scheduler logic
├── templates/
│   ├── index.html           # Main dashboard UI
│   ├── logs.html            # Activity logs page
│   └── error.html           # Error page
├── static/                  # (empty for now, CSS is inline)
├── data/                    # Created at runtime
│   └── chrontainer.db       # SQLite database (auto-created)
├── Dockerfile               # Container build instructions
├── docker-compose.yml       # Easy deployment configuration
├── requirements.txt         # Python dependencies
├── README.md                # Full documentation
├── DEPLOYMENT.md            # Quick deployment guide
├── .gitignore              # Git ignore rules
└── .dockerignore           # Docker ignore rules
```

## Key Files

### `app/main.py` (523 lines)
- Flask web server
- Docker SDK integration
- APScheduler for cron jobs
- SQLite database management
- REST API endpoints
- Container control functions

### `templates/index.html` (424 lines)
- Main dashboard interface
- Container list with status
- Schedule management UI
- Modal for creating schedules
- JavaScript for API interactions

### `templates/logs.html` (110 lines)
- Activity log viewer
- Shows all scheduled & manual actions
- Status indicators

### `docker-compose.yml`
- Single-file deployment
- Volume mounts for Docker socket
- Persistent data storage
- Environment configuration

### `Dockerfile`
- Multi-architecture support (ARM64 + AMD64)
- Minimal Python 3.11 base
- Optimized for Raspberry Pi

## Database Schema

### `schedules` table
```sql
- id: INTEGER PRIMARY KEY
- container_id: TEXT (Docker container ID)
- container_name: TEXT
- action: TEXT (restart/start/stop)
- cron_expression: TEXT (5-part cron)
- enabled: INTEGER (0 or 1)
- created_at: TIMESTAMP
- last_run: TIMESTAMP
- next_run: TIMESTAMP
```

### `logs` table
```sql
- id: INTEGER PRIMARY KEY
- schedule_id: INTEGER (FK to schedules)
- container_name: TEXT
- action: TEXT
- status: TEXT (success/error)
- message: TEXT
- timestamp: TIMESTAMP
```

## Technology Stack

- **Backend**: Flask 3.0 (Python web framework)
- **Scheduler**: APScheduler 3.10 (cron-like job scheduling)
- **Docker**: Docker SDK 7.0 (container management)
- **Database**: SQLite 3 (embedded database)
- **Frontend**: Vanilla JavaScript + CSS
- **Container**: Python 3.11-slim

## Memory Footprint

Estimated resource usage on Raspberry Pi 5:
- **RAM**: ~50-80 MB
- **CPU**: <1% idle, <5% during operations
- **Disk**: ~150 MB (image) + database growth
- **Network**: Minimal (local Docker socket only)

## Security Model

1. **Docker Socket Access**: Read-only mount (`ro` flag)
2. **Database**: Local SQLite file in mounted volume
3. **Web UI**: No authentication (local network only)
4. **API**: No authentication (consider reverse proxy for production)

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

## Future Enhancements (v2.0+)

1. **Multi-host Support**
   - Remote Docker hosts via TCP
   - Host management UI
   - Credential storage

2. **Authentication**
   - Basic auth
   - OAuth integration
   - Role-based access

3. **Notifications**
   - Email alerts
   - Slack webhooks
   - Discord integration

4. **Advanced Features**
   - Container health monitoring
   - Log viewer integration
   - Backup/restore schedules
   - Statistics dashboard
   - One-time schedules
   - Conditional restarts

5. **UI Improvements**
   - Dark mode
   - Mobile responsive
   - Container grouping
   - Search/filter

## Performance Optimization

- Database indexes on frequently queried fields
- Connection pooling for Docker SDK
- Lazy loading for container lists
- Caching container metadata

## Known Limitations

1. **No authentication**: Deploy in trusted network only
2. **Local only**: Remote Docker hosts not yet supported
3. **Restart only**: Other actions (start/stop) exist but limited scheduling
4. **No notifications**: Failed schedules only logged
5. **Single action**: Can't chain multiple container actions
