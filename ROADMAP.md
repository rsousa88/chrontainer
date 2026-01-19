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
✅ Health check endpoint (`/health`)
✅ Version info endpoint (`/api/version`)
✅ pytest test suite (22 tests)
✅ GitHub Actions CI/CD with auto-releases
✅ Alembic database migrations

---

# v0.3.0 Implementation Plan

## Overview
**Focus:** Container Resource Monitoring + One-Time Schedules + ntfy.sh Notifications
**Developer:** ChatGPT
**Architect:** Claude

---

## Feature 1: Container Resource Monitoring (CPU/Memory)

### 1.1 Goal
Display real-time CPU and memory usage for each container in the dashboard table.

### 1.2 Technical Background
The Docker API provides container stats via `container.stats(stream=False)`. This returns:
```python
{
    'cpu_stats': {
        'cpu_usage': {'total_usage': 123456789},
        'system_cpu_usage': 987654321,
        'online_cpus': 4
    },
    'precpu_stats': {
        'cpu_usage': {'total_usage': 123456000},
        'system_cpu_usage': 987654000
    },
    'memory_stats': {
        'usage': 52428800,  # bytes
        'limit': 8589934592  # bytes (total available)
    }
}
```

**CPU Calculation Formula:**
```python
cpu_delta = cpu_stats['cpu_usage']['total_usage'] - precpu_stats['cpu_usage']['total_usage']
system_delta = cpu_stats['system_cpu_usage'] - precpu_stats['system_cpu_usage']
cpu_percent = (cpu_delta / system_delta) * online_cpus * 100
```

**Memory Calculation:**
```python
memory_percent = (memory_stats['usage'] / memory_stats['limit']) * 100
memory_mb = memory_stats['usage'] / (1024 * 1024)
```

### 1.3 Implementation Steps

#### Step 1: Add Stats Endpoint in `app/main.py`

**Location:** After the `/api/container/<container_id>/logs` endpoint (around line 1455)

**New Endpoint:**
```python
@app.route('/api/container/<container_id>/stats', methods=['GET'])
@login_required
def api_get_container_stats(container_id):
    """API endpoint to get container resource stats"""
    host_id = request.args.get('host_id', 1, type=int)

    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            return jsonify({'error': 'Cannot connect to Docker host'}), 500

        container = docker_client.containers.get(container_id)

        # Only get stats for running containers
        if container.status != 'running':
            return jsonify({
                'cpu_percent': None,
                'memory_percent': None,
                'memory_mb': None,
                'status': container.status
            })

        # Get stats (non-streaming for single snapshot)
        stats = container.stats(stream=False)

        # Calculate CPU percentage
        cpu_percent = 0.0
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
            online_cpus = stats['cpu_stats'].get('online_cpus', 1)
            if system_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * online_cpus * 100
        except (KeyError, ZeroDivisionError):
            cpu_percent = 0.0

        # Calculate memory usage
        memory_percent = 0.0
        memory_mb = 0.0
        try:
            memory_usage = stats['memory_stats'].get('usage', 0)
            memory_limit = stats['memory_stats'].get('limit', 1)
            # Subtract cache if available (more accurate)
            cache = stats['memory_stats'].get('stats', {}).get('cache', 0)
            memory_usage = memory_usage - cache
            memory_percent = (memory_usage / memory_limit) * 100
            memory_mb = memory_usage / (1024 * 1024)
        except (KeyError, ZeroDivisionError):
            pass

        return jsonify({
            'cpu_percent': round(cpu_percent, 1),
            'memory_percent': round(memory_percent, 1),
            'memory_mb': round(memory_mb, 1),
            'status': container.status
        })

    except docker.errors.NotFound:
        return jsonify({'error': 'Container not found'}), 404
    except Exception as e:
        logger.error(f"Failed to get stats for container {container_id}: {e}")
        return jsonify({'error': str(e)}), 500
```

#### Step 2: Add Bulk Stats Endpoint

**Location:** After the single stats endpoint

**Purpose:** Fetch stats for all containers in one call (more efficient)

```python
@app.route('/api/containers/stats', methods=['GET'])
@login_required
def api_get_all_container_stats():
    """API endpoint to get stats for all running containers"""
    results = {}

    for host_id, host_name, docker_client in docker_manager.get_all_clients():
        try:
            containers = docker_client.containers.list(all=False)  # Only running
            for container in containers:
                container_id = container.id[:12]
                try:
                    stats = container.stats(stream=False)

                    # CPU
                    cpu_percent = 0.0
                    try:
                        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
                        system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
                        online_cpus = stats['cpu_stats'].get('online_cpus', 1)
                        if system_delta > 0:
                            cpu_percent = (cpu_delta / system_delta) * online_cpus * 100
                    except (KeyError, ZeroDivisionError):
                        pass

                    # Memory
                    memory_percent = 0.0
                    memory_mb = 0.0
                    try:
                        memory_usage = stats['memory_stats'].get('usage', 0)
                        memory_limit = stats['memory_stats'].get('limit', 1)
                        cache = stats['memory_stats'].get('stats', {}).get('cache', 0)
                        memory_usage = memory_usage - cache
                        memory_percent = (memory_usage / memory_limit) * 100
                        memory_mb = memory_usage / (1024 * 1024)
                    except (KeyError, ZeroDivisionError):
                        pass

                    results[f"{container_id}_{host_id}"] = {
                        'cpu_percent': round(cpu_percent, 1),
                        'memory_percent': round(memory_percent, 1),
                        'memory_mb': round(memory_mb, 1)
                    }
                except Exception as e:
                    logger.debug(f"Failed to get stats for {container.name}: {e}")
        except Exception as e:
            logger.error(f"Failed to get containers from host {host_name}: {e}")

    return jsonify(results)
```

#### Step 3: Update UI in `templates/index.html`

**3a. Add CPU/Memory columns to the table header**

Find the table header row (search for `<th>Status</th>`) and add after it:
```html
<th class="sortable" data-sort="cpu" style="width: 70px;">CPU</th>
<th class="sortable" data-sort="memory" style="width: 80px;">Memory</th>
```

**3b. Add CPU/Memory cells to table body**

Find the table row template where container data is rendered. After the status cell, add:
```html
<td class="stats-cell" data-container-id="{{ container.id }}" data-host-id="{{ container.host_id }}">
    <span class="cpu-value">-</span>
</td>
<td class="stats-cell" data-container-id="{{ container.id }}" data-host-id="{{ container.host_id }}">
    <span class="memory-value">-</span>
</td>
```

**3c. Add JavaScript to fetch and update stats**

Add to the script section:
```javascript
// Fetch container stats periodically
function fetchContainerStats() {
    fetch('/api/containers/stats', {
        headers: { 'X-CSRFToken': csrfToken }
    })
    .then(response => response.json())
    .then(data => {
        document.querySelectorAll('.stats-cell').forEach(cell => {
            const containerId = cell.dataset.containerId;
            const hostId = cell.dataset.hostId;
            const key = `${containerId}_${hostId}`;
            const stats = data[key];

            if (cell.querySelector('.cpu-value')) {
                if (stats && stats.cpu_percent !== null) {
                    cell.querySelector('.cpu-value').textContent = stats.cpu_percent + '%';
                    cell.querySelector('.cpu-value').className = 'cpu-value' +
                        (stats.cpu_percent > 80 ? ' high' : stats.cpu_percent > 50 ? ' medium' : '');
                } else {
                    cell.querySelector('.cpu-value').textContent = '-';
                }
            }

            if (cell.querySelector('.memory-value')) {
                if (stats && stats.memory_mb !== null) {
                    const memStr = stats.memory_mb > 1024
                        ? (stats.memory_mb / 1024).toFixed(1) + ' GB'
                        : stats.memory_mb.toFixed(0) + ' MB';
                    cell.querySelector('.memory-value').textContent = memStr;
                    cell.querySelector('.memory-value').className = 'memory-value' +
                        (stats.memory_percent > 80 ? ' high' : stats.memory_percent > 50 ? ' medium' : '');
                } else {
                    cell.querySelector('.memory-value').textContent = '-';
                }
            }
        });
    })
    .catch(err => console.error('Failed to fetch stats:', err));
}

// Fetch stats every 10 seconds
setInterval(fetchContainerStats, 10000);
// Initial fetch
setTimeout(fetchContainerStats, 1000);
```

**3d. Add CSS for stats display**

Add to the style section:
```css
.cpu-value, .memory-value {
    font-family: monospace;
    font-size: 0.85em;
}
.cpu-value.high, .memory-value.high {
    color: var(--danger-color, #e74c3c);
    font-weight: bold;
}
.cpu-value.medium, .memory-value.medium {
    color: var(--warning-color, #f39c12);
}
```

#### Step 4: Add Tests

**File:** `tests/test_stats.py`

```python
"""Tests for container stats endpoints"""
import json


class TestStatsEndpoint:
    """Tests for /api/container/<id>/stats endpoint"""

    def test_stats_endpoint_requires_auth(self, client):
        """Stats endpoint should require authentication"""
        response = client.get('/api/container/abc123/stats?host_id=1')
        assert response.status_code == 302  # Redirect to login

    def test_stats_endpoint_returns_json(self, authenticated_client):
        """Stats endpoint should return JSON"""
        response = authenticated_client.get('/api/container/abc123/stats?host_id=1')
        assert response.content_type == 'application/json'


class TestBulkStatsEndpoint:
    """Tests for /api/containers/stats endpoint"""

    def test_bulk_stats_requires_auth(self, client):
        """Bulk stats should require authentication"""
        response = client.get('/api/containers/stats')
        assert response.status_code == 302

    def test_bulk_stats_returns_dict(self, authenticated_client):
        """Bulk stats should return a dictionary"""
        response = authenticated_client.get('/api/containers/stats')
        data = json.loads(response.data)
        assert isinstance(data, dict)
```

### 1.4 Important Notes for Developer

1. **Performance:** The `container.stats(stream=False)` call takes ~1 second per container. The bulk endpoint should be used for efficiency.

2. **Error Handling:** Always wrap stats calls in try/except - some containers may not have stats available.

3. **Cache Subtraction:** Subtract cache from memory usage for accurate "working memory" calculation.

4. **Non-Running Containers:** Return null values for stopped/paused containers, not errors.

5. **Do NOT modify existing sorting logic** - just add the new columns to the sortable array.

---

## Feature 2: One-Time Schedules

### 2.1 Goal
Allow users to create schedules that run once and then auto-delete.

### 2.2 Database Schema Change

**Migration File:** `migrations/versions/002_add_one_time_schedules.py`

```python
"""Add one-time schedule support

Revision ID: 002
Revises: 001
Create Date: 2026-01-XX
"""
from alembic import op
import sqlalchemy as sa

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add one_time column to schedules table
    op.add_column('schedules', sa.Column('one_time', sa.Integer, default=0))
    # Add run_at column for one-time schedules (stores datetime instead of cron)
    op.add_column('schedules', sa.Column('run_at', sa.DateTime, nullable=True))


def downgrade() -> None:
    op.drop_column('schedules', 'one_time')
    op.drop_column('schedules', 'run_at')
```

**Also update `init_db()` in main.py** - add migration logic after existing migrations:
```python
# Migration: Add one_time column to schedules if needed
cursor.execute("PRAGMA table_info(schedules)")
columns = [col[1] for col in cursor.fetchall()]
if 'one_time' not in columns:
    logger.info("Migrating schedules table - adding one_time column")
    cursor.execute('ALTER TABLE schedules ADD COLUMN one_time INTEGER DEFAULT 0')
if 'run_at' not in columns:
    logger.info("Migrating schedules table - adding run_at column")
    cursor.execute('ALTER TABLE schedules ADD COLUMN run_at TIMESTAMP')
```

### 2.3 Backend Changes

#### Step 1: Modify `add_schedule()` endpoint in `app/main.py`

Update the endpoint to accept `one_time` and `run_at` parameters:

```python
@app.route('/api/schedule', methods=['POST'])
@login_required
def add_schedule():
    """Add a new schedule"""
    data = request.json
    container_id = sanitize_string(data.get('container_id', ''), max_length=64)
    container_name = sanitize_string(data.get('container_name', ''), max_length=255)
    action = sanitize_string(data.get('action', 'restart'), max_length=20)
    cron_expression = sanitize_string(data.get('cron_expression', ''), max_length=50)
    host_id = data.get('host_id', 1)
    one_time = data.get('one_time', False)
    run_at = data.get('run_at')  # ISO format datetime string

    # Validate container ID
    valid, error = validate_container_id(container_id)
    if not valid:
        return jsonify({'error': error}), 400

    # Validate container name
    valid, error = validate_container_name(container_name)
    if not valid:
        return jsonify({'error': error}), 400

    # Validate action
    if action not in ['restart', 'start', 'stop', 'pause', 'unpause', 'update']:
        return jsonify({'error': 'Invalid action'}), 400

    # For one-time schedules, validate run_at datetime
    if one_time:
        if not run_at:
            return jsonify({'error': 'run_at is required for one-time schedules'}), 400
        try:
            run_at_dt = datetime.fromisoformat(run_at.replace('Z', '+00:00'))
            if run_at_dt <= datetime.now(run_at_dt.tzinfo):
                return jsonify({'error': 'run_at must be in the future'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid run_at format. Use ISO format.'}), 400
    else:
        # Validate cron expression for recurring schedules
        valid, error = validate_cron_expression(cron_expression)
        if not valid:
            return jsonify({'error': error}), 400

        try:
            parts = cron_expression.split()
            trigger = CronTrigger(
                minute=parts[0],
                hour=parts[1],
                day=parts[2],
                month=parts[3],
                day_of_week=parts[4]
            )
        except Exception:
            return jsonify({'error': 'Invalid cron expression'}), 400

    # Save to database
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO schedules
               (host_id, container_id, container_name, action, cron_expression, one_time, run_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (host_id, container_id, container_name, action,
             cron_expression if not one_time else '',
             1 if one_time else 0,
             run_at if one_time else None)
        )
        schedule_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Add to scheduler
        action_map = {
            'restart': restart_container,
            'start': start_container,
            'stop': stop_container,
            'pause': pause_container,
            'unpause': unpause_container,
            'update': update_container
        }
        action_func = action_map.get(action)

        if one_time:
            # Use DateTrigger for one-time execution
            from apscheduler.triggers.date import DateTrigger
            trigger = DateTrigger(run_date=run_at_dt)

            # Wrap action to delete schedule after execution
            def one_time_action(cid, cname, sid, hid):
                action_func(cid, cname, sid, hid)
                # Delete the schedule after execution
                try:
                    conn = get_db()
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM schedules WHERE id = ?', (sid,))
                    conn.commit()
                    conn.close()
                    logger.info(f"One-time schedule {sid} executed and deleted")
                except Exception as e:
                    logger.error(f"Failed to delete one-time schedule {sid}: {e}")

            scheduler.add_job(
                one_time_action,
                trigger,
                args=[container_id, container_name, schedule_id, host_id],
                id=f"schedule_{schedule_id}",
                replace_existing=True
            )
        else:
            # Use CronTrigger for recurring schedules
            scheduler.add_job(
                action_func,
                trigger,
                args=[container_id, container_name, schedule_id, host_id],
                id=f"schedule_{schedule_id}",
                replace_existing=True
            )

        logger.info(f"Added {'one-time' if one_time else 'recurring'} schedule {schedule_id}")
        return jsonify({'success': True, 'schedule_id': schedule_id})
    except Exception as e:
        logger.error(f"Failed to add schedule: {e}")
        return jsonify({'error': 'Failed to create schedule'}), 500
```

#### Step 2: Update `load_schedules()` function

Modify to handle both cron and one-time schedules:

```python
def load_schedules():
    """Load all enabled schedules from database and add to scheduler"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, host_id, container_id, container_name, action, cron_expression, one_time, run_at
        FROM schedules WHERE enabled = 1
    ''')
    schedules = cursor.fetchall()
    conn.close()

    for schedule in schedules:
        schedule_id, host_id, container_id, container_name, action, cron_expr, one_time, run_at = schedule

        try:
            action_map = {
                'restart': restart_container,
                'start': start_container,
                'stop': stop_container,
                'pause': pause_container,
                'unpause': unpause_container,
                'update': update_container
            }
            action_func = action_map.get(action)
            if not action_func:
                logger.error(f"Unknown action '{action}' for schedule {schedule_id}")
                continue

            if one_time and run_at:
                # One-time schedule
                from apscheduler.triggers.date import DateTrigger
                run_at_dt = datetime.fromisoformat(run_at) if isinstance(run_at, str) else run_at

                # Skip if already past
                if run_at_dt <= datetime.now():
                    logger.info(f"Skipping past one-time schedule {schedule_id}")
                    continue

                trigger = DateTrigger(run_date=run_at_dt)

                def one_time_action(cid, cname, sid, hid, func=action_func):
                    func(cid, cname, sid, hid)
                    try:
                        conn = get_db()
                        cursor = conn.cursor()
                        cursor.execute('DELETE FROM schedules WHERE id = ?', (sid,))
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        logger.error(f"Failed to delete one-time schedule {sid}: {e}")

                scheduler.add_job(
                    one_time_action,
                    trigger,
                    args=[container_id, container_name, schedule_id, host_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True
                )
                logger.info(f"Loaded one-time schedule {schedule_id}: {container_name} at {run_at}")
            else:
                # Recurring cron schedule
                parts = cron_expr.split()
                if len(parts) != 5:
                    logger.error(f"Invalid cron for schedule {schedule_id}")
                    continue

                trigger = CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4]
                )
                scheduler.add_job(
                    action_func,
                    trigger,
                    args=[container_id, container_name, schedule_id, host_id],
                    id=f"schedule_{schedule_id}",
                    replace_existing=True
                )
                logger.info(f"Loaded schedule {schedule_id}: {container_name} - {action} - {cron_expr}")
        except Exception as e:
            logger.error(f"Failed to load schedule {schedule_id}: {e}")
```

### 2.4 UI Changes in `templates/index.html`

#### Step 1: Update Schedule Modal

Find the schedule modal form and add a toggle for one-time vs recurring:

```html
<!-- Add after action select -->
<div class="form-group">
    <label>Schedule Type</label>
    <div class="schedule-type-toggle">
        <label>
            <input type="radio" name="scheduleType" value="recurring" checked onchange="toggleScheduleType()">
            Recurring (Cron)
        </label>
        <label>
            <input type="radio" name="scheduleType" value="one_time" onchange="toggleScheduleType()">
            One-Time
        </label>
    </div>
</div>

<div id="cronInputGroup" class="form-group">
    <label for="scheduleInput">Cron Expression</label>
    <input type="text" id="scheduleInput" placeholder="0 2 * * *" required>
    <small>Format: minute hour day month day_of_week</small>
</div>

<div id="dateTimeInputGroup" class="form-group" style="display: none;">
    <label for="runAtInput">Run At</label>
    <input type="datetime-local" id="runAtInput">
</div>
```

#### Step 2: Add JavaScript for toggle

```javascript
function toggleScheduleType() {
    const isOneTime = document.querySelector('input[name="scheduleType"]:checked').value === 'one_time';
    document.getElementById('cronInputGroup').style.display = isOneTime ? 'none' : 'block';
    document.getElementById('dateTimeInputGroup').style.display = isOneTime ? 'block' : 'none';

    // Update required attributes
    document.getElementById('scheduleInput').required = !isOneTime;
    document.getElementById('runAtInput').required = isOneTime;
}
```

#### Step 3: Update schedule submission

Modify the schedule creation fetch call:

```javascript
function createSchedule() {
    const isOneTime = document.querySelector('input[name="scheduleType"]:checked').value === 'one_time';

    const payload = {
        container_id: selectedContainerId,
        container_name: selectedContainerName,
        host_id: selectedHostId,
        action: document.getElementById('actionSelect').value,
        one_time: isOneTime
    };

    if (isOneTime) {
        payload.run_at = document.getElementById('runAtInput').value;
    } else {
        payload.cron_expression = document.getElementById('scheduleInput').value;
    }

    fetch('/api/schedule', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(payload)
    })
    // ... rest of handler
}
```

#### Step 4: Update schedules display

In the schedules table, show "One-time" or the cron expression:

```html
<td>
    {% if schedule[7] %}
        <span class="badge badge-info">One-time: {{ schedule[7] }}</span>
    {% else %}
        <code>{{ schedule[3] }}</code>
    {% endif %}
</td>
```

### 2.5 Tests

**File:** `tests/test_schedules.py`

```python
"""Tests for schedule endpoints"""
import json
from datetime import datetime, timedelta


class TestOneTimeSchedules:
    """Tests for one-time schedules"""

    def test_create_one_time_schedule(self, authenticated_client):
        """Should create a one-time schedule"""
        future_time = (datetime.now() + timedelta(hours=1)).isoformat()
        response = authenticated_client.post('/api/schedule',
            json={
                'container_id': 'a' * 12,
                'container_name': 'test-container',
                'host_id': 1,
                'action': 'restart',
                'one_time': True,
                'run_at': future_time
            },
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert response.status_code == 200 or 'schedule_id' in data

    def test_one_time_schedule_requires_run_at(self, authenticated_client):
        """One-time schedule should require run_at"""
        response = authenticated_client.post('/api/schedule',
            json={
                'container_id': 'a' * 12,
                'container_name': 'test-container',
                'host_id': 1,
                'action': 'restart',
                'one_time': True
                # Missing run_at
            },
            content_type='application/json'
        )
        assert response.status_code == 400

    def test_one_time_schedule_rejects_past_time(self, authenticated_client):
        """One-time schedule should reject past times"""
        past_time = (datetime.now() - timedelta(hours=1)).isoformat()
        response = authenticated_client.post('/api/schedule',
            json={
                'container_id': 'a' * 12,
                'container_name': 'test-container',
                'host_id': 1,
                'action': 'restart',
                'one_time': True,
                'run_at': past_time
            },
            content_type='application/json'
        )
        assert response.status_code == 400
```

---

## Feature 3: ntfy.sh Notifications

### 3.1 Goal
Add support for ntfy.sh push notifications as an alternative to Discord.

### 3.2 Database Changes

Add to `init_db()`:
```python
# Ensure settings table can store ntfy settings
# No schema change needed - we use the existing key-value settings table
```

**Settings Keys:**
- `ntfy_enabled`: "true" or "false"
- `ntfy_server`: Server URL (default: "https://ntfy.sh")
- `ntfy_topic`: Topic name (required)
- `ntfy_priority`: 1-5 (default: 3)

### 3.3 Backend Implementation

#### Step 1: Add ntfy notification function in `app/main.py`

Add after `send_discord_notification()`:

```python
def send_ntfy_notification(container_name, action, status, message, schedule_id=None):
    """Send a ntfy.sh push notification"""
    ntfy_enabled = get_setting('ntfy_enabled', 'false')
    if ntfy_enabled != 'true':
        return

    ntfy_server = get_setting('ntfy_server', 'https://ntfy.sh')
    ntfy_topic = get_setting('ntfy_topic')

    if not ntfy_topic:
        return

    try:
        import requests

        # Determine priority and emoji
        if status == 'success':
            priority = 3
            emoji = 'white_check_mark'
        else:
            priority = 4
            emoji = 'x'

        # Build notification
        title = f"Chrontainer: {action.capitalize()} {status.capitalize()}"
        body = f"{container_name}: {message}"

        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"

        response = requests.post(
            url,
            data=body.encode('utf-8'),
            headers={
                'Title': title,
                'Priority': str(get_setting('ntfy_priority', '3')),
                'Tags': emoji
            },
            timeout=10
        )

        if response.status_code not in [200, 204]:
            logger.warning(f"ntfy notification returned status {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send ntfy notification: {e}")
```

#### Step 2: Update all action functions to call ntfy

In each of `restart_container`, `start_container`, `stop_container`, `pause_container`, `unpause_container`, `update_container`:

Add after the `send_discord_notification()` call:
```python
send_ntfy_notification(container_name, 'restart', 'success', message, schedule_id)
```

#### Step 3: Add API endpoints for ntfy settings

```python
@app.route('/api/settings/ntfy', methods=['POST'])
@login_required
def update_ntfy_settings():
    """Update ntfy notification settings"""
    try:
        data = request.json

        ntfy_enabled = data.get('enabled', False)
        ntfy_server = sanitize_string(data.get('server', 'https://ntfy.sh'), max_length=500).strip()
        ntfy_topic = sanitize_string(data.get('topic', ''), max_length=100).strip()
        ntfy_priority = data.get('priority', 3)

        # Validate
        if ntfy_enabled and not ntfy_topic:
            return jsonify({'error': 'Topic is required when ntfy is enabled'}), 400

        if not isinstance(ntfy_priority, int) or ntfy_priority < 1 or ntfy_priority > 5:
            return jsonify({'error': 'Priority must be 1-5'}), 400

        # Validate server URL
        if ntfy_server and not ntfy_server.startswith('http'):
            return jsonify({'error': 'Server must be a valid URL'}), 400

        set_setting('ntfy_enabled', 'true' if ntfy_enabled else 'false')
        set_setting('ntfy_server', ntfy_server)
        set_setting('ntfy_topic', ntfy_topic)
        set_setting('ntfy_priority', str(ntfy_priority))

        logger.info("ntfy settings updated")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to update ntfy settings: {e}")
        return jsonify({'error': 'Failed to save settings'}), 500


@app.route('/api/settings/ntfy/test', methods=['POST'])
@login_required
def test_ntfy():
    """Test ntfy notification"""
    try:
        ntfy_server = get_setting('ntfy_server', 'https://ntfy.sh')
        ntfy_topic = get_setting('ntfy_topic')

        if not ntfy_topic:
            return jsonify({'error': 'ntfy topic not configured'}), 400

        import requests
        url = f"{ntfy_server.rstrip('/')}/{ntfy_topic}"

        response = requests.post(
            url,
            data="This is a test notification from Chrontainer!".encode('utf-8'),
            headers={
                'Title': 'Chrontainer Test',
                'Priority': '3',
                'Tags': 'bell'
            },
            timeout=10
        )

        if response.status_code in [200, 204]:
            return jsonify({'success': True, 'message': 'Test notification sent'})
        else:
            return jsonify({'error': f'Server returned status {response.status_code}'}), 400
    except Exception as e:
        logger.error(f"Failed to test ntfy: {e}")
        return jsonify({'error': str(e)}), 500
```

### 3.4 UI Changes

#### Add ntfy tab to Settings page (`templates/settings.html`)

Add a new tab section for ntfy configuration:

```html
<!-- ntfy Tab Content -->
<div id="ntfy-tab" class="tab-content" style="display: none;">
    <h3>ntfy.sh Notifications</h3>
    <p class="help-text">
        <a href="https://ntfy.sh" target="_blank">ntfy.sh</a> is a simple pub-sub notification service.
        You can use the free public server or self-host your own.
    </p>

    <div class="form-group">
        <label>
            <input type="checkbox" id="ntfyEnabled" onchange="toggleNtfyFields()">
            Enable ntfy notifications
        </label>
    </div>

    <div id="ntfyFields" style="display: none;">
        <div class="form-group">
            <label for="ntfyServer">Server URL</label>
            <input type="url" id="ntfyServer" value="https://ntfy.sh" placeholder="https://ntfy.sh">
            <small>Leave default for public server, or enter your self-hosted URL</small>
        </div>

        <div class="form-group">
            <label for="ntfyTopic">Topic *</label>
            <input type="text" id="ntfyTopic" placeholder="my-chrontainer-alerts" required>
            <small>Choose a unique topic name. Anyone with this name can subscribe.</small>
        </div>

        <div class="form-group">
            <label for="ntfyPriority">Default Priority</label>
            <select id="ntfyPriority">
                <option value="1">1 - Min</option>
                <option value="2">2 - Low</option>
                <option value="3" selected>3 - Default</option>
                <option value="4">4 - High</option>
                <option value="5">5 - Max (urgent)</option>
            </select>
        </div>

        <div class="button-group">
            <button type="button" class="btn btn-primary" onclick="saveNtfySettings()">Save</button>
            <button type="button" class="btn btn-secondary" onclick="testNtfy()">Test Notification</button>
        </div>
    </div>
</div>
```

#### Add JavaScript for ntfy

```javascript
function toggleNtfyFields() {
    const enabled = document.getElementById('ntfyEnabled').checked;
    document.getElementById('ntfyFields').style.display = enabled ? 'block' : 'none';
}

function saveNtfySettings() {
    const payload = {
        enabled: document.getElementById('ntfyEnabled').checked,
        server: document.getElementById('ntfyServer').value,
        topic: document.getElementById('ntfyTopic').value,
        priority: parseInt(document.getElementById('ntfyPriority').value)
    };

    fetch('/api/settings/ntfy', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(payload)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('ntfy settings saved', 'success');
        } else {
            showToast(data.error || 'Failed to save', 'error');
        }
    })
    .catch(err => showToast('Failed to save settings', 'error'));
}

function testNtfy() {
    fetch('/api/settings/ntfy/test', {
        method: 'POST',
        headers: { 'X-CSRFToken': csrfToken }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Test notification sent!', 'success');
        } else {
            showToast(data.error || 'Test failed', 'error');
        }
    })
    .catch(err => showToast('Test failed', 'error'));
}

// Load ntfy settings on page load
function loadNtfySettings() {
    fetch('/api/settings')
    .then(response => response.json())
    .then(data => {
        document.getElementById('ntfyEnabled').checked = data.ntfy_enabled === 'true';
        document.getElementById('ntfyServer').value = data.ntfy_server || 'https://ntfy.sh';
        document.getElementById('ntfyTopic').value = data.ntfy_topic || '';
        document.getElementById('ntfyPriority').value = data.ntfy_priority || '3';
        toggleNtfyFields();
    });
}
```

#### Update `/api/settings` endpoint

Add ntfy settings to the response:
```python
@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get all settings"""
    try:
        return jsonify({
            'discord_webhook_url': get_setting('discord_webhook_url', ''),
            'ntfy_enabled': get_setting('ntfy_enabled', 'false'),
            'ntfy_server': get_setting('ntfy_server', 'https://ntfy.sh'),
            'ntfy_topic': get_setting('ntfy_topic', ''),
            'ntfy_priority': get_setting('ntfy_priority', '3')
        })
    except Exception as e:
        logger.error(f"Failed to get settings: {e}")
        return jsonify({'error': 'Failed to load settings'}), 500
```

---

## Summary Checklist for Developer

### Feature 1: Container Resource Monitoring
- [x] Add `/api/container/<id>/stats` endpoint
- [x] Add `/api/containers/stats` bulk endpoint
- [x] Add CPU/Memory columns to container table
- [x] Add JavaScript for periodic stats fetching (10s interval)
- [x] Add CSS for high/medium usage highlighting
- [x] Add tests in `tests/test_stats.py`
- [x] Run all existing tests to ensure no regressions

### Feature 2: One-Time Schedules
- [x] Create Alembic migration `002_add_one_time_schedules.py`
- [x] Update `init_db()` with inline migration
- [x] Modify `add_schedule()` to handle one-time schedules
- [x] Modify `load_schedules()` to load one-time schedules
- [x] Add DateTrigger import from APScheduler
- [x] Update schedule modal with type toggle
- [x] Update schedule display to show one-time vs cron
- [x] Add tests in `tests/test_schedules.py`

### Feature 3: ntfy.sh Notifications
- [x] Add `send_ntfy_notification()` function
- [x] Call ntfy in all 6 action functions (restart, start, stop, pause, unpause, update)
- [x] Add `/api/settings/ntfy` POST endpoint
- [x] Add `/api/settings/ntfy/test` POST endpoint
- [x] Update `/api/settings` GET to include ntfy settings
- [x] Add ntfy tab to settings page
- [x] Add JavaScript for ntfy settings
- [ ] Test with actual ntfy.sh server

### Final Steps
- [x] Run `pytest tests/ -v` - all tests must pass
- [x] Update ROADMAP.md to mark features complete
- [ ] Update TRACKING_LOG.md with commit hashes
- [ ] Commit with descriptive message
- [ ] Push to GitHub (will trigger CI and release)

---

## Common Mistakes to Avoid

1. **IP Address Find-Replace:** NEVER do global find-replace on IP addresses. The SVG paths contain decimal numbers like `.07` that look like IP octets.

2. **CSRF Token:** All POST/PUT/DELETE fetch calls must include `'X-CSRFToken': csrfToken` header.

3. **Database Connections:** Always close database connections after use. Use the pattern:
   ```python
   conn = get_db()
   cursor = conn.cursor()
   # ... operations
   conn.commit()  # if writing
   conn.close()
   ```

4. **Error Handling:** Wrap Docker API calls in try/except. Container operations can fail.

5. **Stats Performance:** Don't call stats in the main container list render - it's too slow. Use a separate async fetch.

6. **APScheduler Imports:** DateTrigger needs explicit import: `from apscheduler.triggers.date import DateTrigger`

7. **One-Time Schedule Cleanup:** The wrapper function for one-time schedules must capture variables properly to avoid closure issues.

8. **Test Database:** Tests use a temporary SQLite database. Don't hardcode paths.

---

# Previously Completed Phases

## Phase 1: Core Features & Multi-Host Support (v0.2.0) ✅ COMPLETED
(content preserved but collapsed for brevity)

## Phase 2: Notifications & Authentication ✅ PARTIALLY COMPLETED
(Discord + Basic Auth done, ntfy.sh in progress)

## Phase 4: Production Hardening ✅ MOSTLY COMPLETED
(Security, Deployment, CI/CD done)

---

# Future Phases (v0.4.0+)

## Phase 3: Monitoring & Health (v0.4.0)
- Host metrics dashboard page
- Container uptime charts
- Auto-restart on health check failure
- Schedule dependencies

## Phase 5: Advanced Features (v2.0.0+)
- Compose stack management
- Full container CRUD
- Network management
- Image/volume management

---

## Version History
- **v0.2.0** - Multi-host, tags, dark mode, bulk actions, health endpoint
- **v0.3.0** - (In Progress) Resource monitoring, one-time schedules, ntfy.sh

---

## Decision Log

### v0.3.0 Architecture Decisions

**Stats Fetching Strategy:**
- Option A: Fetch stats inline with container list (slow, blocks render)
- Option B: Fetch stats async via separate endpoint (fast, non-blocking)
- **Decision:** Option B - separate `/api/containers/stats` endpoint with 10s polling

**One-Time Schedule Storage:**
- Option A: Separate table for one-time schedules
- Option B: Add columns to existing schedules table
- **Decision:** Option B - simpler, reuses existing code

**ntfy vs Other Notification Services:**
- ntfy.sh chosen because: free, self-hostable, no API keys needed, mobile apps available
