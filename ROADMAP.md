# Chrontainer Roadmap

## Current Status: v0.4.0 (In Progress)
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
✅ pytest test suite (31 tests)
✅ GitHub Actions CI/CD with auto-releases
✅ Alembic database migrations
✅ Container CPU/Memory monitoring
✅ One-time schedules
✅ ntfy.sh notifications
✅ GHCR Docker image publishing

---

# v0.4.0 Implementation Plan

## Overview
**Focus:** API Key Authentication + Webhook Triggers + Host Metrics Dashboard
**Developer:** ChatGPT
**Architect:** Claude

### Why These Features?
1. **API Keys** - Enable external automation (n8n, Home Assistant, scripts) without session cookies
2. **Webhooks** - Allow external systems to trigger container actions via simple HTTP calls
3. **Host Metrics** - User-requested feature for visibility into Docker host health (CPU, memory, disk)

---

## Feature 1: API Key Authentication

### 1.1 Goal
Allow users to create API keys that can be used to authenticate API requests without session cookies. This enables external automation tools to interact with Chrontainer.

### 1.2 Database Schema

**Migration File:** `migrations/versions/003_add_api_keys.py`

```python
"""Add API keys table

Revision ID: 003
Revises: 002
Create Date: 2026-01-XX
"""
from alembic import op
import sqlalchemy as sa

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.Text, nullable=False),
        sa.Column('key_hash', sa.Text, nullable=False),  # bcrypt hash of the key
        sa.Column('key_prefix', sa.Text, nullable=False),  # First 8 chars for identification
        sa.Column('permissions', sa.Text, default='read'),  # 'read', 'write', 'admin'
        sa.Column('last_used', sa.DateTime, nullable=True),
        sa.Column('expires_at', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp())
    )


def downgrade() -> None:
    op.drop_table('api_keys')
```

**Also update `init_db()` in main.py:**
```python
# Create api_keys table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        permissions TEXT DEFAULT 'read',
        last_used TIMESTAMP,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
''')
```

### 1.3 API Key Format
Keys will be in format: `chron_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` (36 chars total)
- Prefix: `chron_` (6 chars) - easy to identify in logs
- Random: 30 chars of base64url-safe characters

### 1.4 Backend Implementation

#### Step 1: Add API key generation utility

**Location:** After the password hashing utilities in `app/main.py`

```python
import secrets
import hashlib

def generate_api_key():
    """Generate a new API key"""
    random_bytes = secrets.token_bytes(22)  # 22 bytes = 30 base64 chars
    key_body = secrets.token_urlsafe(22)[:30]
    full_key = f"chron_{key_body}"
    return full_key

def hash_api_key(key):
    """Hash an API key for storage (using SHA256, not bcrypt - faster for frequent lookups)"""
    return hashlib.sha256(key.encode()).hexdigest()

def verify_api_key(key, key_hash):
    """Verify an API key against its hash"""
    return hashlib.sha256(key.encode()).hexdigest() == key_hash
```

#### Step 2: Add API key authentication decorator

**Location:** After `@login_required` usages, add new decorator

```python
from functools import wraps

def api_key_or_login_required(f):
    """Decorator that allows either session auth or API key auth"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key in header
        api_key = request.headers.get('X-API-Key')
        if api_key:
            # Validate API key
            if not api_key.startswith('chron_'):
                return jsonify({'error': 'Invalid API key format'}), 401

            key_hash = hash_api_key(api_key)
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('''
                SELECT ak.id, ak.user_id, ak.permissions, ak.expires_at, u.role
                FROM api_keys ak
                JOIN users u ON ak.user_id = u.id
                WHERE ak.key_hash = ?
            ''', (key_hash,))
            result = cursor.fetchone()

            if not result:
                conn.close()
                return jsonify({'error': 'Invalid API key'}), 401

            key_id, user_id, permissions, expires_at, user_role = result

            # Check expiration
            if expires_at:
                from datetime import datetime
                if datetime.fromisoformat(expires_at) < datetime.now():
                    conn.close()
                    return jsonify({'error': 'API key expired'}), 401

            # Update last_used
            cursor.execute('UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?', (key_id,))
            conn.commit()
            conn.close()

            # Store auth info in request context
            request.api_key_auth = True
            request.api_key_permissions = permissions
            request.api_key_user_id = user_id
            request.api_key_user_role = user_role
            return f(*args, **kwargs)

        # Fall back to session auth
        if current_user.is_authenticated:
            request.api_key_auth = False
            return f(*args, **kwargs)

        return jsonify({'error': 'Authentication required'}), 401

    return decorated_function
```

#### Step 3: Add API key management endpoints

```python
@app.route('/api/keys', methods=['GET'])
@login_required
def list_api_keys():
    """List all API keys for current user"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, key_prefix, permissions, last_used, expires_at, created_at
            FROM api_keys WHERE user_id = ?
            ORDER BY created_at DESC
        ''', (current_user.id,))
        keys = cursor.fetchall()
        conn.close()

        return jsonify([{
            'id': k[0],
            'name': k[1],
            'key_prefix': k[2],
            'permissions': k[3],
            'last_used': k[4],
            'expires_at': k[5],
            'created_at': k[6]
        } for k in keys])
    except Exception as e:
        logger.error(f"Failed to list API keys: {e}")
        return jsonify({'error': 'Failed to list keys'}), 500


@app.route('/api/keys', methods=['POST'])
@login_required
def create_api_key():
    """Create a new API key"""
    try:
        data = request.json
        name = sanitize_string(data.get('name', 'Unnamed Key'), max_length=100)
        permissions = data.get('permissions', 'read')
        expires_days = data.get('expires_days')  # Optional: number of days until expiration

        if permissions not in ['read', 'write', 'admin']:
            return jsonify({'error': 'Invalid permissions. Use: read, write, or admin'}), 400

        # Only admins can create admin keys
        if permissions == 'admin' and current_user.role != 'admin':
            return jsonify({'error': 'Only admins can create admin API keys'}), 403

        # Generate key
        full_key = generate_api_key()
        key_hash = hash_api_key(full_key)
        key_prefix = full_key[:14]  # "chron_" + first 8 chars

        # Calculate expiration
        expires_at = None
        if expires_days:
            from datetime import datetime, timedelta
            expires_at = (datetime.now() + timedelta(days=int(expires_days))).isoformat()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO api_keys (user_id, name, key_hash, key_prefix, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (current_user.id, name, key_hash, key_prefix, permissions, expires_at))
        key_id = cursor.lastrowid
        conn.commit()
        conn.close()

        logger.info(f"API key created: {key_prefix}... for user {current_user.username}")

        # Return the full key ONLY on creation (never stored or shown again)
        return jsonify({
            'id': key_id,
            'name': name,
            'key': full_key,  # Only returned once!
            'key_prefix': key_prefix,
            'permissions': permissions,
            'expires_at': expires_at,
            'message': 'Save this key now - it will not be shown again!'
        })
    except Exception as e:
        logger.error(f"Failed to create API key: {e}")
        return jsonify({'error': 'Failed to create key'}), 500


@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    """Delete an API key"""
    try:
        conn = get_db()
        cursor = conn.cursor()

        # Verify ownership
        cursor.execute('SELECT user_id FROM api_keys WHERE id = ?', (key_id,))
        result = cursor.fetchone()

        if not result:
            conn.close()
            return jsonify({'error': 'API key not found'}), 404

        if result[0] != current_user.id and current_user.role != 'admin':
            conn.close()
            return jsonify({'error': 'Not authorized to delete this key'}), 403

        cursor.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
        conn.commit()
        conn.close()

        logger.info(f"API key {key_id} deleted by user {current_user.username}")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to delete API key: {e}")
        return jsonify({'error': 'Failed to delete key'}), 500
```

#### Step 4: Update existing API endpoints to use the new decorator

Replace `@login_required` with `@api_key_or_login_required` on these endpoints:
- `/api/containers` (GET)
- `/api/container/<id>/restart` (POST)
- `/api/container/<id>/start` (POST)
- `/api/container/<id>/stop` (POST)
- `/api/container/<id>/pause` (POST)
- `/api/container/<id>/unpause` (POST)
- `/api/container/<id>/stats` (GET)
- `/api/containers/stats` (GET)
- `/api/schedule` (POST)
- `/api/schedule/<id>` (DELETE)
- `/api/schedule/<id>/toggle` (POST)
- `/api/hosts` (GET)
- `/api/tags` (GET)

**Important:** Keep `@login_required` (not the new decorator) on sensitive endpoints:
- `/api/keys/*` - API key management
- `/api/settings/*` - Settings changes
- `/api/user/*` - User management
- `/api/hosts` (POST/PUT/DELETE) - Host management

#### Step 5: Add permission checks in write endpoints

For endpoints that modify data, check permissions:

```python
# Example for restart endpoint
@app.route('/api/container/<container_id>/restart', methods=['POST'])
@api_key_or_login_required
def api_restart_container(container_id):
    # Check write permission for API key auth
    if getattr(request, 'api_key_auth', False):
        if request.api_key_permissions == 'read':
            return jsonify({'error': 'API key does not have write permission'}), 403

    # ... rest of the function
```

### 1.5 UI Changes

#### Add "API Keys" tab to Settings page (`templates/settings.html`)

```html
<!-- Add to tab buttons -->
<button class="tab" onclick="showTab('apikeys')">API Keys</button>

<!-- API Keys Tab Content -->
<div id="apikeys-tab" class="tab-content" style="display: none;">
    <h2>API Keys</h2>
    <p class="help-text">
        API keys allow external applications to access Chrontainer without a browser session.
        Keys are shown only once when created - save them securely!
    </p>

    <div class="form-group">
        <h3>Create New Key</h3>
        <div class="inline-form">
            <input type="text" id="newKeyName" placeholder="Key name (e.g., 'Home Assistant')" style="flex: 2;">
            <select id="newKeyPermissions" style="flex: 1;">
                <option value="read">Read Only</option>
                <option value="write">Read + Write</option>
                <option value="admin">Admin</option>
            </select>
            <select id="newKeyExpires" style="flex: 1;">
                <option value="">Never expires</option>
                <option value="30">30 days</option>
                <option value="90">90 days</option>
                <option value="365">1 year</option>
            </select>
            <button class="btn btn-primary" onclick="createApiKey()">Create Key</button>
        </div>
    </div>

    <div id="newKeyDisplay" class="alert alert-warning" style="display: none;">
        <strong>Save this key now!</strong> It will not be shown again.<br>
        <code id="newKeyValue" style="font-size: 1.1em; user-select: all;"></code>
        <button class="btn btn-sm" onclick="copyApiKey()">Copy</button>
    </div>

    <h3>Existing Keys</h3>
    <table class="data-table" id="apiKeysTable">
        <thead>
            <tr>
                <th>Name</th>
                <th>Key Prefix</th>
                <th>Permissions</th>
                <th>Last Used</th>
                <th>Expires</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="apiKeysList">
            <!-- Populated by JavaScript -->
        </tbody>
    </table>

    <h3>Usage Examples</h3>
    <div class="code-examples">
        <h4>curl</h4>
        <pre><code>curl -H "X-API-Key: chron_xxxxx" http://your-server:5000/api/containers</code></pre>

        <h4>Python</h4>
        <pre><code>import requests
response = requests.get(
    'http://your-server:5000/api/containers',
    headers={'X-API-Key': 'chron_xxxxx'}
)</code></pre>

        <h4>Home Assistant REST Command</h4>
        <pre><code>rest_command:
  restart_container:
    url: "http://your-server:5000/api/container/{{ container_id }}/restart"
    method: POST
    headers:
      X-API-Key: "chron_xxxxx"</code></pre>
    </div>
</div>
```

#### Add JavaScript for API keys

```javascript
function loadApiKeys() {
    fetch('/api/keys', {
        headers: { 'X-CSRFToken': csrfToken }
    })
    .then(response => response.json())
    .then(keys => {
        const tbody = document.getElementById('apiKeysList');
        if (keys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty">No API keys created yet</td></tr>';
            return;
        }
        tbody.innerHTML = keys.map(key => `
            <tr>
                <td>${escapeHtml(key.name)}</td>
                <td><code>${key.key_prefix}...</code></td>
                <td><span class="badge badge-${key.permissions === 'admin' ? 'danger' : key.permissions === 'write' ? 'warning' : 'info'}">${key.permissions}</span></td>
                <td>${key.last_used ? formatDate(key.last_used) : 'Never'}</td>
                <td>${key.expires_at ? formatDate(key.expires_at) : 'Never'}</td>
                <td><button class="btn btn-sm btn-danger" onclick="deleteApiKey(${key.id})">Delete</button></td>
            </tr>
        `).join('');
    })
    .catch(err => console.error('Failed to load API keys:', err));
}

function createApiKey() {
    const name = document.getElementById('newKeyName').value.trim();
    const permissions = document.getElementById('newKeyPermissions').value;
    const expiresDays = document.getElementById('newKeyExpires').value;

    if (!name) {
        showToast('Please enter a key name', 'error');
        return;
    }

    fetch('/api/keys', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({
            name: name,
            permissions: permissions,
            expires_days: expiresDays || null
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
            return;
        }

        // Show the new key (only time it's visible)
        document.getElementById('newKeyValue').textContent = data.key;
        document.getElementById('newKeyDisplay').style.display = 'block';
        document.getElementById('newKeyName').value = '';

        // Refresh the list
        loadApiKeys();
        showToast('API key created! Save it now.', 'success');
    })
    .catch(err => showToast('Failed to create key', 'error'));
}

function copyApiKey() {
    const key = document.getElementById('newKeyValue').textContent;
    navigator.clipboard.writeText(key).then(() => {
        showToast('Key copied to clipboard', 'success');
    });
}

function deleteApiKey(keyId) {
    if (!confirm('Are you sure you want to delete this API key? This cannot be undone.')) {
        return;
    }

    fetch(`/api/keys/${keyId}`, {
        method: 'DELETE',
        headers: { 'X-CSRFToken': csrfToken }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadApiKeys();
            showToast('API key deleted', 'success');
        } else {
            showToast(data.error || 'Failed to delete', 'error');
        }
    })
    .catch(err => showToast('Failed to delete key', 'error'));
}

// Load keys when tab is shown
// Add to showTab function: if (tabName === 'apikeys') loadApiKeys();
```

### 1.6 Tests

**File:** `tests/test_api_keys.py`

```python
"""Tests for API key authentication"""
import json


class TestApiKeyEndpoints:
    """Tests for API key management endpoints"""

    def test_list_keys_requires_auth(self, client):
        """List keys endpoint requires authentication"""
        response = client.get('/api/keys')
        assert response.status_code == 302

    def test_create_key(self, authenticated_client):
        """Should create an API key"""
        response = authenticated_client.post('/api/keys',
            json={'name': 'Test Key', 'permissions': 'read'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert response.status_code == 200
        assert 'key' in data
        assert data['key'].startswith('chron_')
        assert len(data['key']) == 36

    def test_create_key_returns_key_only_once(self, authenticated_client):
        """Key should only be visible on creation"""
        # Create a key
        response = authenticated_client.post('/api/keys',
            json={'name': 'Test Key', 'permissions': 'read'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert 'key' in data

        # List keys - full key should NOT be visible
        response = authenticated_client.get('/api/keys')
        keys = json.loads(response.data)
        assert len(keys) > 0
        assert 'key' not in keys[0]  # Only key_prefix should be visible

    def test_invalid_permissions_rejected(self, authenticated_client):
        """Invalid permissions should be rejected"""
        response = authenticated_client.post('/api/keys',
            json={'name': 'Test Key', 'permissions': 'superadmin'},
            content_type='application/json'
        )
        assert response.status_code == 400


class TestApiKeyAuth:
    """Tests for API key authentication on endpoints"""

    def test_containers_endpoint_accepts_api_key(self, app, authenticated_client):
        """Containers endpoint should accept API key"""
        # First create a key
        response = authenticated_client.post('/api/keys',
            json={'name': 'Test Key', 'permissions': 'read'},
            content_type='application/json'
        )
        key = json.loads(response.data)['key']

        # Use the key (without session)
        with app.test_client() as client:
            response = client.get('/api/containers',
                headers={'X-API-Key': key}
            )
            assert response.status_code == 200

    def test_invalid_api_key_rejected(self, app):
        """Invalid API key should be rejected"""
        with app.test_client() as client:
            response = client.get('/api/containers',
                headers={'X-API-Key': 'chron_invalidkey12345678901234'}
            )
            assert response.status_code == 401

    def test_read_key_cannot_write(self, app, authenticated_client):
        """Read-only key should not be able to perform write operations"""
        # Create read-only key
        response = authenticated_client.post('/api/keys',
            json={'name': 'Read Key', 'permissions': 'read'},
            content_type='application/json'
        )
        key = json.loads(response.data)['key']

        # Try to restart a container (write operation)
        with app.test_client() as client:
            response = client.post('/api/container/abc123/restart?host_id=1',
                headers={'X-API-Key': key}
            )
            assert response.status_code == 403
```

---

## Feature 2: Webhook Triggers

### 2.1 Goal
Allow external systems to trigger container actions via webhooks with optional secret validation.

### 2.2 Database Schema

**Add to migration `003_add_api_keys.py` or create new migration:**

```python
# Add webhooks table
op.create_table(
    'webhooks',
    sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
    sa.Column('name', sa.Text, nullable=False),
    sa.Column('token', sa.Text, nullable=False, unique=True),  # Unique webhook token
    sa.Column('container_id', sa.Text, nullable=True),  # Specific container or null for any
    sa.Column('host_id', sa.Integer, nullable=True),
    sa.Column('action', sa.Text, nullable=False),  # restart, start, stop, etc.
    sa.Column('enabled', sa.Integer, default=1),
    sa.Column('last_triggered', sa.DateTime, nullable=True),
    sa.Column('trigger_count', sa.Integer, default=0),
    sa.Column('created_at', sa.DateTime, server_default=sa.func.current_timestamp())
)
```

### 2.3 Backend Implementation

#### Step 1: Add webhook endpoints

```python
@app.route('/webhook/<token>', methods=['POST', 'GET'])
def trigger_webhook(token):
    """Trigger a webhook action - no auth required, uses token"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, name, container_id, host_id, action, enabled
            FROM webhooks WHERE token = ?
        ''', (token,))
        webhook = cursor.fetchone()

        if not webhook:
            conn.close()
            return jsonify({'error': 'Invalid webhook'}), 404

        webhook_id, name, container_id, host_id, action, enabled = webhook

        if not enabled:
            conn.close()
            return jsonify({'error': 'Webhook is disabled'}), 403

        # Allow overriding container_id via query param or JSON body
        override_container = None
        override_host = None

        if request.method == 'POST' and request.is_json:
            data = request.json
            override_container = data.get('container_id')
            override_host = data.get('host_id')
        else:
            override_container = request.args.get('container_id')
            override_host = request.args.get('host_id')

        target_container = override_container or container_id
        target_host = int(override_host or host_id or 1)

        if not target_container:
            conn.close()
            return jsonify({'error': 'No container specified'}), 400

        # Validate container exists
        docker_client = docker_manager.get_client(target_host)
        if not docker_client:
            conn.close()
            return jsonify({'error': 'Docker host not available'}), 503

        try:
            container = docker_client.containers.get(target_container)
            container_name = container.name
        except docker.errors.NotFound:
            conn.close()
            return jsonify({'error': 'Container not found'}), 404

        # Update trigger stats
        cursor.execute('''
            UPDATE webhooks
            SET last_triggered = CURRENT_TIMESTAMP, trigger_count = trigger_count + 1
            WHERE id = ?
        ''', (webhook_id,))
        conn.commit()
        conn.close()

        # Execute action
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
            return jsonify({'error': f'Unknown action: {action}'}), 400

        # Execute in background thread to return quickly
        import threading
        thread = threading.Thread(
            target=action_func,
            args=[target_container, container_name, None, target_host]
        )
        thread.start()

        logger.info(f"Webhook '{name}' triggered: {action} on {container_name}")

        return jsonify({
            'success': True,
            'webhook': name,
            'action': action,
            'container': container_name,
            'message': f'{action.capitalize()} triggered for {container_name}'
        })

    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'error': 'Webhook execution failed'}), 500


@app.route('/api/webhooks', methods=['GET'])
@login_required
def list_webhooks():
    """List all webhooks"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT w.id, w.name, w.token, w.container_id, w.host_id, w.action,
                   w.enabled, w.last_triggered, w.trigger_count, w.created_at, h.name
            FROM webhooks w
            LEFT JOIN hosts h ON w.host_id = h.id
            ORDER BY w.created_at DESC
        ''')
        webhooks = cursor.fetchall()
        conn.close()

        return jsonify([{
            'id': w[0],
            'name': w[1],
            'token': w[2],
            'container_id': w[3],
            'host_id': w[4],
            'action': w[5],
            'enabled': bool(w[6]),
            'last_triggered': w[7],
            'trigger_count': w[8],
            'created_at': w[9],
            'host_name': w[10]
        } for w in webhooks])
    except Exception as e:
        logger.error(f"Failed to list webhooks: {e}")
        return jsonify({'error': 'Failed to list webhooks'}), 500


@app.route('/api/webhooks', methods=['POST'])
@login_required
def create_webhook():
    """Create a new webhook"""
    try:
        data = request.json
        name = sanitize_string(data.get('name', ''), max_length=100)
        container_id = data.get('container_id')  # Optional - can be null for flexible webhooks
        host_id = data.get('host_id')
        action = data.get('action', 'restart')

        if not name:
            return jsonify({'error': 'Name is required'}), 400

        if action not in ['restart', 'start', 'stop', 'pause', 'unpause', 'update']:
            return jsonify({'error': 'Invalid action'}), 400

        # Generate unique token
        token = secrets.token_urlsafe(24)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO webhooks (name, token, container_id, host_id, action)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, token, container_id, host_id, action))
        webhook_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Build webhook URL
        webhook_url = f"{request.host_url}webhook/{token}"

        logger.info(f"Webhook created: {name}")

        return jsonify({
            'id': webhook_id,
            'name': name,
            'token': token,
            'url': webhook_url,
            'action': action
        })
    except Exception as e:
        logger.error(f"Failed to create webhook: {e}")
        return jsonify({'error': 'Failed to create webhook'}), 500


@app.route('/api/webhooks/<int:webhook_id>', methods=['DELETE'])
@login_required
def delete_webhook(webhook_id):
    """Delete a webhook"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM webhooks WHERE id = ?', (webhook_id,))
        conn.commit()
        conn.close()

        logger.info(f"Webhook {webhook_id} deleted")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Failed to delete webhook: {e}")
        return jsonify({'error': 'Failed to delete webhook'}), 500


@app.route('/api/webhooks/<int:webhook_id>/toggle', methods=['POST'])
@login_required
def toggle_webhook(webhook_id):
    """Enable/disable a webhook"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE webhooks SET enabled = NOT enabled WHERE id = ?', (webhook_id,))
        cursor.execute('SELECT enabled FROM webhooks WHERE id = ?', (webhook_id,))
        result = cursor.fetchone()
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'enabled': bool(result[0])})
    except Exception as e:
        logger.error(f"Failed to toggle webhook: {e}")
        return jsonify({'error': 'Failed to toggle webhook'}), 500
```

### 2.4 UI Changes

#### Add Webhooks section to Settings or new page

```html
<!-- Webhooks Tab Content -->
<div id="webhooks-tab" class="tab-content" style="display: none;">
    <h2>Webhooks</h2>
    <p class="help-text">
        Webhooks allow external services to trigger container actions via a simple URL.
        No authentication required - the unique token acts as the secret.
    </p>

    <div class="form-group">
        <h3>Create New Webhook</h3>
        <div class="form-row">
            <div class="form-group">
                <label>Name *</label>
                <input type="text" id="webhookName" placeholder="e.g., Home Assistant Restart">
            </div>
            <div class="form-group">
                <label>Action *</label>
                <select id="webhookAction">
                    <option value="restart">Restart</option>
                    <option value="start">Start</option>
                    <option value="stop">Stop</option>
                    <option value="pause">Pause</option>
                    <option value="unpause">Unpause</option>
                    <option value="update">Update</option>
                </select>
            </div>
        </div>
        <div class="form-row">
            <div class="form-group">
                <label>Container (optional)</label>
                <select id="webhookContainer">
                    <option value="">Any (specify in request)</option>
                    <!-- Populated by JavaScript -->
                </select>
            </div>
            <div class="form-group">
                <label>Host</label>
                <select id="webhookHost">
                    <!-- Populated by JavaScript -->
                </select>
            </div>
        </div>
        <button class="btn btn-primary" onclick="createWebhook()">Create Webhook</button>
    </div>

    <div id="newWebhookDisplay" class="alert alert-success" style="display: none;">
        <strong>Webhook URL:</strong><br>
        <code id="newWebhookUrl" style="font-size: 1.1em; user-select: all; word-break: break-all;"></code>
        <button class="btn btn-sm" onclick="copyWebhookUrl()">Copy</button>
    </div>

    <h3>Existing Webhooks</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Name</th>
                <th>Action</th>
                <th>Container</th>
                <th>Triggered</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="webhooksList"></tbody>
    </table>

    <h3>Usage Examples</h3>
    <div class="code-examples">
        <h4>curl (GET or POST)</h4>
        <pre><code>curl "http://your-server:5000/webhook/YOUR_TOKEN"</code></pre>

        <h4>curl with container override</h4>
        <pre><code>curl "http://your-server:5000/webhook/YOUR_TOKEN?container_id=abc123&host_id=1"</code></pre>

        <h4>Home Assistant Automation</h4>
        <pre><code>automation:
  - alias: "Restart media server at 3am"
    trigger:
      platform: time
      at: "03:00:00"
    action:
      service: rest_command.trigger_webhook
      data:
        url: "http://chrontainer:5000/webhook/YOUR_TOKEN"</code></pre>

        <h4>n8n HTTP Request Node</h4>
        <pre><code>Method: POST
URL: http://your-server:5000/webhook/YOUR_TOKEN
Body: {"container_id": "optional_override"}</code></pre>
    </div>
</div>
```

### 2.5 Tests

**File:** `tests/test_webhooks.py`

```python
"""Tests for webhook functionality"""
import json


class TestWebhookManagement:
    """Tests for webhook CRUD"""

    def test_create_webhook(self, authenticated_client):
        """Should create a webhook"""
        response = authenticated_client.post('/api/webhooks',
            json={'name': 'Test Webhook', 'action': 'restart'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert response.status_code == 200
        assert 'token' in data
        assert 'url' in data

    def test_list_webhooks(self, authenticated_client):
        """Should list webhooks"""
        # Create one first
        authenticated_client.post('/api/webhooks',
            json={'name': 'Test', 'action': 'restart'},
            content_type='application/json'
        )

        response = authenticated_client.get('/api/webhooks')
        data = json.loads(response.data)
        assert response.status_code == 200
        assert isinstance(data, list)


class TestWebhookTrigger:
    """Tests for webhook triggering"""

    def test_invalid_token_rejected(self, client):
        """Invalid webhook token should return 404"""
        response = client.post('/webhook/invalid_token_12345')
        assert response.status_code == 404

    def test_disabled_webhook_rejected(self, authenticated_client, client):
        """Disabled webhook should return 403"""
        # Create and disable a webhook
        response = authenticated_client.post('/api/webhooks',
            json={'name': 'Test', 'action': 'restart', 'container_id': 'abc123'},
            content_type='application/json'
        )
        data = json.loads(response.data)
        webhook_id = data['id']
        token = data['token']

        # Disable it
        authenticated_client.post(f'/api/webhooks/{webhook_id}/toggle')

        # Try to trigger
        response = client.post(f'/webhook/{token}')
        assert response.status_code == 403
```

---

## Feature 3: Host Metrics Dashboard

### 3.1 Goal
Add a new page showing Docker host system metrics (CPU, memory, disk usage, container count).

### 3.2 Backend Implementation

#### Add host metrics endpoint

```python
@app.route('/api/hosts/<int:host_id>/metrics', methods=['GET'])
@api_key_or_login_required
def get_host_metrics(host_id):
    """Get system metrics for a Docker host"""
    try:
        docker_client = docker_manager.get_client(host_id)
        if not docker_client:
            return jsonify({'error': 'Cannot connect to Docker host'}), 503

        # Get Docker system info
        info = docker_client.info()

        # Get disk usage (Docker data)
        try:
            disk_usage = docker_client.df()
        except:
            disk_usage = None

        # Container counts
        containers_running = info.get('ContainersRunning', 0)
        containers_paused = info.get('ContainersPaused', 0)
        containers_stopped = info.get('ContainersStopped', 0)

        # Memory
        mem_total = info.get('MemTotal', 0)

        # Calculate memory used by containers
        mem_used_by_containers = 0
        try:
            for container in docker_client.containers.list():
                try:
                    stats = container.stats(stream=False)
                    mem_used_by_containers += stats.get('memory_stats', {}).get('usage', 0)
                except:
                    pass
        except:
            pass

        # CPU info
        cpus = info.get('NCPU', 0)

        # Disk usage breakdown
        images_size = 0
        containers_size = 0
        volumes_size = 0
        build_cache_size = 0

        if disk_usage:
            for img in disk_usage.get('Images', []) or []:
                images_size += img.get('Size', 0) or 0

            for cont in disk_usage.get('Containers', []) or []:
                containers_size += cont.get('SizeRw', 0) or 0

            for vol in disk_usage.get('Volumes', []) or []:
                volumes_size += vol.get('UsageData', {}).get('Size', 0) or 0

            for cache in disk_usage.get('BuildCache', []) or []:
                build_cache_size += cache.get('Size', 0) or 0

        return jsonify({
            'host_id': host_id,
            'name': info.get('Name', 'Unknown'),
            'os': info.get('OperatingSystem', 'Unknown'),
            'architecture': info.get('Architecture', 'Unknown'),
            'docker_version': info.get('ServerVersion', 'Unknown'),
            'kernel_version': info.get('KernelVersion', 'Unknown'),
            'cpus': cpus,
            'memory': {
                'total_bytes': mem_total,
                'total_gb': round(mem_total / (1024**3), 2),
                'used_by_containers_bytes': mem_used_by_containers,
                'used_by_containers_gb': round(mem_used_by_containers / (1024**3), 2)
            },
            'containers': {
                'running': containers_running,
                'paused': containers_paused,
                'stopped': containers_stopped,
                'total': containers_running + containers_paused + containers_stopped
            },
            'disk': {
                'images_bytes': images_size,
                'images_gb': round(images_size / (1024**3), 2),
                'containers_bytes': containers_size,
                'containers_gb': round(containers_size / (1024**3), 2),
                'volumes_bytes': volumes_size,
                'volumes_gb': round(volumes_size / (1024**3), 2),
                'build_cache_bytes': build_cache_size,
                'build_cache_gb': round(build_cache_size / (1024**3), 2),
                'total_bytes': images_size + containers_size + volumes_size + build_cache_size,
                'total_gb': round((images_size + containers_size + volumes_size + build_cache_size) / (1024**3), 2)
            },
            'images_count': info.get('Images', 0)
        })

    except Exception as e:
        logger.error(f"Failed to get host metrics for host {host_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hosts/metrics', methods=['GET'])
@api_key_or_login_required
def get_all_hosts_metrics():
    """Get metrics for all enabled hosts"""
    results = []

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name FROM hosts WHERE enabled = 1')
    hosts = cursor.fetchall()
    conn.close()

    for host_id, host_name in hosts:
        try:
            docker_client = docker_manager.get_client(host_id)
            if not docker_client:
                results.append({
                    'host_id': host_id,
                    'name': host_name,
                    'status': 'offline',
                    'error': 'Cannot connect'
                })
                continue

            info = docker_client.info()

            results.append({
                'host_id': host_id,
                'name': host_name,
                'status': 'online',
                'os': info.get('OperatingSystem', 'Unknown'),
                'cpus': info.get('NCPU', 0),
                'memory_gb': round(info.get('MemTotal', 0) / (1024**3), 2),
                'containers_running': info.get('ContainersRunning', 0),
                'containers_total': info.get('Containers', 0),
                'images': info.get('Images', 0)
            })
        except Exception as e:
            results.append({
                'host_id': host_id,
                'name': host_name,
                'status': 'error',
                'error': str(e)
            })

    return jsonify(results)
```

### 3.3 UI - New Metrics Page

**Create new template: `templates/metrics.html`**

```html
{% extends "base.html" if base else "" %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Host Metrics - Chrontainer</title>
    <style>
        /* Include common styles */
        :root {
            --bg-color: #f5f7fa;
            --card-bg: #ffffff;
            --text-color: #2c3e50;
            --border-color: #e1e8ed;
            --primary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
        }

        body.dark-mode {
            --bg-color: #1a1a2e;
            --card-bg: #16213e;
            --text-color: #eee;
            --border-color: #333;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            padding: 20px;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .header h1 { font-size: 1.5em; }

        .hosts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
        }

        .host-card {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .host-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }

        .host-name { font-size: 1.2em; font-weight: 600; }

        .host-status {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .host-status.online { background: #d4edda; color: #155724; }
        .host-status.offline { background: #f8d7da; color: #721c24; }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }

        .metric-box {
            background: var(--bg-color);
            padding: 15px;
            border-radius: 8px;
        }

        .metric-label {
            font-size: 0.8em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .metric-value {
            font-size: 1.5em;
            font-weight: 600;
            margin-top: 5px;
        }

        .metric-bar {
            height: 8px;
            background: var(--border-color);
            border-radius: 4px;
            margin-top: 8px;
            overflow: hidden;
        }

        .metric-bar-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        .bar-success { background: var(--success-color); }
        .bar-warning { background: var(--warning-color); }
        .bar-danger { background: var(--danger-color); }

        .disk-breakdown {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }

        .disk-item {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            font-size: 0.9em;
        }

        .container-counts {
            display: flex;
            gap: 15px;
            margin-top: 10px;
        }

        .count-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
        }
        .count-running { background: #d4edda; color: #155724; }
        .count-stopped { background: #f8d7da; color: #721c24; }
        .count-paused { background: #fff3cd; color: #856404; }

        .refresh-btn {
            padding: 8px 16px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
        }

        .back-link {
            color: var(--primary-color);
            text-decoration: none;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
    </style>
</head>
<body class="{{ 'dark-mode' if dark_mode else '' }}">
    <div class="header">
        <div>
            <a href="/" class="back-link">← Back to Dashboard</a>
            <h1>Host Metrics</h1>
        </div>
        <button class="refresh-btn" onclick="loadMetrics()">Refresh</button>
    </div>

    <div id="metricsContainer" class="hosts-grid">
        <div class="loading">Loading metrics...</div>
    </div>

    <script>
        const csrfToken = '{{ csrf_token }}';

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function getBarClass(percent) {
            if (percent > 80) return 'bar-danger';
            if (percent > 60) return 'bar-warning';
            return 'bar-success';
        }

        function loadMetrics() {
            document.getElementById('metricsContainer').innerHTML = '<div class="loading">Loading metrics...</div>';

            fetch('/api/hosts/metrics', {
                headers: { 'X-CSRFToken': csrfToken }
            })
            .then(response => response.json())
            .then(hosts => {
                const container = document.getElementById('metricsContainer');

                if (hosts.length === 0) {
                    container.innerHTML = '<div class="loading">No hosts configured</div>';
                    return;
                }

                // Fetch detailed metrics for each online host
                const detailPromises = hosts
                    .filter(h => h.status === 'online')
                    .map(h => fetch(`/api/hosts/${h.host_id}/metrics`, {
                        headers: { 'X-CSRFToken': csrfToken }
                    }).then(r => r.json()).catch(() => null));

                Promise.all(detailPromises).then(details => {
                    const detailMap = {};
                    details.forEach(d => {
                        if (d && d.host_id) detailMap[d.host_id] = d;
                    });

                    container.innerHTML = hosts.map(host => {
                        if (host.status !== 'online') {
                            return `
                                <div class="host-card">
                                    <div class="host-header">
                                        <span class="host-name">${host.name}</span>
                                        <span class="host-status offline">${host.status}</span>
                                    </div>
                                    <p>${host.error || 'Host is not reachable'}</p>
                                </div>
                            `;
                        }

                        const detail = detailMap[host.host_id] || {};
                        const memPercent = detail.memory ?
                            Math.round((detail.memory.used_by_containers_bytes / detail.memory.total_bytes) * 100) : 0;

                        return `
                            <div class="host-card">
                                <div class="host-header">
                                    <span class="host-name">${host.name}</span>
                                    <span class="host-status online">Online</span>
                                </div>

                                <div class="metrics-grid">
                                    <div class="metric-box">
                                        <div class="metric-label">Operating System</div>
                                        <div class="metric-value" style="font-size: 1em;">${detail.os || host.os}</div>
                                    </div>
                                    <div class="metric-box">
                                        <div class="metric-label">Docker Version</div>
                                        <div class="metric-value" style="font-size: 1em;">${detail.docker_version || 'N/A'}</div>
                                    </div>
                                    <div class="metric-box">
                                        <div class="metric-label">CPUs</div>
                                        <div class="metric-value">${detail.cpus || host.cpus}</div>
                                    </div>
                                    <div class="metric-box">
                                        <div class="metric-label">Total Memory</div>
                                        <div class="metric-value">${detail.memory ? detail.memory.total_gb : host.memory_gb} GB</div>
                                    </div>
                                </div>

                                ${detail.memory ? `
                                <div class="metric-box" style="margin-top: 15px;">
                                    <div class="metric-label">Memory Used by Containers</div>
                                    <div class="metric-value">${detail.memory.used_by_containers_gb} GB (${memPercent}%)</div>
                                    <div class="metric-bar">
                                        <div class="metric-bar-fill ${getBarClass(memPercent)}" style="width: ${memPercent}%"></div>
                                    </div>
                                </div>
                                ` : ''}

                                <div class="metric-box" style="margin-top: 15px;">
                                    <div class="metric-label">Containers</div>
                                    <div class="container-counts">
                                        <span class="count-badge count-running">${detail.containers?.running || host.containers_running} running</span>
                                        <span class="count-badge count-stopped">${detail.containers?.stopped || 0} stopped</span>
                                        <span class="count-badge count-paused">${detail.containers?.paused || 0} paused</span>
                                    </div>
                                </div>

                                ${detail.disk ? `
                                <div class="disk-breakdown">
                                    <div class="metric-label">Docker Disk Usage</div>
                                    <div class="metric-value">${detail.disk.total_gb} GB total</div>
                                    <div class="disk-item"><span>Images (${detail.images_count})</span><span>${detail.disk.images_gb} GB</span></div>
                                    <div class="disk-item"><span>Containers</span><span>${detail.disk.containers_gb} GB</span></div>
                                    <div class="disk-item"><span>Volumes</span><span>${detail.disk.volumes_gb} GB</span></div>
                                    <div class="disk-item"><span>Build Cache</span><span>${detail.disk.build_cache_gb} GB</span></div>
                                </div>
                                ` : ''}
                            </div>
                        `;
                    }).join('');
                });
            })
            .catch(err => {
                console.error('Failed to load metrics:', err);
                document.getElementById('metricsContainer').innerHTML =
                    '<div class="loading">Failed to load metrics</div>';
            });
        }

        // Initial load
        loadMetrics();

        // Auto-refresh every 30 seconds
        setInterval(loadMetrics, 30000);

        // Dark mode detection
        if (localStorage.getItem('darkMode') === 'true') {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>
```

#### Add route for metrics page

```python
@app.route('/metrics')
@login_required
def metrics_page():
    """Host metrics dashboard page"""
    dark_mode = request.cookies.get('darkMode', 'false') == 'true'
    return render_template('metrics.html', dark_mode=dark_mode, csrf_token=generate_csrf())
```

#### Add link in main dashboard header

In `templates/index.html`, add a link to the metrics page in the header navigation:
```html
<a href="/metrics" class="nav-link">Host Metrics</a>
```

### 3.4 Tests

**File:** `tests/test_host_metrics.py`

```python
"""Tests for host metrics endpoints"""
import json


class TestHostMetrics:
    """Tests for host metrics endpoints"""

    def test_metrics_requires_auth(self, client):
        """Host metrics should require authentication"""
        response = client.get('/api/hosts/1/metrics')
        assert response.status_code in [302, 401]

    def test_all_hosts_metrics(self, authenticated_client):
        """Should return metrics for all hosts"""
        response = authenticated_client.get('/api/hosts/metrics')
        data = json.loads(response.data)
        assert response.status_code == 200
        assert isinstance(data, list)

    def test_single_host_metrics(self, authenticated_client):
        """Should return detailed metrics for a single host"""
        response = authenticated_client.get('/api/hosts/1/metrics')
        # May return 503 if Docker not available in test, that's OK
        assert response.status_code in [200, 503]


class TestMetricsPage:
    """Tests for metrics page"""

    def test_metrics_page_requires_auth(self, client):
        """Metrics page should require authentication"""
        response = client.get('/metrics')
        assert response.status_code == 302

    def test_metrics_page_loads(self, authenticated_client):
        """Metrics page should load for authenticated users"""
        response = authenticated_client.get('/metrics')
        assert response.status_code == 200
        assert b'Host Metrics' in response.data
```

---

## Summary Checklist for Developer

### Feature 1: API Key Authentication
- [x] Create migration `003_add_api_keys.py` with api_keys + webhooks tables
- [x] Update `init_db()` with CREATE TABLE for api_keys
- [x] Add `generate_api_key()`, `hash_api_key()`, `verify_api_key()` utilities
- [x] Add `@api_key_or_login_required` decorator
- [x] Add `/api/keys` endpoints (GET, POST, DELETE)
- [x] Update existing API endpoints to use new decorator (list in spec)
- [x] Add permission checks in write endpoints
- [x] Add "API Keys" tab to settings page
- [x] Add JavaScript for key management
- [x] Add tests in `tests/test_api_keys.py`

### Feature 2: Webhook Triggers
- [x] Add webhooks table to migration (or separate migration)
- [x] Update `init_db()` with CREATE TABLE for webhooks
- [x] Add `/webhook/<token>` trigger endpoint (no auth)
- [x] Add `/api/webhooks` management endpoints (GET, POST, DELETE, toggle)
- [x] Add "Webhooks" tab to settings page
- [x] Add JavaScript for webhook management
- [x] Add tests in `tests/test_webhooks.py`

### Feature 3: Host Metrics Dashboard
- [x] Add `/api/hosts/<id>/metrics` endpoint
- [x] Add `/api/hosts/metrics` bulk endpoint
- [x] Create `templates/metrics.html` page
- [x] Add `/metrics` route
- [x] Add link to metrics in dashboard header
- [x] Add tests in `tests/test_host_metrics.py`

### Final Steps
- [x] Bump VERSION to "0.4.0" in main.py
- [x] Run `pytest tests/ -v` - all tests must pass
- [x] Update ROADMAP.md to mark features complete
- [x] Update TRACKING_LOG.md with commit hashes
- [x] Commit with descriptive message
- [ ] Push to GitHub (will trigger CI and release v0.4.0)

---

## Common Mistakes to Avoid

**(Inherited from v0.3.0 + new items)**

1. **IP Address Find-Replace:** NEVER do global find-replace on IP addresses. The SVG paths contain decimal numbers like `.07` that look like IP octets.

2. **CSRF Token:** All POST/PUT/DELETE fetch calls must include `'X-CSRFToken': csrfToken` header.

3. **Database Connections:** Always close database connections after use.

4. **Error Handling:** Wrap Docker API calls in try/except. Container operations can fail.

5. **API Key Security:**
   - NEVER log the full API key, only the prefix
   - NEVER store the plain key, only the hash
   - NEVER return the full key after creation (only on POST response)

6. **Webhook Security:**
   - Token acts as authentication - treat it as a secret
   - Rate limit webhook triggers to prevent abuse
   - Validate container exists before executing action

7. **Permission Checks:**
   - Read-only API keys should NOT be able to trigger actions
   - Only admins can create admin API keys
   - Check permissions BEFORE executing write operations

8. **Thread Safety:** Webhook trigger uses background thread - ensure no race conditions with database updates.

9. **Metrics Performance:** Host metrics can be slow (especially disk usage). Cache if needed for bulk requests.

---

## Architecture Decision Log

### v0.4.0 Decisions

**API Key Hashing:**
- Option A: bcrypt (slow but secure)
- Option B: SHA256 (fast, good enough for random keys)
- **Decision:** SHA256 - API keys are random and long, bcrypt's slowness isn't needed and would hurt performance on every API call

**Webhook Token Format:**
- Option A: UUID
- Option B: Base64 URL-safe random
- **Decision:** Base64 URL-safe (24 bytes = 32 chars) - shorter URLs, equally secure

**Host Metrics Caching:**
- Option A: Cache in memory with TTL
- Option B: Fetch fresh on each request
- **Decision:** Fetch fresh for now - metrics should be real-time. Add caching later if performance is an issue.

---

# Version History
- **v0.2.0** - Multi-host, tags, dark mode, bulk actions, health endpoint
- **v0.3.0** - Resource monitoring, one-time schedules, ntfy.sh, GHCR publishing
- **v0.4.0** - (Planned) API keys, webhooks, host metrics dashboard

---

# Future Phases (v0.5.0+)

## Remaining from Original Roadmap
- Schedule dependencies (restart A, then B)
- Auto-restart on health check failure
- Container uptime charts
- Email/Slack notifications
- Prometheus metrics endpoint
- OpenAPI/Swagger documentation

## Phase 5: Advanced Features (v2.0.0+)
- Compose stack management
- Full container CRUD
- Network management
- Image/volume management
