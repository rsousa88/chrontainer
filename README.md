# 🐳 Chrontainer

A lightweight, web-based scheduler for automating Docker container restarts and management. Perfect for home lab environments running on Raspberry Pi 5 and NAS systems.

## Features

- ✅ **Visual Dashboard**: View all Docker containers at a glance
- ⏰ **Cron Scheduling**: Schedule automatic container actions (restart, start, stop, pause, unpause)
- 🎛️ **Manual Control**: Start, stop, restart, pause, and unpause containers from the web UI
- 🌐 **Multi-Host Support**: Manage containers across multiple Docker hosts (Raspberry Pi, NAS, servers)
- 📋 **Container Logs**: View container logs directly from the UI with configurable tail and refresh
- 🔔 **Discord Notifications**: Get notified when containers are restarted, started, or stopped
- 📊 **Activity Logs**: Track all scheduled and manual actions
- 🔄 **Enable/Disable Schedules**: Toggle schedules on/off without deleting them
- 💾 **Persistent Storage**: SQLite database for schedules and logs
- 🚀 **Lightweight**: Optimized for ARM64 (Raspberry Pi) and low-resource environments

## Use Cases

- Automatically restart containers with known issues (PostgreSQL timeouts, nginx cache problems)
- Schedule periodic container maintenance
- Manage containers across multiple hosts (Raspberry Pi, Synology NAS, remote servers)
- Centralized dashboard for home lab Docker infrastructure
- Avoid paid Portainer Business subscription

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Docker socket access (`/var/run/docker.sock`)
- ARM64 (Raspberry Pi 5) or AMD64 architecture

### Installation

1. **Clone or download** this directory to your host:
   ```bash
   cd /path/to/your/projects
   # Copy the chrontainer directory here
   ```

2. **Review docker-compose.yml** and update if needed:
   ```yaml
   ports:
     - "5000:5000"  # Change port if needed
   environment:
     - SECRET_KEY=your-secret-key-here  # Change for production!
   ```

3. **Start Chrontainer**:
   ```bash
   cd chrontainer
   docker-compose up -d
   ```

4. **Access the UI**:
   Open your browser to `http://your-raspberry-pi-ip:5000`

### Alternative: Build and Run Manually

```bash
# Build the image
docker build -t chrontainer:latest .

# Run the container
docker run -d \
  --name chrontainer \
  -p 5000:5000 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/data:/data \
  -e SECRET_KEY=your-secret-key \
  chrontainer:latest
```

## Usage

### Creating a Schedule

1. Click the **"Schedule"** button next to any container
2. Enter a cron expression (examples provided in the UI)
3. Click **"Create Schedule"**

### Cron Expression Examples

- `0 2 * * *` - Daily at 2:00 AM
- `0 */6 * * *` - Every 6 hours
- `*/30 * * * *` - Every 30 minutes
- `0 0 * * 0` - Weekly on Sunday at midnight
- `0 3 1 * *` - Monthly on the 1st at 3:00 AM

**Format**: `minute hour day month day_of_week`

### Manual Container Control

Use the action buttons next to each container:
- **Restart**: Restart a running container
- **Stop**: Stop a running container
- **Start**: Start a stopped container

### Managing Schedules

- **Toggle**: Use the switch to enable/disable schedules
- **Delete**: Remove schedules you no longer need
- **View Logs**: Check the logs page for execution history

### Adding Remote Docker Hosts

Chrontainer supports managing containers across multiple Docker hosts (Synology NAS, remote servers, etc.).

1. Navigate to the **Hosts** page from the navigation menu
2. Click **"+ Add New Host"**
3. Enter a name (e.g., "Synology NAS") and URL (e.g., `tcp://192.168.1.100:2375`)
4. Click **"Save"** - Chrontainer will test the connection automatically

⚠️ **Security Requirement**: For remote hosts, you **must** use [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) to securely expose the Docker API. Never expose the raw Docker socket directly to the network.

📖 **Complete Setup Guide**: See [docs/REMOTE_HOSTS.md](docs/REMOTE_HOSTS.md) for detailed instructions on:
- Setting up docker-socket-proxy (recommended method)
- Configuring firewall rules
- Security best practices

## Documentation

See the documentation index at [docs/README.md](docs/README.md) for deployment, security, remote hosts, and API reference.
- Troubleshooting connection issues

Once added, all containers from remote hosts will appear on your dashboard with host badges, and you can schedule/manage them just like local containers.

### Discord Notifications

1. Navigate to **Settings** page
2. Enter your Discord webhook URL
3. Click **"Save Settings"**
4. Test with **"Send Test Notification"**

Chrontainer will send rich notifications with color-coded embeds when containers are restarted, started, or stopped (both manual and scheduled actions).

### Host Metrics Requirements

- **Raspberry Pi / Debian**: enable memory cgroups so Docker can report container memory usage. Edit `/boot/firmware/cmdline.txt` (single line) to remove `cgroup_disable=memory` and add `cgroup_enable=memory cgroup_memory=1`, then reboot.
- **Remote hosts via socket-proxy**: set `SYSTEM=1` in docker-socket-proxy to allow Docker disk usage metrics (`/system/df`).

## Architecture

```
┌─────────────────────┐
│   Web Browser       │
│   (User Interface)  │
└──────────┬──────────┘
           │ HTTP
           ▼
┌─────────────────────┐
│   Chrontainer       │
│   Flask App         │
│   ├─ Web UI         │
│   ├─ REST API       │
│   └─ APScheduler    │
└──────────┬──────────┘
           │
           ├─► Docker Socket (/var/run/docker.sock)
           │   └─► Container Management
           │
           └─► SQLite Database (/data/chrontainer.db)
               └─► Schedules & Logs
```

## API Endpoints

### Containers
- `GET /api/containers` - List all containers (from all hosts)
- `POST /api/container/<id>/restart` - Restart container
- `POST /api/container/<id>/start` - Start container
- `POST /api/container/<id>/stop` - Stop container
- `POST /api/container/<id>/pause` - Pause container
- `POST /api/container/<id>/unpause` - Unpause container
- `GET /api/container/<id>/logs` - Get container logs (supports tail, timestamps params)

### Schedules
- `POST /api/schedule` - Create new schedule
- `DELETE /api/schedule/<id>` - Delete schedule
- `POST /api/schedule/<id>/toggle` - Enable/disable schedule

### Docker Hosts
- `GET /api/hosts` - List all Docker hosts
- `POST /api/hosts` - Add new Docker host
- `DELETE /api/hosts/<id>` - Delete Docker host
- `POST /api/hosts/<id>/test` - Test host connection

### Settings
- `GET /api/settings` - Get current settings
- `POST /api/settings/discord` - Update Discord webhook URL
- `POST /api/settings/discord/test` - Send test notification

## Configuration

### Environment Variables

- `PORT` - Web UI port (default: 5000)
- `SECRET_KEY` - Flask secret key (change for production!)

### Volume Mounts

- `/var/run/docker.sock` - Docker socket (required, read-only)
- `/data` - Persistent storage for database and logs

## Security Considerations

⚠️ **Important Security Notes**:

1. **Docker Socket Access**: Chrontainer requires access to the Docker socket, which provides full control over Docker. Only run this in trusted environments.

2. **Remote Docker Hosts**: **NEVER** expose the Docker socket directly to the network. Always use [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) to create a secure, filtered API layer. See [REMOTE_HOSTS.md](REMOTE_HOSTS.md) for proper setup.

3. **Secret Key**: Change the `SECRET_KEY` in production:
   ```bash
   SECRET_KEY=$(openssl rand -hex 32)
   ```

4. **Network Exposure**: By default, Chrontainer is accessible to anyone on your network. Consider:
   - Running behind a reverse proxy with authentication
   - Using Docker networks to restrict access
   - Adding firewall rules
   - Restricting remote host ports to trusted IPs only

5. **Container Permissions**: Ensure the Chrontainer container runs with appropriate permissions.

## Troubleshooting

### "Docker client not available"

**Cause**: Docker socket not accessible

**Solutions**:
1. Verify socket is mounted: `docker inspect chrontainer | grep docker.sock`
2. Check socket permissions: `ls -la /var/run/docker.sock`
3. Ensure user has Docker access: `sudo usermod -aG docker $USER`

### Containers not appearing

**Cause**: Permission issues or Docker connection problems

**Solutions**:
1. Check logs: `docker logs chrontainer`
2. Verify Docker is running: `docker ps`
3. Test Docker access: `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro alpine ls -la /var/run/docker.sock`

### Schedule not executing

**Cause**: Invalid cron expression or scheduler not running

**Solutions**:
1. Verify cron syntax at [crontab.guru](https://crontab.guru)
2. Check logs for errors: `docker logs chrontainer`
3. Ensure schedule is enabled (toggle switch)
4. Restart Chrontainer: `docker restart chrontainer`

### Database issues

**Cause**: Corrupted database or permission problems

**Solutions**:
1. Check data directory permissions: `ls -la ./data`
2. Backup and remove database: `mv data/chrontainer.db data/chrontainer.db.bak`
3. Restart container to recreate: `docker restart chrontainer`

## Roadmap

### ✅ Completed
- [x] **Multi-host support**: Manage containers on remote Docker hosts
- [x] **Discord notifications**: Rich embeds for container actions

### 🚧 Planned
- [ ] **Authentication**: Basic auth or OAuth for web UI
- [ ] **Additional notifications**: Slack/email alerts
- [ ] **Backup schedules**: Export/import schedule configurations
- [ ] **Container logs**: View container logs from UI
- [ ] **Advanced scheduling**: Support for one-time schedules, delays
- [ ] **Health checks**: Monitor container health and auto-restart
- [ ] **Dashboard stats**: Visualize uptime and restart patterns
- [ ] **SSH tunnel support**: Connect to remote hosts via SSH

## Contributing

This is a personal project for home lab use. Feel free to fork and adapt to your needs!

## License

MIT License - Use freely, modify as needed.

## Support

For issues, questions, or feature requests, please create an issue on the repository.

---

**Built with ❤️ for the home lab community**
