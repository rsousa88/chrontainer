# Adding Remote Docker Hosts to Chrontainer

This guide explains how to safely connect Chrontainer to remote Docker hosts (like Synology NAS, other servers, etc.).

## ⚠️ Security Warning

**NEVER expose Docker socket directly to the network!**
- Raw Docker socket access = root access to the host
- Always use a security proxy like docker-socket-proxy

---

## Method 1: Docker Socket Proxy (Recommended) ✅

The **docker-socket-proxy** creates a secure layer between Chrontainer and the Docker daemon, only exposing safe API endpoints.

### On Your Remote Host (e.g., Synology NAS)

**Option 1: Use the provided compose file** (Easiest):

```bash
# Copy docker-compose.socket-proxy.yml to your remote host
scp docker-compose.socket-proxy.yml user-host-ip:/volume1/docker/

# SSH to remote host and deploy
ssh user-host-ip
cd /volume1/docker
docker-compose -f docker-compose.socket-proxy.yml up -d
```

**Option 2: Create your own docker-compose.yml** for socket-proxy:

```yaml
version: '3.8'

services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy
    container_name: docker-socket-proxy
    restart: unless-stopped
    ports:
      - "2375:2375"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      # Security: Only enable what Chrontainer needs
      - CONTAINERS=1      # List containers
      - POST=1            # Allow POST (for start/stop/restart)
      - BUILD=0           # Disable build
      - COMMIT=0          # Disable commit
      - CONFIGS=0         # Disable configs
      - DISTRIBUTION=1    # Required for update checks (registry digest lookup)
      - EXEC=0            # Disable exec
      - IMAGES=1          # Allow reading images
      - INFO=1            # Allow info
      - NETWORKS=0        # Disable networks (optional)
      - NODES=0           # Disable nodes
      - PLUGINS=0         # Disable plugins
      - SECRETS=0         # Disable secrets
      - SERVICES=0        # Disable services
      - SESSION=0         # Disable session
      - SWARM=0           # Disable swarm
      - SYSTEM=1          # Required for host metrics (disk usage via /system/df)
      - TASKS=0           # Disable tasks
      - VOLUMES=0         # Disable volumes
      - VERSION=1         # Allow version check
    networks:
      - proxy

networks:
  proxy:
    driver: bridge
```

2. **Deploy the socket proxy:**

```bash
docker-compose up -d
```

3. **Test the proxy:**

```bash
curl http://localhost:2375/version
```

You should see Docker version JSON output.

4. **Configure firewall (if needed):**

On Synology: Control Panel → Security → Firewall → Edit Rules
- Allow port 2375 from trusted IPs only (e.g., 192.168.1.100/24)

### In Chrontainer

1. Open **http://your-chrontainer-ip:5000/hosts**
2. Click **"+ Add New Host"**
3. Enter:
   - **Name:** `Synology NAS` (or any name)
   - **URL:** `tcp://192.168.1.100:2375` (your NAS IP)
4. Click **"Save"**

If the connection test succeeds, you're done! All containers from both hosts will appear on the dashboard.

---

## Method 2: Direct Docker Socket (Not Recommended)

Only use this method on trusted, isolated networks for testing.

### On Remote Host

Edit `/etc/docker/daemon.json`:

```json
{
  "hosts": [
    "unix:///var/run/docker.sock",
    "tcp://0.0.0.0:2375"
  ]
}
```

Restart Docker:
```bash
sudo systemctl restart docker
```

**Security Risk:** This exposes full Docker API without authentication. Anyone on your network can control Docker.

---

## Method 3: SSH Tunnel (Future Feature)

Coming soon! This will allow secure connections via SSH without exposing Docker API.

```
# Planned feature
tcp+ssh://user@remote-host:22
```

---

## Troubleshooting

### Connection Refused (Errno 111)

**Problem:** Docker API is not listening on the port.

**Solutions:**
1. Verify socket-proxy is running: `docker ps | grep socket-proxy`
2. Check if port is open: `netstat -tulpn | grep 2375`
3. Test locally on remote host: `curl localhost:2375/version`

### Connection Timeout

**Problem:** Firewall blocking the connection.

**Solutions:**
1. Check firewall rules on remote host
2. Check router/network firewall
3. Verify IP address and port are correct
4. Try from Chrontainer host: `curl http://remote-ip:2375/version`

### Permission Denied

**Problem:** Socket proxy environment variables too restrictive.

**Solutions:**
1. Enable required endpoints in socket-proxy environment variables
2. For containers: `CONTAINERS=1`
3. For start/stop/restart: `POST=1`
4. For images: `IMAGES=1`

### Cannot Start/Stop Containers

**Problem:** `POST=0` in socket-proxy configuration.

**Solution:** Set `POST=1` in docker-socket-proxy environment and restart it.

### Host Metrics Disk Usage Shows 0 GB

**Problem:** `SYSTEM=0` in socket-proxy configuration.

**Solution:** Set `SYSTEM=1` to allow `/system/df` and restart the socket-proxy container.

---

## Socket Proxy vs Direct Access Comparison

| Feature | Socket Proxy | Direct Socket |
|---------|-------------|---------------|
| Security | ✅ High - Filtered API | ❌ None - Full root access |
| Setup Complexity | Medium | Easy |
| Port Required | 2375 (configurable) | 2375 |
| Authentication | Via network isolation | None |
| Fine-grained Control | ✅ Yes | ❌ No |
| **Recommendation** | ✅ **Use This** | ❌ Avoid |

---

## Example: Complete Setup for Synology NAS

### 1. On Synology via SSH

```bash
# Connect to Synology
ssh user-host-ip

# Create directory for socket-proxy
sudo mkdir -p /volume1/docker/socket-proxy
cd /volume1/docker/socket-proxy

# Create docker-compose.yml (use vi or nano)
sudo vi docker-compose.yml
# Paste the socket-proxy config from above

# Start socket-proxy
sudo docker-compose up -d

# Verify it's running
sudo docker ps | grep socket-proxy

# Test locally
curl localhost:2375/version
```

### 2. In Chrontainer

1. Navigate to: http://192.168.1.100:5000/hosts
2. Add host:
   - Name: `Synology NAS`
   - URL: `tcp://192.168.1.100:2375`
3. Click "Test" - should show "Connection successful!"
4. Go to Dashboard - see containers from both hosts

### 3. Verify Multi-Host Setup

You should now see:
- Containers labeled with "Local" badge (from Raspberry Pi)
- Containers labeled with "Synology NAS" badge (from NAS)
- All containers manageable (start/stop/restart/schedule)

---

## Security Best Practices

1. **Use socket-proxy** - Never expose raw Docker socket
2. **Firewall rules** - Restrict port 2375 to trusted IPs only
3. **Private network** - Only expose on local network (192.168.x.x)
4. **No internet exposure** - Never expose port 2375 to the internet
5. **Monitor logs** - Check socket-proxy logs regularly
6. **Minimal permissions** - Only enable needed API endpoints
7. **Update regularly** - Keep socket-proxy image updated

---

## Advanced: Custom Socket Proxy Configuration

For more restrictive environments:

```yaml
environment:
  # Minimal config - read-only operations
  - CONTAINERS=1
  - POST=0
  - IMAGES=1
  - INFO=1
  - VERSION=1
  - PING=1
```

This allows viewing containers but prevents any modifications. Useful for monitoring-only setups.

---

## Next Steps

Once remote hosts are connected:
1. Create schedules for remote containers
2. Set up Discord notifications
3. Monitor all hosts from one dashboard
4. Schedule coordinated restarts across hosts

---

## Support

Having issues? Check:
1. Socket-proxy logs: `docker logs docker-socket-proxy`
2. Chrontainer logs: `docker logs chrontainer`
3. Network connectivity: `ping remote-host-ip`
4. Port accessibility: `telnet remote-host-ip 2375`

For more help, open an issue on GitHub.
