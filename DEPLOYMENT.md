# 🚀 Chrontainer - Quick Deployment Guide

## For Raspberry Pi 5

### Step 1: Transfer Files
```bash
# On your local machine, transfer to Raspberry Pi
scp -r chrontainer/ pi@your-pi-ip:/home/pi/

# Or use rsync
rsync -avz chrontainer/ pi@your-pi-ip:/home/pi/chrontainer/
```

### Step 2: SSH to Raspberry Pi
```bash
ssh pi@your-pi-ip
cd /home/pi/chrontainer
```

### Step 3: Update Configuration
```bash
# Edit docker-compose.yml if needed
nano docker-compose.yml

# Change the SECRET_KEY
# Change the port if 5000 is already in use
```

### Step 4: Deploy
```bash
# Start Chrontainer
docker-compose up -d

# Check if it's running
docker ps | grep chrontainer

# View logs
docker logs -f chrontainer
```

### Step 5: Access UI
```
Open browser to: http://your-raspberry-pi-ip:5000
```

## For Synology NAS

### Method 1: Using Docker Package

1. Open **Docker** package on Synology
2. Go to **Image** tab
3. Click **Add** → **Add from file**
4. Upload a built image or use Method 2

### Method 2: Using SSH (Recommended)

```bash
# SSH to Synology
ssh admin@your-nas-ip

# Navigate to docker directory
cd /volume1/docker

# Create chrontainer directory
mkdir chrontainer
cd chrontainer

# Upload files via SCP or FileStation
# Then run:
sudo docker-compose up -d
```

## Testing the Installation

### 1. Check Container is Running
```bash
docker ps | grep chrontainer
```

Expected output:
```
CONTAINER ID   IMAGE              STATUS        PORTS
abc123def456   chrontainer:latest Up 2 minutes  0.0.0.0:5000->5000/tcp
```

### 2. Check Logs
```bash
docker logs chrontainer
```

Expected output:
```
INFO:__main__:Docker client initialized successfully
INFO:__main__:Database initialized
INFO:__main__:Loaded schedule X: container_name - cron_expression
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
```

### 3. Test Web UI
```bash
curl http://localhost:5000
```

Should return HTML content.

### 4. Create Test Schedule

1. Open UI in browser
2. Click "Schedule" on any container
3. Enter: `*/5 * * * *` (every 5 minutes)
4. Click "Create Schedule"
5. Wait 5 minutes and check logs page

## Common Issues

### Port Already in Use
```bash
# Check what's using port 5000
sudo lsof -i :5000

# Edit docker-compose.yml to use different port
# Change "5000:5000" to "5001:5000"
```

### Permission Denied on Docker Socket
```bash
# Add your user to docker group
sudo usermod -aG docker $USER

# Or run with sudo (not recommended for production)
sudo docker-compose up -d
```

### Cannot Connect to Docker Daemon
```bash
# Make sure Docker is running
sudo systemctl status docker

# Start Docker if needed
sudo systemctl start docker
```

## Updating Chrontainer

```bash
# Stop the container
docker-compose down

# Pull/update code
git pull  # if using git
# Or manually update files

# Rebuild and restart
docker-compose up -d --build
```

## Backup Your Data

```bash
# Backup the database
cp data/chrontainer.db data/chrontainer.db.backup-$(date +%Y%m%d)

# Or backup entire data directory
tar -czf chrontainer-backup-$(date +%Y%m%d).tar.gz data/
```

## Uninstalling

```bash
# Stop and remove container
docker-compose down

# Remove images
docker rmi chrontainer:latest

# Remove data (optional)
rm -rf data/
```

## Adding Remote Docker Hosts

After deploying Chrontainer, you can add remote Docker hosts (Synology NAS, other servers) to manage all your containers from one dashboard.

### Important: Security First

⚠️ **NEVER expose the raw Docker socket to the network!** Always use docker-socket-proxy for remote hosts.

### Quick Setup

1. **On the remote host** (e.g., Synology NAS at 192.168.1.100):
   ```bash
   # Create docker-compose.yml for socket-proxy
   mkdir -p /volume1/docker/socket-proxy
   cd /volume1/docker/socket-proxy

   # Create the file with the configuration below
   docker-compose up -d
   ```

2. **Socket-proxy docker-compose.yml**:
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
         - CONTAINERS=1
         - POST=1
         - IMAGES=1
         - INFO=1
         - VERSION=1
   ```

3. **In Chrontainer**:
   - Navigate to **http://your-chrontainer-ip:5000/hosts**
   - Click **"+ Add New Host"**
   - Enter name: `Synology NAS`
   - Enter URL: `tcp://192.168.1.100:2375`
   - Click **"Save"** and test connection

### Complete Documentation

See [REMOTE_HOSTS.md](REMOTE_HOSTS.md) for:
- Detailed socket-proxy configuration
- Security best practices
- Firewall configuration
- Troubleshooting connection issues
- Example complete setups

## Discord Notifications (Optional)

Configure Discord notifications to get alerts when containers are restarted:

1. In Discord: Server Settings → Integrations → Webhooks → New Webhook
2. Copy the webhook URL
3. In Chrontainer: Settings page → paste URL → Save
4. Test with "Send Test Notification"

## Getting Help

1. Check logs: `docker logs chrontainer`
2. Review README.md for detailed docs
3. Review REMOTE_HOSTS.md for multi-host setup
4. Check Docker socket permissions
5. Verify cron syntax at https://crontab.guru

## Next Steps

- [ ] Change SECRET_KEY in production
- [ ] Set up regular backups of data/
- [ ] Configure Discord notifications
- [ ] Add remote Docker hosts (see REMOTE_HOSTS.md)
- [ ] Configure reverse proxy with authentication (optional)
- [ ] Create schedules for your containers
- [ ] Monitor logs page regularly

---

**Enjoy automated container management! 🎉**
