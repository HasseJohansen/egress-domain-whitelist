# DNS Egress Control - Docker Deployment

This document provides comprehensive instructions for building, running, and testing the DNS Egress Control system using Docker.

## 🐳 Quick Start

### Build the Docker Image

```bash
# Build the production image
docker build -t dns-egress-control .

# Or build the test image
docker build -t dns-egress-control -f Dockerfile.test .
```

### Run the Container

```bash
# Basic run (DNS only, no traffic filtering)
docker run --rm --name dns-egress-control \
    -p 53:53/udp \
    -p 53:53/tcp \
    dns-egress-control \
    -use-iptables=false \
    -upstream-dns 8.8.8.8:53

# Full run with traffic filtering (requires NET_ADMIN capabilities)
docker run --rm --name dns-egress-control \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --network=host \
    dns-egress-control \
    -interface eth0 \
    -upstream-dns 8.8.8.8:53 \
    -domains "example.com,google.com"
```

## 📋 Docker Configuration Options

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `INTERFACE` | Network interface to monitor | `eth0` |
| `UPSTREAM_DNS` | Upstream DNS server | `8.8.8.8:53` |
| `PORT` | DNS server port | `53` |
| `REFRESH_INTERVAL` | DNS refresh interval | `300s` |
| `USE_IPTABLES` | Use iptables for filtering | `true` |
| `USE_EBPF` | Use eBPF for filtering | `false` |
| `DOMAINS` | Comma-separated domains to pre-whitelist | `""` |

### Command Line Arguments

You can also pass command line arguments directly:

```bash
docker run --rm dns-egress-control \
    -interface eth0 \
    -upstream-dns 1.1.1.1:53 \
    -port 5353 \
    -domains "example.com,google.com" \
    -use-iptables=false
```

## 🧪 Testing with Docker

### 1. Using docker-compose

The easiest way to test is using the provided `docker-compose.yml`:

```bash
# Start the services
docker-compose up -d

# View logs
docker-compose logs -f dns-egress-control

# Test DNS resolution
dig @localhost example.com

# Stop the services
docker-compose down
```

### 2. Manual Testing

```bash
# Start the container in background
docker run -d --name dns-egress-control \
    -p 5353:53/udp \
    -p 5353:53/tcp \
    dns-egress-control \
    -port 5353 \
    -use-iptables=false \
    -domains "example.com"

# Test DNS resolution
dig @localhost -p 5353 example.com

# Test with nslookup
nslookup -port=5353 example.com localhost

# View container logs
docker logs dns-egress-control

# Stop the container
docker stop dns-egress-control
```

### 3. Using the Test Script

```bash
# Make the test script executable
chmod +x test-docker.sh

# Run the test
./test-docker.sh
```

## 🔧 Production Deployment

### 1. Build and Push to Registry

```bash
# Build the image
docker build -t your-registry/dns-egress-control:latest .

# Push to registry
docker push your-registry/dns-egress-control:latest
```

### 2. Run in Production

```bash
# Create a data directory for logs
docker volume create dns_egress_logs

# Run the container
docker run -d --name dns-egress-control \
    --restart=unless-stopped \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --network=host \
    -v dns_egress_logs:/app/logs \
    your-registry/dns-egress-control:latest \
    -interface eth0 \
    -upstream-dns 8.8.8.8:53 \
    -domains "example.com,google.com,github.com"
```

### 3. Systemd Service with Docker

Create `/etc/systemd/system/dns-egress-control.service`:

```ini
[Unit]
Description=DNS Egress Control Service
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/docker run --rm \
    --name dns-egress-control \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --network=host \
    your-registry/dns-egress-control:latest \
    -interface eth0 \
    -upstream-dns 8.8.8.8:53 \
    -domains "example.com,google.com"
ExecStop=/usr/bin/docker stop dns-egress-control
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable dns-egress-control
sudo systemctl start dns-egress-control
```

## 🌐 Network Configuration

### For Testing (Without Root Privileges)

If you don't have root privileges or don't want to modify iptables:

```bash
docker run --rm dns-egress-control \
    -p 5353:53/udp \
    -p 5353:53/tcp \
    -use-iptables=false \
    -port 5353
```

Then configure your system to use this DNS server:

```bash
# Linux
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# Or for testing
echo "nameserver 127.0.0.1" > /tmp/resolv.conf.test
```

### For Production (With Traffic Filtering)

To enable traffic filtering, you need:

1. **NET_ADMIN capability** - for iptables rules
2. **NET_RAW capability** - for packet filtering
3. **Host network mode** - to intercept all traffic

```bash
docker run --rm \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --network=host \
    dns-egress-control \
    -interface eth0
```

## 🔍 Monitoring and Debugging

### View Container Logs

```bash
# View logs in real-time
docker logs -f dns-egress-control

# View last 100 lines
docker logs --tail 100 dns-egress-control

# View logs with timestamps
docker logs -t dns-egress-control
```

### Check DNS Resolution

```bash
# Test with dig
dig @localhost example.com

# Test with nslookup
nslookup example.com localhost

# Test with curl (if domain is whitelisted)
curl -v http://example.com
```

### Check iptables Rules (if using iptables)

```bash
# Connect to the container
docker exec -it dns-egress-control sh

# Check iptables rules
iptables -L -n -v
iptables -L EGRESS_WHITELIST -n
```

## 📊 Health Checks

The Docker image includes a health check that verifies the DNS server is responding:

```bash
# Check container health
docker inspect --format='{{json .State.Health}}' dns-egress-control

# View health status
docker ps --filter "health=unhealthy"
```

## 🎯 Common Use Cases

### 1. Development Environment

```bash
# Run with DNS only (no traffic filtering)
docker run --rm -p 5353:53/udp dns-egress-control \
    -port 5353 \
    -use-iptables=false

# Configure your app to use this DNS server
```

### 2. CI/CD Testing

```bash
# Test in your CI pipeline
docker run --rm dns-egress-control \
    -use-iptables=false \
    -port 5353 &

# Run your tests that use DNS
# ...
```

### 3. Production Deployment

```bash
# Full production deployment
docker run -d --name dns-egress-control \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --network=host \
    --restart=unless-stopped \
    dns-egress-control \
    -interface eth0 \
    -upstream-dns 8.8.8.8:53 \
    -domains "api.example.com,cdn.example.com"
```

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied**: Container needs NET_ADMIN and NET_RAW capabilities
   - Solution: Add `--cap-add=NET_ADMIN --cap-add=NET_RAW`

2. **Port Already in Use**: Another service is using port 53
   - Solution: Use a different port with `-port 5353` and `-p 5353:5353/udp`

3. **DNS Queries Not Working**: Check if the container is running
   - Solution: `docker ps` and `docker logs dns-egress-control`

4. **Traffic Not Filtered**: iptables rules may not be working
   - Solution: Check with `docker exec -it dns-egress-control iptables -L -n`

### Debug Mode

For more verbose logging, you can run with debug output:

```bash
docker run --rm dns-egress-control \
    -use-iptables=false \
    -port 5353 \
    -domains "example.com" \
    2>&1 | tee dns-egress-debug.log
```

## 📈 Performance Considerations

- The DNS cache reduces upstream DNS queries
- TTL-based cleanup prevents memory leaks
- iptables rules are efficient for most use cases
- For high-performance scenarios, consider the eBPF version (future enhancement)

## 🔒 Security Considerations

- Run as non-root user inside the container
- Use capabilities instead of running as root
- Limit network access with `--network=host` or custom networks
- Regularly update the base image
- Monitor container logs for suspicious activity

## 📚 Additional Resources

- [Main README](../README.md) - Complete project documentation
- [Examples](../EXAMPLES.md) - Usage examples and scenarios
- [Source Code](../main.go) - Main implementation

---

**Need help?** Open an issue on GitHub or check the main documentation.
