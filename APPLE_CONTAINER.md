# DNS Egress Control - Apple Container Tool Guide

This guide explains how to build, run, and test the DNS Egress Control system using Apple's Container Tool on macOS.

## 🍎 Apple Container Tool Overview

Apple's Container Tool is a command-line interface for working with containers on macOS. It's designed to be simple and efficient, with native integration into the Apple ecosystem.

## 📋 Prerequisites

- macOS (Ventura or later recommended)
- Apple Container Tool installed
- Xcode command line tools (for Go development)

## 🚀 Quick Start

### 1. Build the Container

```bash
# Navigate to the project directory
cd ~/git-repos/egress-domain-whitelist

# Build the container using the Containerfile
container build -f Containerfile -t dns-egress-control .
```

### 2. Run the Container

```bash
# Basic run (DNS only, no traffic filtering)
container run --rm \
    -p 53:53/udp \
    -p 53:53/tcp \
    dns-egress-control \
    -use-iptables=false \
    -upstream-dns 8.8.8.8:53
```

### 3. Test DNS Resolution

```bash
# Test with dig
dig @localhost example.com

# Test with nslookup
nslookup example.com localhost
```

## 📁 Configuration Files

### Containerfile
The main container configuration file that defines:
- Multi-stage build process
- Runtime dependencies
- Entrypoint and default command
- Exposed ports

### container.yml
Configuration file for Apple Container Tool with:
- Build settings
- Runtime configuration
- Test configuration
- Development settings
- Health checks

### container-config.json
JSON configuration for programmatic use with:
- Complete build and run configurations
- Test and development settings

## 🎯 Common Commands

### Build Commands

```bash
# Build with default settings
container build -t dns-egress-control .

# Build with specific Containerfile
container build -f Containerfile -t dns-egress-control .

# Build for multiple platforms
container build --platform linux/amd64,linux/arm64 -t dns-egress-control .
```

### Run Commands

```bash
# Basic run
container run --rm dns-egress-control

# Run with custom port
container run --rm -p 5353:53/udp dns-egress-control -port 5353

# Run with custom DNS server
container run --rm dns-egress-control -upstream-dns 1.1.1.1:53

# Run with domain pre-whitelisting
container run --rm dns-egress-control -domains "example.com,google.com"
```

### Development Commands

```bash
# Run with source code mounted for development
container run --rm \
    -v $(pwd):/app \
    -p 5353:53/udp \
    dns-egress-control \
    -port 5353 \
    -use-iptables=false

# Run with automatic rebuild on changes
container run --rm \
    -v $(pwd):/app \
    -p 5353:53/udp \
    --watch \
    dns-egress-control \
    -port 5353 \
    -use-iptables=false
```

## 🏗️ Build Configuration

### Multi-stage Build
The Containerfile uses a multi-stage build:

1. **Builder stage**: Uses `golang:1.21-alpine` to compile the Go application
2. **Runtime stage**: Uses `alpine:latest` for a minimal runtime image

### Platform Support
- `linux/amd64` - Intel/AMD 64-bit processors
- `linux/arm64` - ARM 64-bit processors (Apple Silicon)

### Build Arguments
You can customize the build with environment variables:

```bash
# Build with custom Go version
GO_VERSION=1.21 container build -t dns-egress-control .
```

## 🚀 Runtime Configuration

### Port Configuration

| Port | Protocol | Description |
|------|----------|-------------|
| 53 | UDP | DNS queries |
| 53 | TCP | DNS queries (TCP fallback) |

### Volume Mounts

| Source | Target | Description |
|--------|--------|-------------|
| `./logs` | `/app/logs` | Application logs |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INTERFACE` | `eth0` | Network interface to monitor |
| `UPSTREAM_DNS` | `8.8.8.8:53` | Upstream DNS server |
| `PORT` | `53` | DNS server port |
| `USE_IPTABLES` | `false` | Use iptables for filtering |
| `DOMAINS` | `""` | Comma-separated domains to pre-whitelist |

### Command Line Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `-interface` | `eth0` | Network interface |
| `-upstream-dns` | `8.8.8.8:53` | Upstream DNS server |
| `-port` | `53` | DNS server port |
| `-refresh-interval` | `300s` | DNS refresh interval |
| `-use-iptables` | `false` | Use iptables for filtering |
| `-use-ebpf` | `false` | Use eBPF for filtering |
| `-domains` | `""` | Domains to pre-whitelist |

## 🧪 Testing

### Test DNS Resolution

```bash
# Start the container
container run --rm -d -p 5353:53/udp dns-egress-control -port 5353

# Test with dig
dig @localhost -p 5353 example.com

# Test with nslookup
nslookup -port=5353 example.com localhost

# Test with curl (if domain is whitelisted)
curl -v http://example.com --connect-timeout 5
```

### Test Script

Use the provided test script:

```bash
# Make executable
chmod +x build-apple-container.sh

# Run the test
./build-apple-container.sh
```

## 🔧 Advanced Configuration

### Network Modes

```bash
# Host network mode (for traffic filtering)
container run --rm --network=host dns-egress-control

# Bridge network mode (for isolation)
container run --rm dns-egress-control
```

### Capabilities

For iptables support, you need additional capabilities:

```bash
container run --rm \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --network=host \
    dns-egress-control \
    -use-iptables=true
```

### Resource Limits

```bash
# Limit CPU and memory
container run --rm \
    --cpus=1 \
    --memory=256m \
    dns-egress-control
```

## 📊 Monitoring

### View Container Logs

```bash
# View logs in real-time
container logs -f <container-id>

# View last 100 lines
container logs --tail 100 <container-id>

# View logs with timestamps
container logs -t <container-id>
```

### Check Container Status

```bash
# List running containers
container ps

# List all containers
container ps -a

# Inspect container details
container inspect <container-id>
```

## 🎯 Production Deployment

### 1. Build Production Image

```bash
container build -f Containerfile -t dns-egress-control:1.0.0 .
```

### 2. Run in Production

```bash
container run -d \
    --name dns-egress-control \
    --restart=unless-stopped \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --network=host \
    -v $(pwd)/logs:/app/logs \
    dns-egress-control:1.0.0 \
    -interface eth0 \
    -upstream-dns 8.8.8.8:53 \
    -domains "example.com,google.com,github.com"
```

### 3. Update Configuration

To update the configuration, you can:

1. **Stop the container**: `container stop dns-egress-control`
2. **Remove the container**: `container rm dns-egress-control`
3. **Run with new configuration**: Use updated command line arguments

## 🔄 Development Workflow

### 1. Mount Source Code

```bash
container run --rm -it \
    -v $(pwd):/app \
    -p 5353:53/udp \
    dns-egress-control \
    -port 5353 \
    -use-iptables=false
```

### 2. Automatic Rebuild

```bash
# Run with file watching
container run --rm \
    -v $(pwd):/app \
    -p 5353:53/udp \
    --watch \
    dns-egress-control \
    -port 5353 \
    -use-iptables=false
```

### 3. Debug Mode

```bash
# Run with debug output
container run --rm \
    -v $(pwd):/app \
    -p 5353:53/udp \
    dns-egress-control \
    -port 5353 \
    -use-iptables=false \
    -domains "example.com"
```

## 🚨 Troubleshooting

### Common Issues

1. **Port Already in Use**: Another service is using port 53
   - Solution: Use a different port with `-port 5353`

2. **Permission Denied**: Container needs additional capabilities
   - Solution: Add `--cap-add=NET_ADMIN --cap-add=NET_RAW`

3. **DNS Queries Not Working**: Check if the container is running
   - Solution: `container ps` and `container logs <container-id>`

4. **Build Failures**: Check Go module dependencies
   - Solution: `go mod tidy` and rebuild

### Debug Commands

```bash
# Check container logs
container logs <container-id>

# Check container processes
container top <container-id>

# Check container stats
container stats <container-id>
```

## 📚 Additional Resources

- [Apple Container Tool Documentation](https://developer.apple.com/documentation/containertool)
- [Main README](../README.md) - Complete project documentation
- [Examples](../EXAMPLES.md) - Usage examples and scenarios

---

**Need help?** Open an issue on GitHub or check the main documentation.

*Last updated: 2024*
