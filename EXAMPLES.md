# DNS Egress Control - Usage Examples

This document provides practical examples of how to use the DNS Egress Control system.

## Basic Usage

### 1. Simple Setup

Start the DNS egress control system with default settings:

```bash
sudo ./egress-domain-whitelist
```

This will:
- Listen for DNS queries on port 53
- Use Google DNS (8.8.8.8:53) as upstream
- Create iptables rules to filter outbound traffic
- Allow IPs based on DNS TTL

### 2. Custom Configuration

```bash
sudo ./egress-domain-whitelist \
    -interface eth0 \
    -upstream-dns 1.1.1.1:53 \
    -port 5353 \
    -domains "example.com,google.com,github.com"
```

This will:
- Use interface eth0 for monitoring
- Use Cloudflare DNS (1.1.1.1:53) as upstream
- Listen on port 5353 for DNS queries
- Pre-whitelist example.com, google.com, and github.com

## Configuration Options

### Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-interface` | Network interface to monitor | `eth0` |
| `-upstream-dns` | Upstream DNS server | `8.8.8.8:53` |
| `-port` | DNS server port | `53` |
| `-refresh-interval` | DNS refresh interval | `300s` (5 minutes) |
| `-use-iptables` | Use iptables for filtering | `true` |
| `-use-ebpf` | Use eBPF for filtering (experimental) | `false` |
| `-domains` | Comma-separated list of domains to pre-whitelist | `""` |

### Environment Variables

You can also use environment variables:

```bash
export INTERFACE=eth0
export UPSTREAM_DNS=1.1.1.1:53
export PORT=5353
sudo ./egress-domain-whitelist
```

## Deployment Scenarios

### 1. Local Development

For local development, you can run the system without root privileges (but without traffic filtering):

```bash
./egress-domain-whitelist -use-iptables=false -port 5353
```

Then configure your system to use this DNS server:

```bash
echo "nameserver 127.0.0.1" > /etc/resolv.conf
```

### 2. Docker Container

Build and run in Docker:

```bash
# Build the image
docker build -t egress-domain-whitelist .

# Run the container
docker run --rm --name egress-control \
    --cap-add=NET_ADMIN \
    --network=host \
    -e INTERFACE=eth0 \
    -e UPSTREAM_DNS=8.8.8.8:53 \
    egress-domain-whitelist
```

### 3. Systemd Service

Create a systemd service file at `/etc/systemd/system/egress-control.service`:

```ini
[Unit]
Description=DNS Egress Control Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/egress-domain-whitelist \
    -interface eth0 \
    -upstream-dns 8.8.8.8:53 \
    -domains "example.com,google.com"
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Then enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable egress-control
sudo systemctl start egress-control
```

## Testing

### 1. Test DNS Resolution

```bash
# Test with dig
dig @localhost example.com

# Test with nslookup
nslookup example.com localhost
```

### 2. Test Traffic Filtering

```bash
# Try to access a whitelisted domain
curl https://example.com

# Try to access a non-whitelisted domain (should fail)
curl https://some-other-domain.com
```

### 3. Check iptables Rules

```bash
# List the custom chain
sudo iptables -L EGRESS_WHITELIST -n

# List all rules
sudo iptables -L -n -v
```

## Monitoring and Debugging

### View Logs

The system logs to stdout by default. You can redirect logs to a file:

```bash
sudo ./egress-domain-whitelist >> /var/log/egress-control.log 2>&1 &
```

### Check DNS Cache

The system logs DNS cache operations. Look for lines like:

```
Cached DNS record for example.com: [93.184.216.34] (TTL: 300s)
Removed expired DNS record for example.com
```

### Check Allowed IPs

```bash
# List all allowed IPs (from iptables)
sudo iptables -L EGRESS_WHITELIST -n | grep ACCEPT
```

## Advanced Usage

### 1. Multiple Upstream DNS Servers

Currently, the system supports only one upstream DNS server. For redundancy, you can run multiple instances with different upstream servers.

### 2. Custom TTL Handling

The system automatically uses the TTL from DNS responses. If you want to override this, you can modify the code to use a minimum or maximum TTL.

### 3. IPv6 Support

The current implementation focuses on IPv4. For IPv6 support, you would need to:
1. Add IPv6 DNS record handling (AAAA records)
2. Add IPv6 iptables rules (ip6tables)
3. Update the eBPF program for IPv6

### 4. CIDR Range Support

To allow entire CIDR ranges instead of individual IPs, you would need to:
1. Modify the DNS resolver to return CIDR ranges
2. Update the firewall manager to handle CIDR ranges
3. For iptables: use `-d` with CIDR notation
4. For eBPF: implement CIDR matching in the eBPF program

## Troubleshooting

### Common Issues

1. **Permission Denied**: The system needs root privileges to modify iptables rules.
   - Solution: Run with `sudo` or as root

2. **DNS Queries Not Working**: Check if the DNS server is running and accessible.
   - Solution: Test with `dig @localhost example.com`

3. **Traffic Not Filtered**: Check if iptables rules are properly configured.
   - Solution: Run `sudo iptables -L -n -v` and verify the EGRESS_WHITELIST chain

4. **eBPF Not Available**: eBPF requires Linux kernel 4.18+ and proper headers.
   - Solution: Use iptables mode or install required kernel headers

### Debug Mode

For more verbose logging, you can modify the code to enable debug logging or add more log statements.

## Performance Considerations

- The DNS cache reduces the number of upstream DNS queries
- The TTL-based cleanup ensures IPs are automatically removed when they expire
- iptables rules are efficient for most use cases
- For high-performance scenarios, consider using eBPF mode (when available)

## Security Considerations

- The system requires root privileges to modify iptables rules
- Ensure your upstream DNS server is trustworthy
- Consider using DNSSEC for additional security
- Monitor logs for suspicious activity
- Regularly update the system to get the latest security fixes
