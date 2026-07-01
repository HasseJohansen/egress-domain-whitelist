# DNS Egress Control with eBPF

A project that implements DNS-based egress control using eBPF. This system intercepts DNS queries, resolves domains, and dynamically allows outbound traffic to the resolved IPs for the duration of the DNS TTL.

## Features

- **DNS Interception**: Captures DNS queries and resolves them through upstream DNS servers
- **TTL-based Whitelisting**: Automatically allows IPs for the duration of their DNS TTL
- **eBPF Filtering**: Uses XDP (eXpress Data Path) to filter outbound traffic at the network level
- **Automatic Cleanup**: Removes expired IPs from the whitelist when their TTL expires
- **Domain Monitoring**: Periodically refreshes DNS records for configured domains

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     DNS Egress Control System                  │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │  DNS Server  │    │ Domain Cache │    │  eBPF Manager    │  │
│  │             │    │             │    │                 │  │
│  │ - Listens on │    │ - Stores DNS │    │ - Manages XDP   │  │
│  │   port 53    │───▶│   records   │───▶│   programs       │  │
│  │ - Handles   │    │ - Tracks TTL│    │ - Updates maps  │  │
│  │   queries    │    │ - Auto-clean│    │ - Filters traffic│  │
│  └─────────────┘    └─────────────┘    └─────────────────┘  │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    eBPF/XDP Filter                        ││
│  │  - Intercepts all outbound traffic                       ││
│  │  - Checks destination IP against allowed list            ││
│  │  - Allows traffic to whitelisted IPs                      ││
│  │  - Drops traffic to non-whitelisted IPs                  ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## How It Works

1. **DNS Query Handling**: When a client makes a DNS query, our DNS server intercepts it
2. **DNS Resolution**: The server resolves the domain through an upstream DNS server
3. **IP Whitelisting**: The resolved IPs are added to the eBPF map with their TTL
4. **Traffic Filtering**: The eBPF/XDP program checks all outbound packets against the whitelist
5. **TTL Management**: When the TTL expires, the IPs are automatically removed from the whitelist

## Installation

### Prerequisites

- Linux kernel 4.18+ (for XDP support)
- Go 1.21+
- clang and llvm (for eBPF compilation)
- libelf-dev
- Network interface that supports XDP

### Building

```bash
# Clone the repository
git clone https://github.com/HasseJohansen/egress-domain-whitelist.git
cd egress-domain-whitelist

# Build the project
make build

# Or build with eBPF program compilation
make build-ebpf
```

### Using Docker

```bash
# Build the Docker image
docker build -t egress-domain-whitelist .

# Run the container with necessary privileges
docker run --rm --name egress-control \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    --network=host \
    -e INTERFACE=eth0 \
    -e UPSTREAM_DNS=8.8.8.8:53 \
    egress-domain-whitelist
```

## Configuration

### Environment Variables

- `INTERFACE`: Network interface to attach XDP program to (default: `eth0`)
- `UPSTREAM_DNS`: Upstream DNS server to use for resolution (default: `8.8.8.8:53`)
- `PORT`: Port to listen on for DNS queries (default: `53`)
- `REFRESH_INTERVAL`: How often to refresh DNS records (default: `300s`)

### Command Line Arguments

```bash
./egress-domain-whitelist \
    -interface eth0 \
    -upstream-dns 8.8.8.8:53 \
    -port 53 \
    -domains example.com,google.com
```

## Usage

### Basic Usage

1. Start the service:
   ```bash
   sudo ./egress-domain-whitelist -interface eth0
   ```

2. Configure your system to use this DNS server (e.g., in `/etc/resolv.conf`):
   ```
   nameserver 127.0.0.1
   ```

3. Now when you access any domain, its IPs will be automatically whitelisted for the DNS TTL duration

### Pre-whitelisting Domains

You can pre-whitelist specific domains by specifying them in the configuration:

```bash
sudo ./egress-domain-whitelist -interface eth0 -domains example.com,google.com
```

This will resolve these domains immediately and keep their IPs whitelisted, refreshing them periodically.

## Implementation Details

### eBPF/XDP Program

The eBPF program (`bpf_program.c`) implements an XDP filter that:

1. Parses Ethernet headers to identify IP packets
2. Extracts source and destination IP addresses
3. Checks if the IP is in the allowed list (eBPF map)
4. Allows or drops the packet based on the check

### DNS Server

The DNS server:

1. Listens for DNS queries on UDP port 53
2. Resolves domains through upstream DNS servers
3. Caches DNS responses with their TTL
4. Updates the eBPF maps with allowed IPs
5. Returns DNS responses to clients

### Domain Cache

The domain cache:

1. Stores DNS records with their TTL
2. Automatically removes expired records
3. Provides thread-safe access to cached records

### IP Management

The system:

1. Adds IPs to the eBPF maps when they are resolved
2. Removes IPs when their TTL expires
3. Periodically refreshes DNS records for configured domains
4. Updates eBPF maps when IPs change

## Security Considerations

- **Privileges**: The application requires `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` capabilities to load eBPF programs
- **Network Interface**: Only attach to interfaces where you want to filter traffic
- **DNS Spoofing**: Ensure your upstream DNS server is trustworthy
- **Performance**: XDP processing happens at the network layer, so it's very efficient

## Limitations

- Currently only supports IPv4 (IPv6 support is in the eBPF program but not fully implemented in Go)
- Requires Linux kernel with XDP support
- Needs root privileges to load eBPF programs
- DNS server only handles A records (IPv4 addresses)

## Future Enhancements

- [ ] Full IPv6 support
- [ ] TCP DNS support
- [ ] DNSSEC validation
- [ ] More sophisticated IP management (CIDR ranges, etc.)
- [ ] Metrics and monitoring
- [ ] Configuration file support
- [ ] Multiple upstream DNS servers with failover

## License

This project is licensed under the GPL License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
