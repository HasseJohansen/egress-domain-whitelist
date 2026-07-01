# DNS Egress Control Containerfile for Apple Container Tool
# Compatible with Apple's container ecosystem

# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata

# Copy source files
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the application for Linux
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dns-egress-control .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache \
    iptables \
    ip6tables \
    bash \
    tzdata \
    ca-certificates \
    sudo \
    shadow \
    bind-tools \
    curl

# Create a non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the binary from builder
COPY --from=builder /app/dns-egress-control .
COPY --from=builder /app/README.md .
COPY --from=builder /app/EXAMPLES.md .
COPY --from=builder /app/LICENSE .

# Set permissions
RUN chown appuser:appgroup /app/dns-egress-control && \
    chmod +x /app/dns-egress-control

# Create entrypoint script
RUN echo '#!/bin/bash
set -e

echo "DNS Egress Control v1.0"
echo "======================="
echo ""

# If running as root, set up iptables and drop privileges
if [ "$(id -u)" = "0" ]; then
    echo "🔧 Setting up iptables rules..."
    
    # Set capabilities for iptables (will be handled by container runtime)
    echo "Note: For iptables support, run with --cap-add=NET_ADMIN --cap-add=NET_RAW"
    
    # Run as non-root user
    echo "🚀 Starting DNS Egress Control as appuser..."
    exec su-exec appuser /app/dns-egress-control "$@"
else
    echo "🚀 Starting DNS Egress Control..."
    exec /app/dns-egress-control "$@"
fi' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

# Create health check script
RUN echo '#!/bin/bash
# Health check - verify DNS server is responding
if nc -z -w 2 localhost 53 >/dev/null 2>&1; then
    exit 0
else
    exit 1
fi' > /healthcheck.sh && \
    chmod +x /healthcheck.sh

# Expose DNS port
EXPOSE 53/udp
EXPOSE 53/tcp

# Set default command
ENTRYPOINT ["/entrypoint.sh"]

# Default command - safe for testing without iptables
CMD ["-interface", "eth0", "-upstream-dns", "8.8.8.8:53", "-port", "53", "-use-iptables=false"]
