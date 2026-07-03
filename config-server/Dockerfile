# Dockerfile for the configuration server
FROM golang:1.22-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY config-server/go.mod config-server/go.sum ./
RUN go mod download

# Copy source code
COPY config-server/ ./
COPY ebpf/ ./ebpf/
COPY main.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/config-server ./config-server/cmd/server

# Final stage
FROM alpine:3.18

# Install ca-certificates for TLS
RUN apk --no-cache add ca-certificates sqlite

# Create data and certs directories
RUN mkdir -p /var/lib/config-server/data /var/lib/config-server/certs /var/lib/config-server/static /var/lib/config-server/templates

# Copy built binary
COPY --from=builder /app/config-server /usr/local/bin/config-server

# Copy static files
COPY --from=builder /app/config-server/web/static /var/lib/config-server/static
COPY --from=builder /app/config-server/web/templates /var/lib/config-server/templates

# Copy eBPF programs (if they exist)
COPY --from=builder /app/ebpf/compiled /var/lib/config-server/ebpf/compiled

# Set working directory
WORKDIR /var/lib/config-server

# Create a non-root user for security
RUN adduser -D -g 'config-server' config-server
USER config-server

# Set permissions
RUN chown -R config-server:config-server /var/lib/config-server

# Expose port
EXPOSE 8443

# Set environment variables
ENV DATABASE_PATH=/var/lib/config-server/data/config-server.db
ENV CONFIG_DIR=/var/lib/config-server

# Entrypoint
ENTRYPOINT ["/usr/local/bin/config-server"]
CMD ["--db", "/var/lib/config-server/data/config-server.db", "--password", "changeme"]
