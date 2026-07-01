# Build stage
FROM golang:1.21 as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-amd64 \
    && rm -rf /var/lib/apt/lists/*

# Copy source files
COPY . .

# Build the application
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -o egress-domain-whitelist .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install dependencies
RUN apk add --no-cache \
    libelf \
    zlib \
    bash \
    iptables \
    ip6tables

# Copy the binary
COPY --from=builder /app/egress-domain-whitelist .

# Copy configuration files
COPY --from=builder /app/bpf_program.c .

# Set capabilities for eBPF
RUN setcap cap_net_admin,cap_sys_admin+ep /app/egress-domain-whitelist

EXPOSE 53/udp

ENTRYPOINT ["./egress-domain-whitelist"]
CMD ["-interface", "eth0", "-upstream-dns", "8.8.8.8:53"]
