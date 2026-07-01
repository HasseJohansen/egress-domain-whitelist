#!/bin/bash

# Test script for DNS Egress Control Docker image
set -e

echo "🚀 Testing DNS Egress Control Docker build..."

# Build the Docker image
echo "📦 Building Docker image..."
docker build -t dns-egress-control .

# Test basic container startup
echo "🧪 Testing container startup..."
docker run --rm \
    --name test-dns-egress \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --network=host \
    dns-egress-control \
    -interface lo \
    -upstream-dns 8.8.8.8:53 \
    -port 5353 \
    -domains "example.com" \
    -use-iptables=false &

CONTAINER_PID=$!
echo "⏳ Container started with PID: $CONTAINER_PID"

# Wait for DNS server to start
sleep 3

# Test DNS resolution
echo "🔍 Testing DNS resolution..."
if dig @localhost -p 5353 example.com +short; then
    echo "✅ DNS resolution test passed!"
else
    echo "❌ DNS resolution test failed!"
    exit 1
fi

# Test with nslookup
echo "🔍 Testing with nslookup..."
if nslookup -port=5353 example.com localhost; then
    echo "✅ nslookup test passed!"
else
    echo "❌ nslookup test failed!"
    exit 1
fi

# Clean up
echo "🧹 Cleaning up..."
kill $CONTAINER_PID 2>/dev/null || true
wait $CONTAINER_PID 2>/dev/null || true

echo "✅ All Docker tests passed!"
echo ""
echo "🎉 DNS Egress Control Docker image is working correctly!"
echo ""
echo "To run the container manually:"
echo "  docker run --rm --name dns-egress-control \\"
echo "    --cap-add=NET_ADMIN --cap-add=NET_RAW \\"
echo "    --network=host \\"
echo "    dns-egress-control \\"
echo "    -interface eth0 \\"
echo "    -upstream-dns 8.8.8.8:53 \\"
echo "    -domains example.com,google.com"
