#!/bin/bash

# Build and run script for Apple Container Tool
# This script provides commands that would work with Apple's container ecosystem

set -e

echo "🍎 Apple Container Tool - DNS Egress Control"
echo "============================================"
echo ""

# Check if we're on macOS (Apple environment)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📋 macOS detected - Apple Container Tool commands"
    echo ""
    
    # Build the container
    echo "📦 Building container..."
    echo "Command: container build -f Containerfile -t dns-egress-control ."
    # container build -f Containerfile -t dns-egress-control .
    
    # Run the container
    echo "🚀 Running container..."
    echo "Command: container run --rm -p 53:53/udp dns-egress-control -use-iptables=false"
    # container run --rm -p 53:53/udp dns-egress-control -use-iptables=false
    
else
    echo "🐧 Linux detected - Using Docker as fallback"
    echo ""
    
    # Build with Docker (fallback for Linux)
    echo "📦 Building Docker image..."
    docker build -f Containerfile -t dns-egress-control .
    
    # Run with Docker
    echo "🚀 Running container with Docker..."
    docker run --rm \
        -p 53:53/udp \
        -p 53:53/tcp \
        --name dns-egress-control \
        dns-egress-control \
        -interface eth0 \
        -upstream-dns 8.8.8.8:53 \
        -port 53 \
        -use-iptables=false \
        -domains "example.com"
fi

echo ""
echo "✅ Container setup complete!"
echo ""
echo "Available commands:"
echo "  - Build: container build -f Containerfile -t dns-egress-control ."
echo "  - Run:   container run --rm -p 53:53/udp dns-egress-control -use-iptables=false"
echo "  - Test:  dig @localhost example.com"
echo ""
echo "For more options, check container-config.json"
