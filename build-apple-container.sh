#!/bin/bash

# Build and run script for Apple Container Tool
# This script provides commands that work with Apple's container ecosystem

set -e

echo "🍎 Apple Container Tool - DNS Egress Control"
echo "============================================"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if we're on macOS
is_macos() {
    [[ "$OSTYPE" == "darwin"* ]]
}

# Function to check if we're on Linux
is_linux() {
    [[ "$OSTYPE" == "linux"* ]]
}

# Check available container tools
if command_exists container; then
    CONTAINER_CMD="container"
elif command_exists docker; then
    CONTAINER_CMD="docker"
else
    echo "❌ Error: No container runtime found (container or docker)"
    echo "Please install Apple Container Tool or Docker"
    exit 1
fi

echo "📋 Using container runtime: $CONTAINER_CMD"
echo ""

# Build the container
BUILD_CMD="$CONTAINER_CMD build"
if [ "$CONTAINER_CMD" = "container" ]; then
    # Apple Container Tool
    echo "📦 Building with Apple Container Tool..."
    echo "Command: $BUILD_CMD -f Containerfile.simple -t dns-egress-control ."
    
    # Try building with the simple Containerfile first
    if $BUILD_CMD -f Containerfile.simple -t dns-egress-control .; then
        echo "✅ Build successful!"
    else
        echo "⚠️  Simple build failed, trying with standard Containerfile..."
        # Try with the standard Containerfile
        if $BUILD_CMD -f Containerfile -t dns-egress-control .; then
            echo "✅ Build successful with standard Containerfile!"
        else
            echo "❌ Build failed. Let's try with Docker syntax..."
            # Try with Dockerfile
            if $BUILD_CMD -f Dockerfile -t dns-egress-control .; then
                echo "✅ Build successful with Dockerfile!"
            else
                echo "❌ All build attempts failed."
                echo "Please check the Containerfile syntax and try again."
                exit 1
            fi
        fi
    fi
else
    # Docker
    echo "📦 Building with Docker..."
    if $BUILD_CMD -f Containerfile.simple -t dns-egress-control .; then
        echo "✅ Build successful!"
    else
        echo "⚠️  Simple build failed, trying with standard Containerfile..."
        if $BUILD_CMD -f Containerfile -t dns-egress-control .; then
            echo "✅ Build successful with standard Containerfile!"
        else
            echo "❌ Build failed. Trying with Dockerfile..."
            if $BUILD_CMD -f Dockerfile -t dns-egress-control .; then
                echo "✅ Build successful with Dockerfile!"
            else
                echo "❌ All build attempts failed."
                exit 1
            fi
        fi
    fi
fi

echo ""
echo "🚀 Running container..."
echo ""

# Run the container
RUN_CMD="$CONTAINER_CMD run --rm"

if [ "$CONTAINER_CMD" = "container" ]; then
    # Apple Container Tool
    echo "Running with Apple Container Tool..."
    echo "Command: $RUN_CMD -p 53:53/udp dns-egress-control -use-iptables=false"
    echo ""
    echo "To actually run the container, execute:"
    echo "  $RUN_CMD -p 53:53/udp dns-egress-control -use-iptables=false"
    echo ""
    echo "Then test with:"
    echo "  dig @localhost example.com"
else
    # Docker
    echo "Running with Docker..."
    $RUN_CMD \
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
echo "  Build:  $CONTAINER_CMD build -f Containerfile.simple -t dns-egress-control ."
echo "  Run:    $CONTAINER_CMD run --rm -p 53:53/udp dns-egress-control -use-iptables=false"
echo "  Test:   dig @localhost example.com"
echo ""
echo "For more options, check APPLE_CONTAINER.md or container.yml"
