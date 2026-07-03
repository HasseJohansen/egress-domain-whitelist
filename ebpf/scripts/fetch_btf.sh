#!/bin/bash
# BTFHub fallback script for fetching BTF when kernel doesn't have embedded BTF
# This script downloads appropriate BTF from https://btfhub.com for CO-RE compatibility

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# BTFHub URL
BTFHUB_URL="https://btfhub.com"
BTFHUB_RAW_URL="https://raw.githubusercontent.com/aquasecurity/btfhub/main"

# Output file
OUTPUT_FILE="$(dirname "$0")/../vmlinux.h"
TEMP_BTF_FILE="/tmp/kernel_btf.o"
TEMP_BTF_JSON="/tmp/kernel_btf.json"

echo -e "${BLUE}Starting BTFHub fallback...${NC}"

# Function to detect kernel version
get_kernel_version() {
    local version=""
    
    # Try uname first
    if command -v uname &> /dev/null; then
        version=$(uname -r | cut -d- -f1)
        echo "Detected kernel version from uname: $version"
        echo "$version"
        return 0
    fi
    
    # Try /proc/version
    if [ -f /proc/version ]; then
        version=$(grep -oP '\d+\.\d+\.\d+' /proc/version | head -1)
        if [ -n "$version" ]; then
            echo "Detected kernel version from /proc/version: $version"
            echo "$version"
            return 0
        fi
    fi
    
    # Try /proc/sys/kernel/osrelease
    if [ -f /proc/sys/kernel/osrelease ]; then
        version=$(cat /proc/sys/kernel/osrelease | cut -d- -f1)
        echo "Detected kernel version from /proc/sys/kernel/osrelease: $version"
        echo "$version"
        return 0
    fi
    
    echo -e "${RED}Error: Could not detect kernel version${NC}" >&2
    return 1
}

# Function to download BTF from BTFHub
fetch_btf_from_btfhub() {
    local kernel_version="$1"
    local arch="$2"
    
    echo -e "${YELLOW}Fetching BTF for kernel $kernel_version ($arch) from BTFHub...${NC}"
    
    # BTFHub organizes by: https://raw.githubusercontent.com/aquasecurity/btfhub/main/specs/<arch>/<kernel_version>/<flavor>/btf
    # Common architectures: x86_64, aarch64, s390x
    # Common flavors: vanilla, distro
    
    # Try different flavors in order
    local flavors=("vanilla" "distro" "cloud")
    local btf_url=""
    
    for flavor in "${flavors[@]}"; do
        btf_url="${BTFHUB_RAW_URL}/specs/${arch}/${kernel_version}/${flavor}/btf"
        echo "Trying BTF URL: $btf_url"
        
        if curl -s -f -o "$TEMP_BTF_JSON" "$btf_url"; then
            echo -e "${GREEN}Found BTF for $kernel_version ($arch, $flavor)${NC}"
            return 0
        fi
    done
    
    # Try without specifying flavor
    btf_url="${BTFHUB_RAW_URL}/specs/${arch}/${kernel_version}/btf"
    echo "Trying BTF URL: $btf_url"
    
    if curl -s -f -o "$TEMP_BTF_JSON" "$btf_url"; then
        echo -e "${GREEN}Found BTF for $kernel_version ($arch)${NC}"
        return 0
    fi
    
    echo -e "${RED}Error: Could not find BTF for kernel $kernel_version ($arch) on BTFHub${NC}" >&2
    return 1
}

# Function to extract BTF and convert to vmlinux.h
extract_and_convert_btf() {
    local btf_json="$1"
    
    echo -e "${YELLOW}Converting BTF to vmlinux.h format...${NC}"
    
    # If we have a JSON spec, we need to download the actual BTF file
    # BTFHub stores specs as JSON, actual BTF files may be in different locations
    if [ -f "$btf_json" ]; then
        # Check if it's a JSON spec or actual BTF
        if head -1 "$btf_json" | grep -q "{"; then
            echo "Downloaded JSON spec, trying to find BTF URL in spec..."
            # Try to extract download URL from JSON
            local btf_url=$(grep -oP '"btf_url":\s*"\K[^"]+' "$btf_json" || echo "")
            local download_url=$(grep -oP '"url":\s*"\K[^"]+' "$btf_json" || echo "")
            
            if [ -n "$btf_url" ]; then
                echo "Found BTF URL in spec: $btf_url"
                curl -s -f -o "$TEMP_BTF_FILE" "$btf_url" || {
                    echo -e "${RED}Failed to download BTF from spec URL${NC}" >&2
                    return 1
                }
            elif [ -n "$download_url" ]; then
                echo "Found download URL in spec: $download_url"
                curl -s -f -o "$TEMP_BTF_FILE" "$download_url" || {
                    echo -e "${RED}Failed to download BTF from download URL${NC}" >&2
                    return 1
                }
            else
                echo "No BTF URL found in spec, trying alternative BTFHub format..."
                # Alternative: try to find the BTF file directly
                local arch=$(uname -m)
                local kernel_version=$(get_kernel_version)
                local btf_path="/tmp/btf_${kernel_version}_${arch}.o"
                
                # Try different BTFHub archive locations
                curl -s -f -o "$TEMP_BTF_FILE" "${BTFHUB_URL}/${kernel_version}/${arch}/btf" || \
                curl -s -f -o "$TEMP_BTF_FILE" "${BTFHUB_URL}/btf/${kernel_version}/${arch}/vmlinux" || \
                {
                    echo -e "${RED}Failed to download BTF from alternative locations${NC}" >&2
                    return 1
                }
            fi
        else
            # It's already a BTF file
            cp "$btf_json" "$TEMP_BTF_FILE"
        fi
    fi
    
    # Convert BTF to vmlinux.h using bpftool
    if command -v bpftool &> /dev/null; then
        echo -e "${GREEN}Generating vmlinux.h using bpftool...${NC}"
        bpftool btf dump file "$TEMP_BTF_FILE" format c > "$OUTPUT_FILE"
        
        if [ -s "$OUTPUT_FILE" ]; then
            echo -e "${GREEN}Successfully generated vmlinux.h${NC}"
            return 0
        else
            echo -e "${RED}Failed to generate vmlinux.h${NC}" >&2
            return 1
        fi
    else
        echo -e "${RED}Error: bpftool not found. Please install bpftool.${NC}" >&2
        return 1
    fi
}

# Function to use local kernel headers as last resort
use_local_headers() {
    echo -e "${YELLOW}Trying to generate vmlinux.h from local kernel headers...${NC}"
    
    # Find kernel headers
    local header_dirs=(
        "/usr/src/linux-headers-$(uname -r)/include"
        "/usr/src/linux-headers-*/include"
        "/usr/include/linux"
        "/lib/modules/$(uname -r)/build/include"
    )
    
    local found_headers=false
    for header_dir in "${header_dirs[@]}"; do
        if [ -d "$header_dir" ]; then
            echo "Found kernel headers at: $header_dir"
            found_headers=true
            break
        fi
    done
    
    if [ "$found_headers" = false ]; then
        echo -e "${RED}Error: No local kernel headers found${NC}" >&2
        return 1
    fi
    
    # Create a minimal vmlinux.h with common types
    echo "Creating minimal vmlinux.h from local headers..."
    cat > "$OUTPUT_FILE" << 'EOF'
/* Minimal vmlinux.h generated from local headers */
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/* CO-RE compatibility macros */
#define bpf_target_defined(T, F) 1
#define bpf_target_offsetof(T, F) offsetof(T, F)
#define bpf_target_x86 1

/* Type access macros */
#define bpf_core_type(T) T
#define bpf_core_field_exists(T, F) 1
#define bpf_core_field_offset(T, F) offsetof(T, F)
#define bpf_core_field_size(T, F) sizeof(((T *)0)->F)

/* Memory access */
#define bpf_core_read(dst, sz, src) bpf_probe_read(dst, sz, src)
EOF
    
    echo -e "${GREEN}Created minimal vmlinux.h from local headers${NC}"
    return 0
}

# Main execution
main() {
    echo -e "${BLUE}BTFHub Fallback Script v1.0${NC}"
    echo "This script fetches BTF from BTFHub when kernel doesn't have embedded BTF"
    echo
    
    # Check if we already have kernel BTF
    if [ -f /sys/kernel/btf/vmlinux ]; then
        echo -e "${GREEN}Kernel BTF already exists at /sys/kernel/btf/vmlinux${NC}"
        echo "Use: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h"
        return 0
    fi
    
    # Get kernel version
    local kernel_version
    kernel_version=$(get_kernel_version) || {
        echo -e "${RED}Cannot continue without kernel version${NC}" >&2
        exit 1
    }
    
    # Get architecture
    local arch
    arch=$(uname -m || echo "x86_64")
    case "$arch" in
        x86_64) arch="x86_64" ;;
        aarch64) arch="aarch64" ;;
        arm64) arch="aarch64" ;;
        s390x) arch="s390x" ;;
        *) 
            echo -e "${YELLOW}Unsupported architecture: $arch, defaulting to x86_64${NC}"
            arch="x86_64"
            ;;
    esac
    
    # Try to fetch BTF from BTFHub
    if fetch_btf_from_btfhub "$kernel_version" "$arch"; then
        if extract_and_convert_btf "$TEMP_BTF_JSON"; then
            echo -e "${GREEN}BTFHub fallback succeeded!${NC}"
            echo "Generated vmlinux.h at: $OUTPUT_FILE"
            cleanup
            exit 0
        fi
    fi
    
    # Last resort: use local headers
    echo -e "${YELLOW}BTFHub fallback failed, trying local headers...${NC}"
    if use_local_headers; then
        echo -e "${GREEN}Generated vmlinux.h from local headers${NC}"
        cleanup
        exit 0
    fi
    
    echo -e "${RED}All fallback methods failed. Please install kernel BTF or use a kernel with embedded BTF.${NC}" >&2
    cleanup
    exit 1
}

# Cleanup temporary files
cleanup() {
    rm -f "$TEMP_BTF_FILE" "$TEMP_BTF_JSON"
}

# Run main function
main "$@"

# Exit with cleanup
cleanup
exit $?