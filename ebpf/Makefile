# eBPF Makefile
# Builds eBPF programs for DNS Egress Control with CO-RE support

# Compiler settings
CLANG ?= clang
CFLAGS ?= -Wall -Wextra -O2 -target bpf

# Architecture detection
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
	TARGET_ARCH := arm64
else ifeq ($(ARCH),arm64)
	TARGET_ARCH := arm64
else
	TARGET_ARCH := x86
endif

# CO-RE specific settings
CORE_CFLAGS := -D__TARGET_ARCH_$(TARGET_ARCH) -D__BPF_TRACING__

# Include paths - use vmlinux.h for CO-RE instead of direct kernel headers
# Add standard kernel header paths for multiple architectures
# Detect architecture and add appropriate include paths
ARCH_DIR := $(shell uname -m)
ifeq ($(ARCH_DIR),x86_64)
    ARCH_INCLUDES := -I/usr/include/linux -I/usr/src/linux-headers-generic/include -I/usr/include/x86_64-linux-gnu
else ifeq ($(ARCH_DIR),aarch64)
    ARCH_INCLUDES := -I/usr/include/linux -I/usr/src/linux-headers-generic/include -I/usr/include/aarch64-linux-gnu -I/usr/include/asm-generic
else
    ARCH_INCLUDES := -I/usr/include/linux -I/usr/src/linux-headers-generic/include
endif

INCLUDES := -I. -I./include -I../include $(ARCH_INCLUDES) $(CORE_CFLAGS)

# Source files
SRCS := src/dns_intercept.c src/conn_filter.c
OBJS := $(patsubst src/%.c,compiled/%.o,$(SRCS))

# Output directory
OUT_DIR ?= compiled

# vmlinux.h file (generated from BTF)
VMLINUX_H := vmlinux.h

all: $(OBJS)

# vmlinux.h can be generated separately
vmlinux.h: $(VMLINUX_H)

# Generate vmlinux.h from kernel BTF or BTFHub fallback
$(VMLINUX_H):
	@echo "Generating vmlinux.h from kernel BTF..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		 echo "Using kernel BTF from /sys/kernel/btf/vmlinux"; \
		 bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		 echo "No kernel BTF found, trying BTFHub fallback..."; \
		 ./scripts/fetch_btf.sh; \
	fi
	@if [ ! -s $@ ]; then \
		 echo "Failed to generate vmlinux.h, will use direct kernel headers"; \
		 touch $@; \
		 echo "/* Fallback vmlinux.h - using direct kernel headers */" > $@; \
	fi

# Compile each eBPF program with CO-RE support
compiled/%.o: src/%.c
	mkdir -p $(OUT_DIR)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean
clean:
	rm -rf $(OUT_DIR) $(VMLINUX_H)

# Check if BTF is available
check_btf:
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		 echo "Kernel BTF available"; \
	else \
		 echo "No kernel BTF found"; \
	fi

# Force rebuild
rebuild: clean all

.PHONY: all clean check_btf rebuild
