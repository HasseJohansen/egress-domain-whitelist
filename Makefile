.PHONY: all build clean run

# Build the eBPF program
BPF_SOURCE = bpf_program.c
BPF_OBJECT = bpf_program.o

# Go build
GO_BINARY = egress-domain-whitelist

all: build

build: $(GO_BINARY)

$(GO_BINARY): main.go bpf_program.c
	go build -o $(GO_BINARY) .

# Compile the eBPF program (requires clang and llvm)
$(BPF_OBJECT): $(BPF_SOURCE)
	clang -O2 -target bpf -c $(BPF_SOURCE) -o $(BPF_OBJECT)

clean:
	rm -f $(GO_BINARY) $(BPF_OBJECT)

run: build
	./$(GO_BINARY)

# Build with eBPF program compilation
build-ebpf: $(BPF_OBJECT) $(GO_BINARY)

.PHONY: build-ebpf
