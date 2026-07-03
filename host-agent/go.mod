module github.com/HasseJohansen/egress-domain-whitelist/host-agent

go 1.22

require (
	github.com/HasseJohansen/egress-domain-whitelist/config-server v0.0.0
	github.com/cilium/ebpf v0.11.0
	github.com/google/uuid v1.4.0
	golang.org/x/net v0.20.0
	golang.org/x/sys v0.15.0
)

// Replace the local module with the parent directory
replace github.com/HasseJohansen/egress-domain-whitelist/config-server => ../config-server
