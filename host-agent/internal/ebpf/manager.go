// Package ebpf provides eBPF management for the host agent
package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/config"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// HostAgentEBPFManager manages eBPF programs for the host agent
type HostAgentEBPFManager struct {
	collection    *ebpf.Collection
	programs     map[string]*ebpf.Program
	links        []link.Link
	maps         map[string]*ebpf.Map
	interfaceName string
	stopChan     chan struct{}
	closed       bool
	currentConfig *config.LocalEgressConfig
}

// NewHostAgentEBPFManager creates a new eBPF manager for the host agent
func NewHostAgentEBPFManager(hostConfig *config.HostAgentConfig) (*HostAgentEBPFManager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %v", err)
	}

	interfaceName := "eth0"
	if hostConfig.LocalConfig != nil && hostConfig.LocalConfig.Interface != "" {
		interfaceName = hostConfig.LocalConfig.Interface
	}

	return &HostAgentEBPFManager{
		programs:     make(map[string]*ebpf.Program),
		maps:         make(map[string]*ebpf.Map),
		interfaceName: interfaceName,
		stopChan:     make(chan struct{}),
		closed:       false,
	}, nil
}

// Setup loads and attaches eBPF programs
func (m *HostAgentEBPFManager) Setup() error {
	// Get the path to eBPF programs
	programsPath := "./ebpf/compiled"
	
	dnsInterceptPath := filepath.Join(programsPath, "dns_intercept.o")
	connFilterPath := filepath.Join(programsPath, "conn_filter.o")

	// Check if programs exist
	if _, err := filepath.Glob(dnsInterceptPath); err != nil {
		return fmt.Errorf("DNS intercept program not found at %s: %v", dnsInterceptPath, err)
	}
	if _, err := filepath.Glob(connFilterPath); err != nil {
		log.Printf("Warning: connection filter program not found at %s", connFilterPath)
		// Continue without connection filter
	}

	// Load DNS intercept collection
	dnsColl, err := ebpf.LoadCollection(dnsInterceptPath)
	if err != nil {
		return fmt.Errorf("failed to load DNS intercept: %v", err)
	}

	// Store programs and maps
	for name, prog := range dnsColl.Programs {
		m.programs[name] = prog
	}
	for name, mapEntry := range dnsColl.Maps {
		m.maps[name] = mapEntry
	}

	// Load connection filter collection if available
	if connProgPath, err := filepath.Glob(connFilterPath); err == nil && len(connProgPath) > 0 {
		connColl, err := ebpf.LoadCollection(connProgPath[0])
		if err != nil {
			log.Printf("Warning: failed to load connection filter: %v", err)
		} else {
			for name, prog := range connColl.Programs {
				m.programs[name] = prog
			}
			for name, mapEntry := range connColl.Maps {
				m.maps[name] = mapEntry
			}
			m.collection = connColl
		}
	} else {
		m.collection = dnsColl
	}

	// Get network interface
	iface, err := net.InterfaceByName(m.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", m.interfaceName, err)
	}

	// Attach DNS intercept program (XDP)
	dnsProg := m.programs["xdp_dns"]
	if dnsProg == nil {
		// Try to find any program
		for _, prog := range m.programs {
			dnsProg = prog
			break
		}
		if dnsProg == nil {
			return fmt.Errorf("no DNS program found")
		}
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   dnsProg,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP: %v", err)
	}
	m.links = append(m.links, xdpLink)
	log.Printf("Attached DNS intercept to %s", m.interfaceName)

	// Attach connection filter if available
	connProg := m.programs["xdp_filter"]
	if connProg == nil {
		connProg = m.programs["conn_filter"]
	}
	if connProg != nil && connProg != dnsProg {
		connXDPLink, err := link.AttachXDP(link.XDPOptions{
			Program:   connProg,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Printf("Warning: failed to attach connection filter: %v", err)
		} else {
			m.links = append(m.links, connXDPLink)
			log.Printf("Attached connection filter to %s", m.interfaceName)
		}
	}

	return nil
}

// ApplyConfig applies a configuration to the eBPF maps
func (m *HostAgentEBPFManager) ApplyConfig(cfg *config.LocalEgressConfig) error {
	m.currentConfig = cfg
	
	// Setup allowed DNS servers
	for _, dnsServer := range cfg.AllowedDNSServers {
		ip := parseIPFromServer(dnsServer)
		if ip != nil {
			if err := m.AllowDNSServer(ip); err != nil {
				log.Printf("Warning: failed to allow DNS server %s: %v", dnsServer, err)
			}
		} else {
			log.Printf("Warning: invalid DNS server %s", dnsServer)
		}
	}

	log.Printf("eBPF configuration applied successfully")
	return nil
}

// parseIPFromServer parses an IP address from a server string (ip:port format)
func parseIPFromServer(server string) net.IP {
	// Try to parse as IP first
	if ip := net.ParseIP(server); ip != nil {
		return ip
	}
	
	// Try to split by colon (IPv4:port)
	if strings.Contains(server, ":") {
		// Check if it's IPv6 (multiple colons) or IPv4 with port
		if strings.Count(server, ":") > 1 {
			// IPv6 - try to parse directly
			return net.ParseIP(server)
		} else {
			// IPv4:port
			parts := strings.Split(server, ":")
			return net.ParseIP(parts[0])
		}
	}
	
	return nil
}

// AllowIPWithTTL adds an IP to the whitelist with TTL
func (m *HostAgentEBPFManager) AllowIPWithTTL(ip net.IP, ttl time.Duration) error {
	if m.closed {
		return fmt.Errorf("manager is closed")
	}

	ipMap, ok := m.maps["ip_whitelist"]
	if !ok {
		return fmt.Errorf("ip_whitelist map not found")
	}

	// Convert IP to map key format
	var ipKey [2]uint64
	if ip4 := ip.To4(); ip4 != nil {
		ipKey[0] = 0
		ipKey[1] = uint64(binary.BigEndian.Uint32(ip4))
	} else {
		ip16 := ip.To16()
		ipKey[0] = binary.BigEndian.Uint64(ip16[0:8])
		ipKey[1] = binary.BigEndian.Uint64(ip16[8:16])
	}

	now := time.Now().UnixNano()
	expiresAt := now + ttl.Nanoseconds()

	entry := struct {
		ExpiresAt uint64
	}{
		ExpiresAt: uint64(expiresAt),
	}

	if err := ipMap.Put(ipKey, entry); err != nil {
		return fmt.Errorf("failed to store IP in map: %v", err)
	}

	log.Printf("eBPF: Allowed IP %s with TTL %v", ip.String(), ttl)
	return nil
}

// AllowIP adds an IP with default TTL
func (m *HostAgentEBPFManager) AllowIP(ip net.IP) error {
	defaultTTL := 300 * time.Second
	if m.currentConfig != nil && m.currentConfig.DefaultTTL > 0 {
		defaultTTL = time.Duration(m.currentConfig.DefaultTTL) * time.Second
	}
	return m.AllowIPWithTTL(ip, defaultTTL)
}

// RemoveIP removes an IP from the whitelist
func (m *HostAgentEBPFManager) RemoveIP(ip net.IP) error {
	if m.closed {
		return fmt.Errorf("manager is closed")
	}

	ipMap, ok := m.maps["ip_whitelist"]
	if !ok {
		return fmt.Errorf("ip_whitelist map not found")
	}

	// Convert IP to map key format
	var ipKey [2]uint64
	if ip4 := ip.To4(); ip4 != nil {
		ipKey[0] = 0
		ipKey[1] = uint64(binary.BigEndian.Uint32(ip4))
	} else {
		ip16 := ip.To16()
		ipKey[0] = binary.BigEndian.Uint64(ip16[0:8])
		ipKey[1] = binary.BigEndian.Uint64(ip16[8:16])
	}

	ipMap.Delete(ipKey)
	log.Printf("eBPF: Removed IP %s", ip.String())
	return nil
}

// AllowDNSServer adds a DNS server IP to the allowed list
func (m *HostAgentEBPFManager) AllowDNSServer(ip net.IP) error {
	if m.closed {
		return fmt.Errorf("manager is closed")
	}

	dnsMap, ok := m.maps["allowed_dns_servers"]
	if !ok {
		return fmt.Errorf("allowed_dns_servers map not found")
	}

	// Convert IP to map key format
	var ipKey [2]uint64
	if ip4 := ip.To4(); ip4 != nil {
		ipKey[0] = 0
		ipKey[1] = uint64(binary.BigEndian.Uint32(ip4))
	} else {
		ip16 := ip.To16()
		ipKey[0] = binary.BigEndian.Uint64(ip16[0:8])
		ipKey[1] = binary.BigEndian.Uint64(ip16[8:16])
	}

	// Value is just 1 (allowed)
	var allowed uint8 = 1
	
	if err := dnsMap.Put(ipKey, allowed); err != nil {
		return fmt.Errorf("failed to store DNS server in map: %v", err)
	}

	log.Printf("eBPF: Allowed DNS server %s", ip.String())
	return nil
}

// Cleanup removes all eBPF programs and resources
func (m *HostAgentEBPFManager) Cleanup() error {
	if m.closed {
		return nil
	}

	m.closed = true
	close(m.stopChan)

	for _, link := range m.links {
		link.Close()
	}
	m.links = nil

	if m.collection != nil {
		m.collection.Close()
		m.collection = nil
	}

	log.Printf("eBPF manager cleanup completed")
	return nil
}

// Close is an alias for Cleanup
func (m *HostAgentEBPFManager) Close() error {
	return m.Cleanup()
}
