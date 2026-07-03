// Package ebpf provides eBPF-based DNS egress control
package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Manager handles eBPF programs for DNS egress control
type Manager struct {
	collection    *ebpf.Collection
	programs     map[string]*ebpf.Program
	links        []link.Link
	maps         map[string]*ebpf.Map
	interfaceName string
	stopChan     chan struct{}
	closed       bool
	config       *Config
}

// Config for the eBPF manager
type Config struct {
	Interface    string
	ProgramsPath string
	DefaultTTL   time.Duration
	MinTTL       time.Duration
	MaxTTL       time.Duration
	DNSServers   []string // List of allowed DNS server IPs
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Interface:    "eth0",
		ProgramsPath: "./ebpf/compiled",
		DefaultTTL:   300 * time.Second,
		MinTTL:       5 * time.Second,
		MaxTTL:       24 * time.Hour,
	}
}

// NewManager creates a new eBPF manager
func NewManager(config *Config) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %v", err)
	}

	return &Manager{
		programs:     make(map[string]*ebpf.Program),
		maps:         make(map[string]*ebpf.Map),
		interfaceName: config.Interface,
		stopChan:     make(chan struct{}),
		closed:       false,
		config:       config,
	}, nil
}

// Setup loads and attaches eBPF programs
func (m *Manager) Setup() error {
	dnsInterceptPath := filepath.Join(m.config.ProgramsPath, "dns_intercept.o")
	connFilterPath := filepath.Join(m.config.ProgramsPath, "conn_filter.o")

	if _, err := os.Stat(dnsInterceptPath); os.IsNotExist(err) {
		return fmt.Errorf("DNS intercept program not found at %s", dnsInterceptPath)
	}
	if _, err := os.Stat(connFilterPath); os.IsNotExist(err) {
		return fmt.Errorf("Connection filter program not found at %s", connFilterPath)
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

	// Load connection filter collection
	connColl, err := ebpf.LoadCollection(connFilterPath)
	if err != nil {
		return fmt.Errorf("failed to load connection filter: %v", err)
	}

	for name, prog := range connColl.Programs {
		m.programs[name] = prog
	}
	for name, mapEntry := range connColl.Maps {
		m.maps[name] = mapEntry
	}

	m.collection = dnsColl

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
			return errors.New("no DNS program found")
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

	// Attach connection filter
	connProg := m.programs["xdp_filter"]
	if connProg == nil {
		connProg = m.programs["conn_filter"]
	}
	if connProg == nil {
		connProg = m.programs["socket_filter"]
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

	// Setup allowed DNS servers from configuration
	for _, dnsServer := range m.config.DNSServers {
		ip := net.ParseIP(dnsServer)
		if ip != nil {
			if err := m.AllowDNSServer(ip); err != nil {
				log.Printf("Warning: failed to allow DNS server %s: %v", dnsServer, err)
			}
		} else {
			log.Printf("Warning: invalid DNS server IP %s", dnsServer)
		}
	}

	return nil
}

// AllowIPWithTTL adds an IP to the whitelist with TTL
func (m *Manager) AllowIPWithTTL(ip net.IP, ttl time.Duration) error {
	if m.closed {
		return errors.New("manager is closed")
	}

	ipMap, ok := m.maps["ip_whitelist"]
	if !ok {
		return errors.New("ip_whitelist map not found")
	}

	// Convert IP to 128-bit format for the map
	var ipKey [2]uint64
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: store in lower 32 bits of ipKey[1]
		ipKey[0] = 0
		ipKey[1] = uint64(binary.BigEndian.Uint32(ip4))
	} else {
		// IPv6: split into high and low 64 bits
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
func (m *Manager) AllowIP(ip net.IP) error {
	return m.AllowIPWithTTL(ip, m.config.DefaultTTL)
}

// RemoveIP removes an IP from the whitelist
func (m *Manager) RemoveIP(ip net.IP) error {
	if m.closed {
		return errors.New("manager is closed")
	}

	ipMap, ok := m.maps["ip_whitelist"]
	if !ok {
		return errors.New("ip_whitelist map not found")
	}

	// Convert IP to 128-bit format for the map
	var ipKey [2]uint64
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: store in lower 32 bits of ipKey[1]
		ipKey[0] = 0
		ipKey[1] = uint64(binary.BigEndian.Uint32(ip4))
	} else {
		// IPv6: split into high and low 64 bits
		ip16 := ip.To16()
		ipKey[0] = binary.BigEndian.Uint64(ip16[0:8])
		ipKey[1] = binary.BigEndian.Uint64(ip16[8:16])
	}

	ipMap.Delete(ipKey)
	log.Printf("eBPF: Removed IP %s", ip.String())
	return nil
}

// Cleanup removes all eBPF programs and resources
func (m *Manager) Cleanup() error {
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
func (m *Manager) Close() error {
	return m.Cleanup()
}

// AllowDNSServer adds a DNS server IP to the allowed list
func (m *Manager) AllowDNSServer(ip net.IP) error {
	if m.closed {
		return errors.New("manager is closed")
	}

	dnsMap, ok := m.maps["allowed_dns_servers"]
	if !ok {
		return errors.New("allowed_dns_servers map not found")
	}

	// Convert IP to 128-bit format for the map
	var ipKey [2]uint64
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: store in lower 32 bits of ipKey[1]
		ipKey[0] = 0
		ipKey[1] = uint64(binary.BigEndian.Uint32(ip4))
	} else {
		// IPv6: split into high and low 64 bits
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

// RemoveDNSServer removes a DNS server IP from the allowed list
func (m *Manager) RemoveDNSServer(ip net.IP) error {
	if m.closed {
		return errors.New("manager is closed")
	}

	dnsMap, ok := m.maps["allowed_dns_servers"]
	if !ok {
		return errors.New("allowed_dns_servers map not found")
	}

	// Convert IP to 128-bit format for the map
	var ipKey [2]uint64
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: store in lower 32 bits of ipKey[1]
		ipKey[0] = 0
		ipKey[1] = uint64(binary.BigEndian.Uint32(ip4))
	} else {
		// IPv6: split into high and low 64 bits
		ip16 := ip.To16()
		ipKey[0] = binary.BigEndian.Uint64(ip16[0:8])
		ipKey[1] = binary.BigEndian.Uint64(ip16[8:16])
	}

	dnsMap.Delete(ipKey)
	log.Printf("eBPF: Removed DNS server %s", ip.String())
	return nil
}

// CleanupExpired is a no-op as eBPF handles expiration lazily
func (m *Manager) CleanupExpired() error {
	return nil
}
