package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/HasseJohansen/egress-domain-whitelist/ebpf"
	"github.com/miekg/dns"
)

// DNSRecord represents a DNS A record with TTL
type DNSRecord struct {
	IPs       []net.IP
	TTL       time.Duration
	ExpiresAt time.Time
}

// DomainCache stores DNS records with their TTL
type DomainCache struct {
	mu      sync.RWMutex
	records map[string]*DNSRecord
}

// NewDomainCache creates a new domain cache
func NewDomainCache() *DomainCache {
	cache := &DomainCache{
		records: make(map[string]*DNSRecord),
	}
	// Start cleanup goroutine
	go cache.cleanupLoop()
	return cache
}

// cleanupLoop removes expired records periodically
func (c *DomainCache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		for domain, record := range c.records {
			if time.Now().After(record.ExpiresAt) {
				delete(c.records, domain)
				log.Printf("Removed expired DNS record for %s", domain)
			}
		}
		c.mu.Unlock()
	}
}

// Get returns the DNS record for a domain if it exists and hasn't expired
func (c *DomainCache) Get(domain string) *DNSRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	record, exists := c.records[domain]
	if !exists {
		return nil
	}

	if time.Now().After(record.ExpiresAt) {
		return nil
	}

	return record
}

// Set stores a DNS record with its TTL
func (c *DomainCache) Set(domain string, ips []net.IP, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.records[domain] = &DNSRecord{
		IPs:       ips,
		TTL:       ttl,
		ExpiresAt: time.Now().Add(ttl),
	}
	log.Printf("Cached DNS record for %s: %v (TTL: %v)", domain, ips, ttl)
}

// AllowedIPs returns all currently allowed IPs from the cache
func (c *DomainCache) AllowedIPs() []net.IP {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var ips []net.IP
	for _, record := range c.records {
		if time.Now().Before(record.ExpiresAt) {
			ips = append(ips, record.IPs...)
		}
	}
	return ips
}

// DNSResolver handles DNS resolution
type DNSResolver struct {
	cache       *DomainCache
	upstreamDNS string
	client      *dns.Client
	config      *Config
}

// NewDNSResolver creates a new DNS resolver
func NewDNSResolver(upstreamDNS string, cache *DomainCache, config *Config) *DNSResolver {
	return &DNSResolver{
		cache:       cache,
		upstreamDNS: upstreamDNS,
		client:      new(dns.Client),
		config:      config,
	}
}

// Resolve resolves a domain and caches the result
func (r *DNSResolver) Resolve(domain string) ([]net.IP, error) {
	ips, _, err := r.ResolveWithTTL(domain)
	return ips, err
}

// ResolveWithTTL resolves a domain and returns IPs with their TTL
func (r *DNSResolver) ResolveWithTTL(domain string) ([]net.IP, time.Duration, error) {
	// Check cache first
	if record := r.cache.Get(domain); record != nil {
		log.Printf("Cache hit for %s, returning %v (TTL: %v)", domain, record.IPs, record.TTL)
		return record.IPs, record.TTL, nil
	}

	log.Printf("Cache miss for %s, resolving...", domain)

	// Perform DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	resp, _, err := r.client.Exchange(msg, r.upstreamDNS)
	if err != nil {
		return nil, 0, fmt.Errorf("DNS query failed: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("DNS query returned non-success code: %d", resp.Rcode)
	}

	var ips []net.IP
	var minTTL uint32 = 300 // Default TTL if not specified

	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ip := net.ParseIP(a.A.String())
			if ip != nil {
				ips = append(ips, ip)
			}
			if a.Hdr.Ttl < minTTL {
				minTTL = a.Hdr.Ttl
			}
		}
	}

	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("no A records found for %s", domain)
	}

	// Apply TTL bounds from configuration
	ttl := time.Duration(minTTL) * time.Second
	if r.config != nil {
		if ttl < r.config.MinTTL {
			ttl = r.config.MinTTL
		}
		if ttl > r.config.MaxTTL {
			ttl = r.config.MaxTTL
		}
	} else {
		// Use reasonable defaults if config is not set
		const defaultMinTTL = 5 * time.Second
		const defaultMaxTTL = 24 * time.Hour
		if ttl < defaultMinTTL {
			ttl = defaultMinTTL
		}
		if ttl > defaultMaxTTL {
			ttl = defaultMaxTTL
		}
	}

	// Cache the result
	r.cache.Set(domain, ips, ttl)

	log.Printf("Resolved %s -> %v (TTL: %v)", domain, ips, ttl)
	return ips, ttl, nil
}

// FirewallManager interface for different firewall implementations
type FirewallManager interface {
	Setup() error
	AllowIP(ip net.IP) error
	AllowIPWithTTL(ip net.IP, ttl time.Duration) error
	RemoveIP(ip net.IP) error
	Cleanup() error
	CleanupExpired() error
	Close() error
}

// IPEntry represents an IP with its expiration time
type IPEntry struct {
	IP        string
	ExpiresAt time.Time
}

// IPTablesManager manages iptables rules for IP whitelisting
type IPTablesManager struct {
	mu          sync.Mutex
	allowedIPs  map[string]*IPEntry
	chainName   string
	cleanupDone chan struct{}
}

// NewIPTablesManager creates a new iptables manager
func NewIPTablesManager() *IPTablesManager {
	m := &IPTablesManager{
		allowedIPs:  make(map[string]*IPEntry),
		chainName:   "EGRESS_WHITELIST",
		cleanupDone: make(chan struct{}),
	}
	// Start background cleanup goroutine
	go m.cleanupLoop()
	return m
}

// cleanupLoop periodically removes expired IPs
func (m *IPTablesManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.CleanupExpired(); err != nil {
				log.Printf("Error during cleanup: %v", err)
			}
		case <-m.cleanupDone:
			return
		}
	}
}

// Setup creates the iptables chain and rules
func (m *IPTablesManager) Setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create a custom chain (ignore error if it already exists)
	cmd := fmt.Sprintf("iptables -N %s 2>/dev/null || true", m.chainName)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("failed to create iptables chain: %v", err)
	}

	// Flush existing rules in the chain
	cmd = fmt.Sprintf("iptables -F %s", m.chainName)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("failed to flush iptables chain: %v", err)
	}

	// Insert rule at the beginning of OUTPUT chain
	cmd = fmt.Sprintf("iptables -I OUTPUT -j %s", m.chainName)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("failed to insert OUTPUT rule: %v", err)
	}

	// Set default policy to DROP in our chain
	cmd = fmt.Sprintf("iptables -A %s -j DROP", m.chainName)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("failed to set default DROP policy: %v", err)
	}

	log.Printf("IPTables chain %s created and configured", m.chainName)
	return nil
}

// AllowIP adds an IP to the allowed list with default TTL
func (m *IPTablesManager) AllowIP(ip net.IP) error {
	return m.AllowIPWithTTL(ip, 300*time.Second)
}

// RemoveIP removes an IP from the allowed list
func (m *IPTablesManager) RemoveIP(ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := ip.String()
	_, exists := m.allowedIPs[ipStr]
	if !exists {
		return nil // Not in the list
	}

	// Remove the rule
	cmd := fmt.Sprintf("iptables -D %s -d %s -j ACCEPT 2>/dev/null || true", m.chainName, ipStr)
	runCommand(cmd)

	delete(m.allowedIPs, ipStr)
	log.Printf("Removed IP: %s", ipStr)
	return nil
}

// AllowIPWithTTL adds an IP to the allowed list with TTL
func (m *IPTablesManager) AllowIPWithTTL(ip net.IP, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := ip.String()
	
	// If already exists, update TTL if new TTL extends expiration
	if entry, exists := m.allowedIPs[ipStr]; exists {
		newExpiresAt := time.Now().Add(ttl)
		if time.Now().Before(entry.ExpiresAt) && newExpiresAt.After(entry.ExpiresAt) {
			// Entry is still valid but new TTL extends it - update the iptables rule and expiration
			cmd := fmt.Sprintf("iptables -D %s -d %s -j ACCEPT 2>/dev/null || true", m.chainName, ipStr)
			runCommand(cmd)
			cmd = fmt.Sprintf("iptables -I %s -d %s -j ACCEPT", m.chainName, ipStr)
			if err := runCommand(cmd); err != nil {
				return fmt.Errorf("failed to update IP %s: %v", ipStr, err)
			}
			entry.ExpiresAt = newExpiresAt
			log.Printf("Updated IP TTL: %s (new expires at %s)", ipStr, entry.ExpiresAt.Format(time.RFC3339))
			return nil
		}
		if time.Now().Before(entry.ExpiresAt) {
			// Still valid and new TTL doesn't extend it, keep existing
			return nil
		}
		// Expired, remove old iptables rule first
		cmd := fmt.Sprintf("iptables -D %s -d %s -j ACCEPT 2>/dev/null || true", m.chainName, ipStr)
		runCommand(cmd)
	}

	// Add rule to allow this IP (insert at beginning to prioritize)
	cmd := fmt.Sprintf("iptables -I %s -d %s -j ACCEPT", m.chainName, ipStr)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("failed to allow IP %s: %v", ipStr, err)
	}

	// Store with expiration
	m.allowedIPs[ipStr] = &IPEntry{
		IP:        ipStr,
		ExpiresAt: time.Now().Add(ttl),
	}
	log.Printf("Allowed IP: %s (expires at %s)", ipStr, m.allowedIPs[ipStr].ExpiresAt.Format(time.RFC3339))
	return nil
}

// CleanupExpired removes expired IPs from iptables
func (m *IPTablesManager) CleanupExpired() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for ipStr, entry := range m.allowedIPs {
		if now.After(entry.ExpiresAt) {
			toRemove = append(toRemove, ipStr)
		}
	}

	// Remove expired IPs
	for _, ipStr := range toRemove {
		cmd := fmt.Sprintf("iptables -D %s -d %s -j ACCEPT 2>/dev/null || true", m.chainName, ipStr)
		runCommand(cmd)
		delete(m.allowedIPs, ipStr)
		log.Printf("Removed expired IP: %s", ipStr)
	}

	return nil
}

// Close signals the cleanup goroutine to stop
func (m *IPTablesManager) Close() error {
	close(m.cleanupDone)
	return nil
}

// Cleanup removes all rules and the chain
func (m *IPTablesManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove all IP rules
	for ipStr := range m.allowedIPs {
		cmd := fmt.Sprintf("iptables -D %s -d %s -j ACCEPT 2>/dev/null || true", m.chainName, ipStr)
		runCommand(cmd) // Ignore errors during cleanup
	}

	// Remove the chain from OUTPUT
	cmd := fmt.Sprintf("iptables -D OUTPUT -j %s 2>/dev/null || true", m.chainName)
	runCommand(cmd) // Ignore errors during cleanup

	// Flush and delete the chain
	cmd = fmt.Sprintf("iptables -F %s 2>/dev/null || true", m.chainName)
	runCommand(cmd)

	cmd = fmt.Sprintf("iptables -X %s 2>/dev/null || true", m.chainName)
	runCommand(cmd)

	log.Printf("IPTables cleanup completed")
	return nil
}

// runCommand executes a shell command
func runCommand(cmd string) error {
	log.Printf("Executing: %s", cmd)
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return nil
	}
	
	command := exec.Command(parts[0], parts[1:]...)
	output, err := command.CombinedOutput()
	if err != nil {
		log.Printf("Command failed: %s, output: %s", err, string(output))
		return err
	}
	return nil
}

// =============================================================================
// Mock Firewall Manager for Testing
// =============================================================================

// MockFirewallManager is a mock implementation for testing that doesn't require iptables
type MockFirewallManager struct {
	mu          sync.Mutex
	allowedIPs  map[string]*IPEntry
	cleanupDone chan struct{}
}

// NewMockFirewallManager creates a new mock firewall manager
func NewMockFirewallManager() *MockFirewallManager {
	return &MockFirewallManager{
		allowedIPs:  make(map[string]*IPEntry),
		cleanupDone: make(chan struct{}),
	}
}

// Setup is a no-op for mock
func (m *MockFirewallManager) Setup() error {
	return nil
}

// AllowIP adds an IP to the allowed list with default TTL
func (m *MockFirewallManager) AllowIP(ip net.IP) error {
	return m.AllowIPWithTTL(ip, 300*time.Second)
}

// AllowIPWithTTL adds an IP to the allowed list with TTL
func (m *MockFirewallManager) AllowIPWithTTL(ip net.IP, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := ip.String()
	
	// If already exists, update TTL if new TTL extends expiration
	if entry, exists := m.allowedIPs[ipStr]; exists {
		newExpiresAt := time.Now().Add(ttl)
		if time.Now().Before(entry.ExpiresAt) && newExpiresAt.After(entry.ExpiresAt) {
			// Entry is still valid but new TTL extends it - update expiration
			entry.ExpiresAt = newExpiresAt
			log.Printf("Mock: Updated IP TTL: %s (new expires at %s)", ipStr, entry.ExpiresAt.Format(time.RFC3339))
			return nil
		}
		if time.Now().Before(entry.ExpiresAt) {
			// Still valid and new TTL doesn't extend it, keep existing
			return nil
		}
		// Expired, remove old entry first
		delete(m.allowedIPs, ipStr)
	}

	// Store with expiration
	m.allowedIPs[ipStr] = &IPEntry{
		IP:        ipStr,
		ExpiresAt: time.Now().Add(ttl),
	}
	log.Printf("Mock: Allowed IP: %s (expires at %s)", ipStr, m.allowedIPs[ipStr].ExpiresAt.Format(time.RFC3339))
	return nil
}

// RemoveIP removes an IP from the allowed list
func (m *MockFirewallManager) RemoveIP(ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := ip.String()
	delete(m.allowedIPs, ipStr)
	log.Printf("Mock: Removed IP: %s", ipStr)
	return nil
}

// Cleanup removes all rules (no-op for mock)
func (m *MockFirewallManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.allowedIPs = make(map[string]*IPEntry)
	log.Printf("Mock: Cleanup completed")
	return nil
}

// CleanupExpired removes expired IPs
func (m *MockFirewallManager) CleanupExpired() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for ipStr, entry := range m.allowedIPs {
		if now.After(entry.ExpiresAt) {
			toRemove = append(toRemove, ipStr)
		}
	}

	// Remove expired IPs
	for _, ipStr := range toRemove {
		delete(m.allowedIPs, ipStr)
		log.Printf("Mock: Removed expired IP: %s", ipStr)
	}

	return nil
}

// Close signals the cleanup goroutine to stop
func (m *MockFirewallManager) Close() error {
	close(m.cleanupDone)
	return nil
}

// Config holds the application configuration
type Config struct {
	Interface        string
	UpstreamDNS      string // Keep for backward compatibility
	Domains          []string
	Port             int
	RefreshInterval  time.Duration
	UseIPTables      bool
	UseEBPF         bool
	// TTL configuration
	DefaultTTL time.Duration // Default TTL when DNS doesn't specify
	MinTTL     time.Duration // Minimum TTL to use
	MaxTTL     time.Duration // Maximum TTL to use
	// DNS Server restriction
	DNSServers []string // List of allowed DNS server IPs (extracted from UpstreamDNS)
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Interface:        "eth0",
		UpstreamDNS:      "8.8.8.8:53",
		Domains:          []string{},
		Port:             53,
		RefreshInterval:  300 * time.Second,
		UseIPTables:      false, // Prefer eBPF
		UseEBPF:         true,
		DefaultTTL:       300 * time.Second,
		MinTTL:           5 * time.Second,
		MaxTTL:           24 * time.Hour,
	}
}

// LoadConfig loads configuration from command line flags
func LoadConfig() *Config {
	config := DefaultConfig()

	flag.StringVar(&config.Interface, "interface", config.Interface, "Network interface to monitor")
	flag.StringVar(&config.UpstreamDNS, "upstream-dns", config.UpstreamDNS, "Upstream DNS server(s), comma-separated")
	flag.IntVar(&config.Port, "port", config.Port, "DNS server port")
	flag.DurationVar(&config.RefreshInterval, "refresh-interval", config.RefreshInterval, "DNS refresh interval")
	flag.BoolVar(&config.UseIPTables, "use-iptables", config.UseIPTables, "Use iptables for filtering")
	flag.BoolVar(&config.UseEBPF, "use-ebpf", config.UseEBPF, "Use eBPF for filtering")
	flag.DurationVar(&config.DefaultTTL, "default-ttl", config.DefaultTTL, "Default TTL for allowed IPs")
	flag.DurationVar(&config.MinTTL, "min-ttl", config.MinTTL, "Minimum TTL to use")
	flag.DurationVar(&config.MaxTTL, "max-ttl", config.MaxTTL, "Maximum TTL to use")

	domains := flag.String("domains", "", "Comma-separated list of domains to pre-whitelist")
	flag.Parse()

	if *domains != "" {
		config.Domains = strings.Split(*domains, ",")
	}

	// Parse upstream DNS servers (comma-separated) and extract IPs
	if config.UpstreamDNS != "" {
		servers := strings.Split(config.UpstreamDNS, ",")
		for _, server := range servers {
			server = strings.TrimSpace(server)
			// Remove port if present (format: ip:port)
			if strings.Contains(server, ":") {
				// Check if this is IPv6 (has multiple colons) or IPv4 with port
				if strings.Count(server, ":") > 1 {
					// IPv6 - use as is
					config.DNSServers = append(config.DNSServers, server)
				} else {
					// IPv4:port - extract just the IP
					ip := strings.Split(server, ":")[0]
					config.DNSServers = append(config.DNSServers, ip)
				}
			} else {
				// Just an IP
				config.DNSServers = append(config.DNSServers, server)
			}
		}
	}

	return config
}

// DNSServer handles incoming DNS queries
type DNSServer struct {
	resolver *DNSResolver
	config   *Config
	cache    *DomainCache
	manager  FirewallManager
}

// NewDNSServer creates a new DNS server
func NewDNSServer(config *Config, cache *DomainCache, manager FirewallManager) *DNSServer {
	return &DNSServer{
		resolver: NewDNSResolver(config.UpstreamDNS, cache, config),
		config:   config,
		cache:    cache,
		manager:  manager,
	}
}

// HandleDNS handles incoming DNS queries
func (s *DNSServer) HandleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)

	if len(r.Question) == 0 {
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	if question.Qtype != dns.TypeA {
		// Only handle A records for now
		msg.Rcode = dns.RcodeNotImplemented
		w.WriteMsg(msg)
		return
	}

	// Resolve the domain with TTL
	domain := strings.TrimSuffix(question.Name, ".")
	ips, ttl, err := s.resolver.ResolveWithTTL(domain)
	if err != nil {
		log.Printf("Failed to resolve %s: %v", domain, err)
		msg.Rcode = dns.RcodeServerFailure
		w.WriteMsg(msg)
		return
	}

	// Add the resolved IPs to the allowed list with TTL
	for _, ip := range ips {
		if err := s.manager.AllowIPWithTTL(ip, ttl); err != nil {
			log.Printf("Failed to allow IP %s: %v", ip.String(), err)
		}
	}

	// Create the response
	for _, ip := range ips {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(ttl.Seconds()),
			},
			A: ip,
		})
	}

	w.WriteMsg(msg)
}

// Start starts the DNS server
func (s *DNSServer) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.HandleDNS)

	// Start the DNS server
	server := &dns.Server{
		Addr:    fmt.Sprintf(":%d", s.config.Port),
		Net:     "udp",
		Handler: mux,
	}

	log.Printf("Starting DNS server on port %d", s.config.Port)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
	}()

	return nil
}

// DomainMonitor monitors domains and keeps their IPs allowed
func (s *DNSServer) DomainMonitor() {
	ticker := time.NewTicker(s.config.RefreshInterval)
	defer ticker.Stop()

	for range ticker.C {
		for _, domain := range s.config.Domains {
			// Resolve the domain to refresh the cache and rules
			ips, ttl, err := s.resolver.ResolveWithTTL(domain)
			if err != nil {
				log.Printf("Failed to refresh domain %s: %v", domain, err)
				continue
			}

			// Update the rules with TTL
			for _, ip := range ips {
				if err := s.manager.AllowIPWithTTL(ip, ttl); err != nil {
					log.Printf("Failed to allow IP %s for domain %s: %v", ip.String(), domain, err)
				}
			}
		}
	}
}

// CleanupExpiredIPs periodically removes expired IPs from the firewall rules
func (s *DNSServer) CleanupExpiredIPs() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Get all currently allowed IPs from cache
		currentIPs := s.cache.AllowedIPs()
		currentIPSet := make(map[string]bool)
		for _, ip := range currentIPs {
			currentIPSet[ip.String()] = true
		}

		log.Printf("Cleanup: %d IPs currently allowed", len(currentIPs))
		
		// In a real implementation, we would compare with existing rules
		// and remove any that are no longer in the cache
	}
}

func main() {
	// Load configuration
	config := LoadConfig()

	log.Printf("Starting DNS Egress Control with configuration:")
	log.Printf("  Interface: %s", config.Interface)
	log.Printf("  Upstream DNS: %s", config.UpstreamDNS)
	log.Printf("  Port: %d", config.Port)
	log.Printf("  Domains: %v", config.Domains)
	log.Printf("  Use iptables: %v", config.UseIPTables)
	log.Printf("  Use eBPF: %v", config.UseEBPF)

	// Create domain cache
	cache := NewDomainCache()

	// Create firewall manager
	var manager FirewallManager
	var managerCleanup func() error
	
	if config.UseEBPF {
		// Try to create eBPF manager
		ebpfConfig := &ebpf.Config{
			Interface:    config.Interface,
			ProgramsPath: "./ebpf/compiled",
			DefaultTTL:   config.DefaultTTL,
			MinTTL:       config.MinTTL,
			MaxTTL:       config.MaxTTL,
			DNSServers:   config.DNSServers,
		}
		
		// Check if eBPF programs exist
		if _, err := os.Stat(filepath.Join(ebpfConfig.ProgramsPath, "dns_intercept.o")); err == nil {
			mgr, err := ebpf.NewManager(ebpfConfig)
			if err != nil {
				log.Printf("Warning: Failed to create eBPF manager: %v, falling back to iptables", err)
				manager = NewIPTablesManager()
				managerCleanup = func() error { return manager.Cleanup() }
			} else {
				if err := mgr.Setup(); err != nil {
					log.Printf("Warning: Failed to setup eBPF programs: %v, falling back to iptables", err)
					mgr.Close()
					manager = NewIPTablesManager()
					managerCleanup = func() error { return manager.Cleanup() }
				} else {
					manager = mgr
					managerCleanup = func() error { return mgr.Cleanup() }
					log.Printf("Using eBPF for DNS egress control on interface %s", config.Interface)
				}
			}
		} else {
			log.Printf("eBPF programs not found at %s, falling back to iptables", ebpfConfig.ProgramsPath)
			manager = NewIPTablesManager()
			managerCleanup = func() error { return manager.Cleanup() }
		}
	} else {
		manager = NewIPTablesManager()
		managerCleanup = func() error { return manager.Cleanup() }
	}

	if err := manager.Setup(); err != nil {
		log.Printf("Warning: Failed to setup firewall: %v", err)
		log.Printf("Running in DNS-only mode (no traffic filtering)")
	}
	defer func() {
		if managerCleanup != nil {
			managerCleanup()
		}
	}()

	// Create DNS server
	server := NewDNSServer(config, cache, manager)

	// Start DNS server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}

	// Start domain monitor
	go server.DomainMonitor()

	// Start cleanup goroutine
	go server.CleanupExpiredIPs()

	// Pre-resolve configured domains
	for _, domain := range config.Domains {
		ips, ttl, err := server.resolver.ResolveWithTTL(domain)
		if err != nil {
			log.Printf("Failed to pre-resolve domain %s: %v", domain, err)
			continue
		}
		for _, ip := range ips {
			if err := manager.AllowIPWithTTL(ip, ttl); err != nil {
				log.Printf("Failed to allow IP %s for domain %s: %v", ip.String(), domain, err)
			}
		}
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
}
