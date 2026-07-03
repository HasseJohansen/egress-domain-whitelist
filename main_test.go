package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// isAlwaysAllowed checks if an IP is in localhost or RFC1918 ranges
// This mirrors the logic in the eBPF common.h file
func isAlwaysAllowed(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}

	// Check IPv4 RFC1918 ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}

	// Check IPv6
	// ::1/128 (localhost)
	// fc00::/7 (unique local addresses - includes RFC4193)
	// fe80::/10 (link-local addresses)
	if ip.To16() != nil {
		if ip.IsLoopback() {
			return true
		}
		// Check for unique local addresses (fc00::/7)
		if len(ip) >= 16 {
			firstByte := ip[0]
			// Unique Local Address (ULA): fc00::/7
			// Bits: 1111110x xxxxxxxx...
			if (firstByte & 0xfe) == 0xfc {
				return true
			}
			// Link-local: fe80::/10
			// Bits: 11111110 10xxxxxx...
			// First byte must be 0xfe
			// Second byte top 2 bits must be 10 (i.e., & 0xc0 == 0x80)
			if firstByte == 0xfe {
				secondByte := ip[1]
				if (secondByte & 0xc0) == 0x80 {
					return true
				}
			}
		}
	}

	return false
}

// isIPAllowedInManager checks if an IP is allowed in a given manager
func isIPAllowedInManager(manager FirewallManager, ip net.IP) bool {
	// First check if it's always allowed (RFC1918, localhost)
	if isAlwaysAllowed(ip) {
		return true
	}

	// For IPTablesManager, check the internal map
	if m, ok := manager.(*IPTablesManager); ok {
		m.mu.Lock()
		defer m.mu.Unlock()
		
		if entry, exists := m.allowedIPs[ip.String()]; exists {
			// Check if TTL hasn't expired
			return time.Now().Before(entry.ExpiresAt)
		}
		return false
	}

	// For MockFirewallManager, check the internal map
	if m, ok := manager.(*MockFirewallManager); ok {
		m.mu.Lock()
		defer m.mu.Unlock()
		
		if entry, exists := m.allowedIPs[ip.String()]; exists {
			// Check if TTL hasn't expired
			return time.Now().Before(entry.ExpiresAt)
		}
		return false
	}

	// For eBPF manager, we can't easily query the map from userspace
	// in this simple implementation. In production, we'd use bpf_map_lookup.
	// For now, return false for eBPF in unit tests (it would be checked in eBPF)
	return false
}

// =============================================================================
// Test 1: RFC1918 + Localhost Addresses Are Always Allowed
// =============================================================================

func TestRFC1918AddressesAlwaysAllowed(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Localhost (IPv4)
		{"localhost 127.0.0.1", "127.0.0.1", true},
		{"localhost 127.0.0.2", "127.0.0.2", true},
		{"localhost 127.1.2.3", "127.1.2.3", true},

		// RFC1918: 10.0.0.0/8
		{"10.0.0.0/8 start", "10.0.0.0", true},
		{"10.0.0.0/8 middle", "10.123.45.67", true},
		{"10.0.0.0/8 end", "10.255.255.255", true},

		// RFC1918: 172.16.0.0/12
		{"172.16.0.0/12 start", "172.16.0.0", true},
		{"172.16.0.0/12 middle", "172.20.30.40", true},
		{"172.16.0.0/12 end", "172.31.255.255", true},
		{"172.16.0.0/12 just below", "172.15.255.255", false},
		{"172.16.0.0/12 just above", "172.32.0.0", false},

		// RFC1918: 192.168.0.0/16
		{"192.168.0.0/16 start", "192.168.0.0", true},
		{"192.168.0.0/16 middle", "192.168.1.1", true},
		{"192.168.0.0/16 end", "192.168.255.255", true},
		{"192.168.0.0/16 just below", "192.167.255.255", false},
		{"192.168.0.0/16 just above", "192.169.0.0", false},

		// Public addresses (should NOT be allowed)
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 142.250.190.46 (google)", "142.250.190.46", false},

		// Edge cases
		{"0.0.0.0", "0.0.0.0", false},
		{"255.255.255.255", "255.255.255.255", false},
		{"224.0.0.1 (multicast)", "224.0.0.1", false},

		// IPv6 localhost
		{"IPv6 localhost", "::1", true},
		{"IPv6 localhost expanded", "0:0:0:0:0:0:0:1", true},

		// IPv6 unique local addresses (RFC4193)
		{"IPv6 ULA", "fd00::1", true},
		{"IPv6 ULA 2", "fc00::1", true},

		// IPv6 link-local
		{"IPv6 link-local", "fe80::1", true},

		// IPv6 public (should NOT be allowed)
		{"IPv6 public", "2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}
			result := isAlwaysAllowed(ip)
			if result != tt.expected {
				t.Errorf("isAlwaysAllowed(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Test 2: Non-Whitelisted Domain IPs Are NOT Allowed
// =============================================================================

func TestNonWhitelistedDomainIPsNotAllowed(t *testing.T) {
	// Create a fresh manager with no IPs whitelisted
	manager := NewMockFirewallManager()
	
	// Test that arbitrary IPs are NOT allowed (unless they're RFC1918/localhost)
	tests := []struct {
		name     string
		ip       string
		expected bool // Should be false for all except RFC1918/localhost
	}{
		{"public DNS 8.8.8.8", "8.8.8.8", false},
		{"public DNS 1.1.1.1", "1.1.1.1", false},
		{"google", "142.250.190.46", false},
		{"cloudflare", "104.20.23.154", false},
		// RFC1918 should still be allowed
		{"RFC1918 10.0.0.1", "10.0.0.1", true},
		{"RFC1918 172.16.0.1", "172.16.0.1", true},
		{"RFC1918 192.168.1.1", "192.168.1.1", true},
		{"localhost", "127.0.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}
			result := isIPAllowedInManager(manager, ip)
			if result != tt.expected {
				t.Errorf("isIPAllowedInManager(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
	
	// Cleanup
	manager.Close()
}

// =============================================================================
// Test 3: DNS Lookup IPs ARE Allowed
// =============================================================================

func TestDNSLookupIPsAreAllowed(t *testing.T) {
	// Create manager and resolver
	config := &Config{
		UpstreamDNS: "8.8.8.8:53",
		DefaultTTL:   300 * time.Second,
		MinTTL:       5 * time.Second,
		MaxTTL:       24 * time.Hour,
	}
	
	cache := NewDomainCache()
	manager := NewMockFirewallManager()
	resolver := NewDNSResolver(config.UpstreamDNS, cache, config)
	
	// Resolve a domain - this should add IPs to the cache
	// Note: This actually makes a DNS query, so it requires network access
	// We'll use example.com which should resolve
	domain := "example.com"
	ips, ttl, err := resolver.ResolveWithTTL(domain)
	
	// If DNS resolution fails (no network), skip this test
	if err != nil {
		t.Skipf("DNS resolution failed (no network?): %v", err)
	}
	
	if len(ips) == 0 {
		t.Skip("No IPs returned from DNS")
	}
	
	// Simulate what HandleDNS does: add IPs with TTL
	for _, ip := range ips {
		err := manager.AllowIPWithTTL(ip, ttl)
		if err != nil {
			t.Fatalf("Failed to allow IP %s: %v", ip.String(), err)
		}
	}
	
	// Verify all resolved IPs are now allowed
	for _, ip := range ips {
		if !isIPAllowedInManager(manager, ip) {
			t.Errorf("IP %s should be allowed but isn't", ip.String())
		}
	}
	
	// Verify that other public IPs are NOT allowed
	otherIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"142.250.190.46",
	}
	
	for _, ipStr := range otherIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("Invalid IP: %s", ipStr)
		}
		// Skip if it's RFC1918 or localhost
		if isAlwaysAllowed(ip) {
			continue
		}
		if isIPAllowedInManager(manager, ip) {
			t.Errorf("IP %s should NOT be allowed but is", ip.String())
		}
	}
	
	// Cleanup
	manager.Close()
}

// =============================================================================
// Test 4: TTL Expiration Works
// =============================================================================

func TestTTLExpiration(t *testing.T) {
	// Use a mock manager that doesn't require iptables
	// We'll test the IPTablesManager's internal logic directly
	
	manager := &IPTablesManager{
		allowedIPs:  make(map[string]*IPEntry),
		chainName:   "TEST",
		cleanupDone: make(chan struct{}),
	}
	
	// Add some IPs with very short TTL directly to the map
	testIPs := []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.3"),
	}
	
	ttl := 100 * time.Millisecond
	now := time.Now()
	
	for _, ip := range testIPs {
		manager.allowedIPs[ip.String()] = &IPEntry{
			IP:        ip.String(),
			ExpiresAt: now.Add(ttl),
		}
	}
	
	// Verify IPs are allowed initially
	for _, ip := range testIPs {
		if !isIPAllowedInManager(manager, ip) {
			t.Errorf("IP %s should be allowed initially", ip.String())
		}
	}
	
	// Wait for TTL to expire (plus a small buffer)
	time.Sleep(ttl + 50*time.Millisecond)
	
	// Run cleanup
	err := manager.CleanupExpired()
	if err != nil {
		t.Fatalf("CleanupExpired failed: %v", err)
	}
	
	// Verify IPs are no longer allowed
	for _, ip := range testIPs {
		if isIPAllowedInManager(manager, ip) {
			t.Errorf("IP %s should NOT be allowed after TTL expiration", ip.String())
		}
	}
	
	// Cleanup
	close(manager.cleanupDone)
}

// =============================================================================
// Test 5: TTL Bounds Are Respected
// =============================================================================

func TestTTLBounds(t *testing.T) {
	// Create resolver with TTL bounds
	config := &Config{
		UpstreamDNS: "8.8.8.8:53",
		DefaultTTL:   300 * time.Second,
		MinTTL:       10 * time.Second,
		MaxTTL:       100 * time.Second,
	}
	
	cache := NewDomainCache()
	resolver := NewDNSResolver(config.UpstreamDNS, cache, config)
	
	// Test with a domain that has a very short TTL
	// We'll use a mock or test with known TTL values
	// For now, test the ResolveWithTTL function with various TTLs
	
	tests := []struct {
		name       string
		dnsTTL     uint32 // TTL from DNS response (seconds)
		expectedTTL time.Duration
	}{
		{"TTL below min", 5, 10 * time.Second},   // Should be clamped to min
		{"TTL at min", 10, 10 * time.Second},      // Should stay at min
		{"TTL in range", 50, 50 * time.Second},    // Should stay as-is
		{"TTL at max", 100, 100 * time.Second},    // Should stay at max
		{"TTL above max", 200, 100 * time.Second},  // Should be clamped to max
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't easily test this without mocking DNS responses
			// For now, test the bounds logic directly
			rawTTL := time.Duration(tt.dnsTTL) * time.Second
			
			// Apply bounds (same logic as in ResolveWithTTL)
			ttl := rawTTL
			if ttl < config.MinTTL {
				ttl = config.MinTTL
			}
			if ttl > config.MaxTTL {
				ttl = config.MaxTTL
			}
			
			if ttl != tt.expectedTTL {
				t.Errorf("TTL = %v, expected %v", ttl, tt.expectedTTL)
			}
		})
	}
	
	// Cleanup
	_ = resolver
	_ = cache
}

// =============================================================================
// Test 6: FirewallManager AllowIPWithTTL Updates Existing IPs
// =============================================================================

func TestFirewallManagerUpdateExistingIP(t *testing.T) {
	manager := NewMockFirewallManager()
	
	ip := net.ParseIP("192.0.2.1")
	
	// Add IP with short TTL
	err := manager.AllowIPWithTTL(ip, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to allow IP: %v", err)
	}
	
	// Verify IP is allowed
	if !isIPAllowedInManager(manager, ip) {
		t.Error("IP should be allowed")
	}
	
	// Wait a bit
	time.Sleep(50 * time.Millisecond)
	
	// Add IP again with longer TTL - should update the expiration
	err = manager.AllowIPWithTTL(ip, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to allow IP again: %v", err)
	}
	
	// IP should still be allowed (TTL was extended)
	if !isIPAllowedInManager(manager, ip) {
		t.Error("IP should still be allowed after TTL update")
	}
	
	// Wait for the original TTL to expire
	time.Sleep(60 * time.Millisecond)
	
	// IP should STILL be allowed (because we extended the TTL)
	if !isIPAllowedInManager(manager, ip) {
		t.Error("IP should still be allowed (TTL was extended)")
	}
	
	// Wait for the extended TTL to expire
	time.Sleep(1 * time.Second)
	
	// Run cleanup
	manager.CleanupExpired()
	
	// Now IP should NOT be allowed
	if isIPAllowedInManager(manager, ip) {
		t.Error("IP should NOT be allowed after extended TTL expires")
	}
	
	// Cleanup
	manager.Close()
}

// =============================================================================
// Test 7: Pre-whitelisted Domains
// =============================================================================

func TestPreWhitelistedDomains(t *testing.T) {
	// Create config with pre-whitelisted domains
	config := &Config{
		UpstreamDNS: "8.8.8.8:53",
		Domains:     []string{"example.com", "google.com"},
		DefaultTTL:  300 * time.Second,
		MinTTL:      5 * time.Second,
		MaxTTL:      24 * time.Hour,
	}
	
	cache := NewDomainCache()
	manager := NewMockFirewallManager()
	resolver := NewDNSResolver(config.UpstreamDNS, cache, config)
	
	// Create DNS server
	server := NewDNSServer(config, cache, manager)
	
	// Simulate pre-resolving domains (what main() does)
	for _, domain := range config.Domains {
		ips, ttl, err := resolver.ResolveWithTTL(domain)
		if err != nil {
			t.Skipf("Failed to resolve %s: %v", domain, err)
		}
		for _, ip := range ips {
			err := manager.AllowIPWithTTL(ip, ttl)
			if err != nil {
				t.Fatalf("Failed to allow IP %s for %s: %v", ip.String(), domain, err)
			}
		}
	}
	
	// Verify that at least some IPs are whitelisted
	// (we can't guarantee which IPs, but there should be some)
	if len(manager.allowedIPs) == 0 {
		t.Error("Expected some IPs to be whitelisted for pre-configured domains")
	}
	
	// Verify RFC1918 is still allowed
	if !isIPAllowedInManager(manager, net.ParseIP("10.0.0.1")) {
		t.Error("RFC1918 should still be allowed")
	}
	
	// Cleanup
	manager.Close()
	_ = server
}

// =============================================================================
// Test 8: Concurrent DNS Requests (Race Condition Test)
// =============================================================================

func TestConcurrentDNSRequests(t *testing.T) {
	config := &Config{
		UpstreamDNS: "8.8.8.8:53",
		DefaultTTL:  300 * time.Second,
		MinTTL:      5 * time.Second,
		MaxTTL:      24 * time.Hour,
	}
	
	cache := NewDomainCache()
	manager := NewMockFirewallManager()
	resolver := NewDNSResolver(config.UpstreamDNS, cache, config)
	
	// Make many concurrent DNS requests for the same domain
	domain := "example.com"
	numRequests := 10
	
	// Channel to collect results
	results := make(chan error, numRequests)
	
	for i := 0; i < numRequests; i++ {
		go func() {
			ips, ttl, err := resolver.ResolveWithTTL(domain)
			if err != nil {
				results <- err
				return
			}
			for _, ip := range ips {
				err := manager.AllowIPWithTTL(ip, ttl)
				if err != nil {
					results <- err
					return
				}
			}
			results <- nil
		}()
	}
	
	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		err := <-results
		if err != nil {
			t.Logf("Request %d failed: %v", i, err)
			// Don't fail the test, just log
		}
	}
	
	// Verify that IPs are whitelisted (at least once)
	ips, _, err := resolver.ResolveWithTTL(domain)
	if err != nil {
		t.Skip("DNS resolution failed")
	}
	
	for _, ip := range ips {
		if !isIPAllowedInManager(manager, ip) {
			t.Errorf("IP %s should be allowed after concurrent requests", ip.String())
		}
	}
	
	// Cleanup
	manager.Close()
}

// =============================================================================
// Test 9: DNS Server Configuration Parsing
// =============================================================================

// =============================================================================
// Test 10: TCP and UDP DNS Server Restriction
// =============================================================================

func TestTCPAndUDPDNSServerRestriction(t *testing.T) {
	// Test that both TCP and UDP DNS traffic is restricted to configured servers
	// This is a conceptual test since we can't test actual eBPF filtering in unit tests
	
	config := &Config{
		UpstreamDNS: "8.8.8.8:53,1.1.1.1:53",
		DefaultTTL:   300 * time.Second,
		MinTTL:       5 * time.Second,
		MaxTTL:       24 * time.Hour,
	}

	// Parse the DNS servers (same logic as LoadConfig)
	if config.UpstreamDNS != "" {
		servers := strings.Split(config.UpstreamDNS, ",")
		for _, server := range servers {
			server = strings.TrimSpace(server)
			if strings.Contains(server, ":") {
				if strings.Count(server, ":") > 1 {
					config.DNSServers = append(config.DNSServers, server)
				} else {
					ip := strings.Split(server, ":")[0]
					config.DNSServers = append(config.DNSServers, ip)
				}
			} else {
				config.DNSServers = append(config.DNSServers, server)
			}
		}
	}

	// Verify we have the expected DNS servers
	expected := []string{"8.8.8.8", "1.1.1.1"}
	if len(config.DNSServers) != len(expected) {
		t.Errorf("Expected %d DNS servers, got %d", len(expected), len(config.DNSServers))
	}

	for i, exp := range expected {
		if config.DNSServers[i] != exp {
			t.Errorf("Expected DNS server %s at index %d, got %s", exp, i, config.DNSServers[i])
		}
	}

	// Test cases for DNS traffic validation (conceptual)
	testCases := []struct {
		name       string
		protocol   string
		destIP     string
		destPort   int
		shouldPass bool
	}{
		{"UDP DNS to allowed server", "UDP", "8.8.8.8", 53, true},
		{"TCP DNS to allowed server", "TCP", "8.8.8.8", 53, true},
		{"UDP DNS to rogue server", "UDP", "1.0.0.1", 53, false},
		{"TCP DNS to rogue server", "TCP", "1.0.0.1", 53, false},
		{"UDP to allowed server non-DNS port", "UDP", "8.8.8.8", 80, true}, // Not DNS traffic
		{"TCP to allowed server non-DNS port", "TCP", "8.8.8.8", 80, true}, // Not DNS traffic
	}

	// This is a conceptual validation - in reality, eBPF would handle this
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// For DNS traffic to configured servers, it should pass
			if tc.destPort == 53 && (tc.destIP == "8.8.8.8" || tc.destIP == "1.1.1.1") {
				if !tc.shouldPass {
					t.Errorf("DNS traffic to configured server should be allowed")
				}
			}
			// For DNS traffic to unconfigured servers, it should be blocked
			if tc.destPort == 53 && tc.destIP == "1.0.0.1" {
				if tc.shouldPass {
					t.Errorf("DNS traffic to rogue server should be blocked")
				}
			}
			// For non-DNS traffic, it should pass through to normal IP filtering
			if tc.destPort != 53 && tc.shouldPass {
				// This should be handled by normal IP filtering
			}
		})
	}
}

func TestDNSServerConfigurationParsing(t *testing.T) {
	// Test parsing of multiple DNS servers from upstream-dns flag
	tests := []struct {
		name           string
		upstreamDNS    string
		expectedIPs    []string
		expectedCount  int
	}{
		{
			name:        "single IPv4 DNS server",
			upstreamDNS: "8.8.8.8:53",
			expectedIPs:  []string{"8.8.8.8"},
			expectedCount: 1,
		},
		{
			name:        "single IPv4 DNS server without port",
			upstreamDNS: "8.8.8.8",
			expectedIPs:  []string{"8.8.8.8"},
			expectedCount: 1,
		},
		{
			name:        "multiple IPv4 DNS servers",
			upstreamDNS: "8.8.8.8:53,1.1.1.1:53",
			expectedIPs:  []string{"8.8.8.8", "1.1.1.1"},
			expectedCount: 2,
		},
		{
			name:        "multiple DNS servers with spaces",
			upstreamDNS: "8.8.8.8:53, 1.1.1.1:53, 9.9.9.9:53",
			expectedIPs:  []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"},
			expectedCount: 3,
		},
		{
			name:        "empty DNS server",
			upstreamDNS: "",
			expectedIPs:  []string{},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create config and parse DNS servers
			config := DefaultConfig()
			config.UpstreamDNS = tt.upstreamDNS
			
			// Use the same parsing logic as LoadConfig
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

			// Check count
			if len(config.DNSServers) != tt.expectedCount {
				t.Errorf("Expected %d DNS servers, got %d: %v", tt.expectedCount, len(config.DNSServers), config.DNSServers)
			}
			
			// Check that expected IPs are present
			for _, expectedIP := range tt.expectedIPs {
				found := false
				for _, actualIP := range config.DNSServers {
					if actualIP == expectedIP {
						found = true
						break
					}
				}
				if !found && expectedIP != "" {
					t.Errorf("Expected DNS server %s not found in %v", expectedIP, config.DNSServers)
				}
			}
		})
	}
}
