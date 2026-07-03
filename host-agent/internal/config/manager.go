// Package config provides configuration management for the host agent
package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LocalEgressConfig holds the local egress filter configuration
type LocalEgressConfig struct {
	AllowedDNSServers   []string `yaml:"allowed_dns_resolvers" json:"allowed_dns_resolvers"`
	WhitelistedDomains   []string `yaml:"whitelisted_domains" json:"whitelisted_domains"`
	BlacklistedDomains   []string `yaml:"blacklisted_domains" json:"blacklisted_domains"`
	DefaultTTL          int      `yaml:"default_ttl" json:"default_ttl"` // seconds
	MaxTTL              int      `yaml:"max_ttl" json:"max_ttl"`         // seconds
	MinTTL              int      `yaml:"min_ttl" json:"min_ttl"`         // seconds
	RefreshInterval     int      `yaml:"refresh_interval" json:"refresh_interval"` // seconds
	RestrictToAllowedDNS bool    `yaml:"restrict_to_allowed_dns" json:"restrict_to_allowed_dns"`
	Interface          string    `yaml:"interface" json:"interface"`
	UseEBPF           bool      `yaml:"use_ebpf" json:"use_ebpf"`
	UseIPTables       bool      `yaml:"use_iptables" json:"use_iptables"`
}

// ConfigManager manages the egress filter configuration
type ConfigManager struct {
	mu              sync.RWMutex
	currentConfig   *LocalEgressConfig
	configPath     string
	configSource   string // "local" or "server"
	onConfigChange func(*LocalEgressConfig) error
	lastUpdated    time.Time
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(configPath string, onConfigChange func(*LocalEgressConfig) error) (*ConfigManager, error) {
	cm := &ConfigManager{
		configPath:     configPath,
		configSource:   "local",
		onConfigChange: onConfigChange,
		lastUpdated:    time.Now(),
	}

	// Load initial configuration
	if err := cm.loadLocalConfig(); err != nil {
		log.Printf("Warning: failed to load local config: %v", err)
		// Continue with default config
		cm.currentConfig = &LocalEgressConfig{
			AllowedDNSServers: []string{"8.8.8.8:53", "1.1.1.1:53"},
			DefaultTTL:        300,
			MaxTTL:            86400,
			MinTTL:            5,
			RefreshInterval:   300,
			RestrictToAllowedDNS: true,
			Interface:        "eth0",
			UseEBPF:         true,
			UseIPTables:     false,
		}
	} else {
		log.Printf("Loaded initial configuration from %s", configPath)
	}

	return cm, nil
}

// loadLocalConfig loads configuration from file
func (cm *ConfigManager) loadLocalConfig() error {
	if cm.configPath == "" {
		return fmt.Errorf("config path not set")
	}

	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return err
	}

	var config LocalEgressConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	cm.mu.Lock()
	cm.currentConfig = &config
	cm.configSource = "local"
	cm.mu.Unlock()

	return nil
}

// GetCurrentConfig returns the current configuration
func (cm *ConfigManager) GetCurrentConfig() *LocalEgressConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.currentConfig == nil {
		return nil
	}
	
	// Return a copy
	return cm.currentConfig.DeepCopy()
}

// GetConfigSource returns the source of the current configuration
func (cm *ConfigManager) GetConfigSource() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.configSource
}

// SetConfig sets a new configuration from the server
func (cm *ConfigManager) SetConfig(config *LocalEgressConfig, source string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if configuration actually changed
	if cm.configsEqual(cm.currentConfig, config) {
		log.Printf("Configuration received but not changed")
		return nil
	}

	// Update configuration
	oldConfig := cm.currentConfig
	cm.currentConfig = config
	cm.configSource = source
	cm.lastUpdated = time.Now()

	// Log the change
	log.Printf("Configuration updated from %s at %s", source, cm.lastUpdated.Format(time.RFC3339))
	log.Printf("  Previous source: %s", source)
	
	// Log detailed changes
	if oldConfig != nil {
		log.Printf("  Changes detected:")
		if !cm.stringSlicesEqual(oldConfig.AllowedDNSServers, config.AllowedDNSServers) {
			log.Printf("    Allowed DNS Servers: %v -> %v", 
				oldConfig.AllowedDNSServers, config.AllowedDNSServers)
		}
		if !cm.stringSlicesEqual(oldConfig.WhitelistedDomains, config.WhitelistedDomains) {
			log.Printf("    Whitelisted Domains: %v -> %v", 
				oldConfig.WhitelistedDomains, config.WhitelistedDomains)
		}
		if !cm.stringSlicesEqual(oldConfig.BlacklistedDomains, config.BlacklistedDomains) {
			log.Printf("    Blacklisted Domains: %v -> %v", 
				oldConfig.BlacklistedDomains, config.BlacklistedDomains)
		}
		if oldConfig.DefaultTTL != config.DefaultTTL {
			log.Printf("    Default TTL: %d -> %d", oldConfig.DefaultTTL, config.DefaultTTL)
		}
		if oldConfig.MaxTTL != config.MaxTTL {
			log.Printf("    Max TTL: %d -> %d", oldConfig.MaxTTL, config.MaxTTL)
		}
		if oldConfig.MinTTL != config.MinTTL {
			log.Printf("    Min TTL: %d -> %d", oldConfig.MinTTL, config.MinTTL)
		}
		if oldConfig.RefreshInterval != config.RefreshInterval {
			log.Printf("    Refresh Interval: %d -> %d", oldConfig.RefreshInterval, config.RefreshInterval)
		}
		if oldConfig.RestrictToAllowedDNS != config.RestrictToAllowedDNS {
			log.Printf("    Restrict to Allowed DNS: %v -> %v", 
				oldConfig.RestrictToAllowedDNS, config.RestrictToAllowedDNS)
		}
	} else {
		log.Printf("  Initial configuration applied")
	}

	// Trigger config change callback
	if cm.onConfigChange != nil {
		if err := cm.onConfigChange(config); err != nil {
			log.Printf("Error applying configuration: %v", err)
			// Revert to old config
			cm.currentConfig = oldConfig
			return err
		}
	}

	log.Printf("Configuration successfully updated and applied")
	return nil
}

// SetServerConfig sets a new configuration from the config server
func (cm *ConfigManager) SetServerConfig(config interface{}) error {
	// Convert from server config to local config
	localConfig := convertToLocalConfig(config)
	return cm.SetConfig(localConfig, "server")
}

// SaveToFile saves the current configuration to file
func (cm *ConfigManager) SaveToFile() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.configPath == "" {
		return fmt.Errorf("config path not set")
	}

	// Ensure directory exists
	dir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cm.currentConfig, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(cm.configPath, data, 0644); err != nil {
		return err
	}

	log.Printf("Configuration saved to %s", cm.configPath)
	return nil
}

// GetLastUpdated returns the time when configuration was last updated
func (cm *ConfigManager) GetLastUpdated() time.Time {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.lastUpdated
}

// configsEqual compares two configurations for equality
func (cm *ConfigManager) configsEqual(a, b *LocalEgressConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return cm.stringSlicesEqual(a.AllowedDNSServers, b.AllowedDNSServers) &&
		cm.stringSlicesEqual(a.WhitelistedDomains, b.WhitelistedDomains) &&
		cm.stringSlicesEqual(a.BlacklistedDomains, b.BlacklistedDomains) &&
		a.DefaultTTL == b.DefaultTTL &&
		a.MaxTTL == b.MaxTTL &&
		a.MinTTL == b.MinTTL &&
		a.RefreshInterval == b.RefreshInterval &&
		a.RestrictToAllowedDNS == b.RestrictToAllowedDNS &&
		a.Interface == b.Interface &&
		a.UseEBPF == b.UseEBPF &&
		a.UseIPTables == b.UseIPTables
}

// stringSlicesEqual compares two string slices for equality (order-independent)
func (cm *ConfigManager) stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aSet := make(map[string]bool)
	for _, s := range a {
		aSet[s] = true
	}

	for _, s := range b {
		if !aSet[s] {
			return false
		}
	}

	return true
}

// DeepCopy creates a deep copy of the configuration
func (c *LocalEgressConfig) DeepCopy() *LocalEgressConfig {
	if c == nil {
		return nil
	}

	copy := &LocalEgressConfig{
		AllowedDNSServers: make([]string, len(c.AllowedDNSServers)),
		WhitelistedDomains: make([]string, len(c.WhitelistedDomains)),
		BlacklistedDomains: make([]string, len(c.BlacklistedDomains)),
		DefaultTTL:        c.DefaultTTL,
		MaxTTL:            c.MaxTTL,
		MinTTL:            c.MinTTL,
		RefreshInterval:   c.RefreshInterval,
		RestrictToAllowedDNS: c.RestrictToAllowedDNS,
		Interface:        c.Interface,
		UseEBPF:         c.UseEBPF,
		UseIPTables:     c.UseIPTables,
	}

	copy(c.AllowedDNSServers, copy.AllowedDNSServers)
	copy(c.WhitelistedDomains, copy.WhitelistedDomains)
	copy(c.BlacklistedDomains, copy.BlacklistedDomains)

	return copy
}

// convertToLocalConfig converts a server configuration to a local configuration
func convertToLocalConfig(serverConfig interface{}) *LocalEgressConfig {
	// Type assertion to the expected server config type
	if sc, ok := serverConfig.(map[string]interface{}); ok {
		config := &LocalEgressConfig{
			DefaultTTL:        300,
			MaxTTL:            86400,
			MinTTL:            5,
			RefreshInterval:   300,
			RestrictToAllowedDNS: true,
			Interface:        "eth0",
			UseEBPF:         true,
			UseIPTables:     false,
		}

		// Extract fields from server config
		if allowedDNSServers, ok := sc["allowed_dns_resolvers"].([]interface{}); ok {
			for _, dns := range allowedDNSServers {
				if dnsStr, ok := dns.(string); ok {
					config.AllowedDNSServers = append(config.AllowedDNSServers, dnsStr)
				}
			}
		}

		if whitelistedDomains, ok := sc["whitelisted_domains"].([]interface{}); ok {
			for _, domain := range whitelistedDomains {
				if domainStr, ok := domain.(string); ok {
					config.WhitelistedDomains = append(config.WhitelistedDomains, domainStr)
				}
			}
		}

		if blacklistedDomains, ok := sc["blacklisted_domains"].([]interface{}); ok {
			for _, domain := range blacklistedDomains {
				if domainStr, ok := domain.(string); ok {
					config.BlacklistedDomains = append(config.BlacklistedDomains, domainStr)
				}
			}
		}

		// Extract numeric fields
		if defaultTTL, ok := sc["default_ttl"].(float64); ok {
			config.DefaultTTL = int(defaultTTL)
		}
		if maxTTL, ok := sc["max_ttl"].(float64); ok {
			config.MaxTTL = int(maxTTL)
		}
		if minTTL, ok := sc["min_ttl"].(float64); ok {
			config.MinTTL = int(minTTL)
		}
		if refreshInterval, ok := sc["refresh_interval"].(float64); ok {
			config.RefreshInterval = int(refreshInterval)
		}
		if restrictToAllowedDNS, ok := sc["restrict_to_allowed_dns"].(bool); ok {
			config.RestrictToAllowedDNS = restrictToAllowedDNS
		}

		return config
	}

	// Fallback: return nil
	log.Printf("Warning: unknown server config type: %T", serverConfig)
	return nil
}
