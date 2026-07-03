// Package config provides configuration management for the server
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig holds the server configuration
type ServerConfig struct {
	Port           int      `yaml:"port" json:"port"`
	DatabasePath   string   `yaml:"database_path" json:"database_path"`
	CertFile       string   `yaml:"cert_file" json:"cert_file"`
	KeyFile        string   `yaml:"key_file" json:"key_file"`
	CACertFile     string   `yaml:"ca_cert_file" json:"ca_cert_file"`
	AllowedSubnets []string `yaml:"allowed_subnets" json:"allowed_subnets"`
	DevMode        bool     `yaml:"dev_mode" json:"dev_mode"`
	LogLevel       string   `yaml:"log_level" json:"log_level"`
	// Web interface authentication
	Password        string `yaml:"password" json:"password"` // Web interface password (required)
	SessionTimeout  int    `yaml:"session_timeout" json:"session_timeout"` // Session timeout in minutes
}

// DefaultServerConfig returns the default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:           8443,
		DatabasePath:   "./data/config-server.db",
		CertFile:       "./certs/server.crt",
		KeyFile:        "./certs/server.key",
		CACertFile:     "./certs/ca.crt",
		AllowedSubnets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"},
		DevMode:        false,
		LogLevel:       "info",
		Password:       "", // No default password - must be set
		SessionTimeout: 30, // 30 minutes
	}
}

// LoadServerConfig loads configuration from a YAML file
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ServerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Apply defaults for missing values
	if config.Port == 0 {
		config.Port = DefaultServerConfig().Port
	}
	if config.DatabasePath == "" {
		config.DatabasePath = DefaultServerConfig().DatabasePath
	}
	if len(config.AllowedSubnets) == 0 {
		config.AllowedSubnets = DefaultServerConfig().AllowedSubnets
	}

	return &config, nil
}

// SaveServerConfig saves configuration to a YAML file
func SaveServerConfig(path string, config *ServerConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	dir := os.Getenv("CONFIG_DIR")
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// HostAgentConfig holds the configuration for host agents
type HostAgentConfig struct {
	ServerURL        string   `yaml:"server_url" json:"server_url"`
	CertFile        string   `yaml:"cert_file" json:"cert_file"`
	KeyFile         string   `yaml:"key_file" json:"key_file"`
	CACertFile      string   `yaml:"ca_cert_file" json:"ca_cert_file"`
	Hostname        string   `yaml:"hostname" json:"hostname"`
	ConfigServerURL string   `yaml:"config_server_url" json:"config_server_url"`
	PollInterval    int      `yaml:"poll_interval" json:"poll_interval"` // seconds
	LogLevel        string   `yaml:"log_level" json:"log_level"`
	// Local config (only used in standalone mode)
	LocalConfig *LocalEgressConfig `yaml:"local_config,omitempty" json:"local_config,omitempty"`
	// Managed mode flag - when true, local config is ignored
	ManagedMode bool `yaml:"managed_mode" json:"managed_mode"`
}

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

// DefaultHostAgentConfig returns the default host agent configuration
func DefaultHostAgentConfig() *HostAgentConfig {
	return &HostAgentConfig{
		ServerURL:        "https://localhost:8443",
		CertFile:        "./certs/client.crt",
		KeyFile:         "./certs/client.key",
		CACertFile:      "./certs/ca.crt",
		Hostname:        getHostname(),
		ConfigServerURL: "",
		PollInterval:    30,
		LogLevel:        "info",
		ManagedMode:     false,
		LocalConfig: &LocalEgressConfig{
			AllowedDNSServers: []string{"8.8.8.8:53", "1.1.1.1:53"},
			WhitelistedDomains: []string{},
			BlacklistedDomains: []string{},
			DefaultTTL:        300,
			MaxTTL:            86400,
			MinTTL:            5,
			RefreshInterval:   300,
			RestrictToAllowedDNS: true,
			Interface:        "eth0",
			UseEBPF:         true,
			UseIPTables:     false,
		},
	}
}

// LoadHostAgentConfig loads host agent configuration from a YAML file
func LoadHostAgentConfig(path string) (*HostAgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config HostAgentConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Apply defaults for missing values
	if config.ServerURL == "" {
		config.ServerURL = DefaultHostAgentConfig().ServerURL
	}
	if config.PollInterval == 0 {
		config.PollInterval = DefaultHostAgentConfig().PollInterval
	}
	if config.Hostname == "" {
		config.Hostname = getHostname()
	}

	return &config, nil
}

// SaveHostAgentConfig saves host agent configuration to a YAML file
func SaveHostAgentConfig(path string, config *HostAgentConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() (*ServerConfig, *HostAgentConfig, error) {
	serverConfig := DefaultServerConfig()
	hostAgentConfig := DefaultHostAgentConfig()

	// Override with environment variables
	if port := os.Getenv("SERVER_PORT"); port != "" {
		fmt.Sscanf(port, "%d", &serverConfig.Port)
	}
	if dbPath := os.Getenv("DATABASE_PATH"); dbPath != "" {
		serverConfig.DatabasePath = dbPath
	}
	if certFile := os.Getenv("SERVER_CERT"); certFile != "" {
		serverConfig.CertFile = certFile
	}
	if keyFile := os.Getenv("SERVER_KEY"); keyFile != "" {
		serverConfig.KeyFile = keyFile
	}
	if caCert := os.Getenv("CA_CERT"); caCert != "" {
		serverConfig.CACertFile = caCert
	}

	// For host agent
	if serverURL := os.Getenv("CONFIG_SERVER_URL"); serverURL != "" {
		hostAgentConfig.ConfigServerURL = serverURL
		hostAgentConfig.ServerURL = serverURL
	}
	if managedMode := os.Getenv("MANAGED_MODE"); managedMode == "true" {
		hostAgentConfig.ManagedMode = true
	}

	return serverConfig, hostAgentConfig, nil
}

// Helper functions
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// MarshalJSON implements json.Marshaler for ServerConfig
func (s *ServerConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"port":            s.Port,
		"database_path":   s.DatabasePath,
		"cert_file":       s.CertFile,
		"key_file":        s.KeyFile,
		"ca_cert_file":    s.CACertFile,
		"allowed_subnets": s.AllowedSubnets,
		"dev_mode":        s.DevMode,
		"log_level":       s.LogLevel,
	})
}

// MarshalJSON implements json.Marshaler for HostAgentConfig
func (h *HostAgentConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"server_url":        h.ServerURL,
		"cert_file":        h.CertFile,
		"key_file":         h.KeyFile,
		"ca_cert_file":      h.CACertFile,
		"hostname":         h.Hostname,
		"config_server_url": h.ConfigServerURL,
		"poll_interval":    h.PollInterval,
		"log_level":        h.LogLevel,
		"managed_mode":     h.ManagedMode,
		"local_config":     h.LocalConfig,
	})
}
