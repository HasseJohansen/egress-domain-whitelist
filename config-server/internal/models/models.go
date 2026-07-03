// Package models contains data models for the configuration server
package models

import (
	"encoding/json"
	"time"
)

// Configuration represents a DNS egress filter configuration
type Configuration struct {
	ID               uint      `json:"id" db:"id"`
	Name             string    `json:"name" db:"name"`
	AllowedDNSServers []string `json:"allowed_dns_resolvers" db:"allowed_dns_resolvers"` // JSON array
	WhitelistedDomains []string `json:"whitelisted_domains" db:"whitelisted_domains"`     // JSON array
	BlacklistedDomains []string `json:"blacklisted_domains" db:"blacklisted_domains"`     // JSON array
	DefaultTTL        int       `json:"default_ttl" db:"default_ttl"`                       // seconds
	MaxTTL            int       `json:"max_ttl" db:"max_ttl"`                             // seconds
	MinTTL            int       `json:"min_ttl" db:"min_ttl"`                             // seconds
	RefreshInterval   int       `json:"refresh_interval" db:"refresh_interval"`         // seconds
	RestrictToAllowedDNS bool   `json:"restrict_to_allowed_dns" db:"restrict_to_allowed_dns"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// Scan implements the sql.Scanner interface for Configuration
func (c *Configuration) Scan(value interface{}) error {
	return json.Unmarshal(value.([]byte), c)
}

// Value implements the driver.Valuer interface for Configuration
func (c *Configuration) Value() (interface{}, error) {
	return json.Marshal(c)
}

// Host represents a registered host
type Host struct {
	ID                  uint      `json:"id" db:"id"`
	Hostname            string    `json:"hostname" db:"hostname"`
	IPAddress           string    `json:"ip_address" db:"ip_address"`
	LastSeenAt          time.Time `json:"last_seen_at" db:"last_seen_at"`
	Status              string    `json:"status" db:"status"` // "unconfigured", "configured", "error"
	CertificateFingerprint string `json:"certificate_fingerprint" db:"certificate_fingerprint"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	ConfigID           *uint     `json:"config_id" db:"config_id"` // Direct config assignment
}

// HostGroup represents a static group of hosts
type HostGroup struct {
	ID        uint      `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	ConfigID  *uint     `json:"config_id" db:"config_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// DynamicHostGroup represents a dynamic group based on hostname patterns
type DynamicHostGroup struct {
	ID        uint      `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Pattern   string    `json:"pattern" db:"pattern"` // e.g., "web-*", "*.example.com"
	ConfigID  *uint     `json:"config_id" db:"config_id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// HostConfiguration represents the configuration assignment for a host
type HostConfiguration struct {
	HostID           uint  `json:"host_id" db:"host_id"`
	ConfigID        *uint `json:"config_id" db:"config_id"`        // Direct config
	HostGroupID     *uint `json:"host_group_id" db:"group_id"`    // Static group
	DynamicGroupID  *uint `json:"dynamic_group_id" db:"dynamic_group_id"` // Dynamic group
}

// EgressFilterConfig represents the configuration sent to host agents
type EgressFilterConfig struct {
	AllowedDNSServers   []string `json:"allowed_dns_resolvers"`
	WhitelistedDomains   []string `json:"whitelisted_domains"`
	BlacklistedDomains   []string `json:"blacklisted_domains"`
	DefaultTTL          int      `json:"default_ttl"`
	MaxTTL              int      `json:"max_ttl"`
	MinTTL              int      `json:"min_ttl"`
	RefreshInterval     int      `json:"refresh_interval"`
	RestrictToAllowedDNS bool    `json:"restrict_to_allowed_dns"`
	// Computed from assignments
	ConfigurationID uint `json:"configuration_id"`
}

// ConvertToEgressConfig converts a Configuration to EgressFilterConfig
func (c *Configuration) ConvertToEgressConfig() *EgressFilterConfig {
	return &EgressFilterConfig{
		AllowedDNSServers:   c.AllowedDNSServers,
		WhitelistedDomains:   c.WhitelistedDomains,
		BlacklistedDomains:   c.BlacklistedDomains,
		DefaultTTL:          c.DefaultTTL,
		MaxTTL:              c.MaxTTL,
		MinTTL:              c.MinTTL,
		RefreshInterval:     c.RefreshInterval,
		RestrictToAllowedDNS: c.RestrictToAllowedDNS,
		ConfigurationID:     c.ID,
	}
}

// HostStatus represents the current status of a host
type HostStatus struct {
	HostID          uint   `json:"host_id"`
	Status         string `json:"status"`
	LastConfigID   *uint  `json:"last_config_id"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	LastError      string `json:"last_error,omitempty"`
	ConfigurationID *uint  `json:"configuration_id,omitempty"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// NewSuccessResponse creates a success response
func NewSuccessResponse(message string, data interface{}) APIResponse {
	return APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// NewErrorResponse creates an error response
func NewErrorResponse(message string, err string) APIResponse {
	return APIResponse{
		Success: false,
		Message: message,
		Error:   err,
	}
}
