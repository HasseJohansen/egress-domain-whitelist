// Package api provides host-related REST API handlers for the configuration server
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/db"
	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/models"
	"github.com/go-chi/chi/v5"
)

// HostAPIConfig holds configuration for host API handlers
type HostAPIConfig struct {
	HostRepo        *db.HostRepository
	ConfigRepo     *db.ConfigurationRepository
	GroupRepo      *db.HostGroupRepository
	DynamicGroupRepo *db.DynamicHostGroupRepository
	Hub            *Hub
}

// registerHost registers a new host with the configuration server
func (s *Server) registerHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hostname            string `json:"hostname"`
		IPAddress           string `json:"ip_address"`
		CertificateFingerprint string `json:"certificate_fingerprint,omitempty"`
		Status              string `json:"status,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "hostname is required", nil)
		return
	}

	// Validate hostname (basic validation)
	if len(req.Hostname) > 255 {
		writeError(w, http.StatusBadRequest, "hostname too long (max 255 chars)", nil)
		return
	}

	// Use default status if not provided
	if req.Status == "" {
		req.Status = "unconfigured"
	}

	// Validate status
	if req.Status != "" && req.Status != "unconfigured" && req.Status != "configured" && req.Status != "error" {
		writeError(w, http.StatusBadRequest, "invalid status", nil)
		return
	}

	// Validate IP address if provided
	if req.IPAddress != "" {
		if _, err := filepath.Match("[0-9].*.[0-9].*.[0-9].*", req.IPAddress); err != nil {
			// Simple IP validation - more thorough validation in production
			if !strings.Contains(req.IPAddress, ":") && !strings.Contains(req.IPAddress, ".") {
				writeError(w, http.StatusBadRequest, "invalid IP address", nil)
				return
			}
		}
	} else {
		// Try to get IP from request
		req.IPAddress = getClientIP(r)
	}

	// Generate certificate fingerprint if not provided
	if req.CertificateFingerprint == "" {
		// In production, this would be the actual certificate fingerprint
		// For now, use a placeholder based on hostname
		req.CertificateFingerprint = fmt.Sprintf("placeholder-%s", req.Hostname)
	}

	// Check if host already exists
	existingHost, err := s.config.HostRepo.GetByHostname(req.Hostname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check existing host", err)
		return
	}

	if existingHost != nil {
		// Update existing host
		existingHost.IPAddress = req.IPAddress
		existingHost.LastSeenAt = time.Now()
		existingHost.Status = req.Status
		if req.CertificateFingerprint != "" {
			existingHost.CertificateFingerprint = req.CertificateFingerprint
		}

		if err := s.config.HostRepo.Update(existingHost); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to update existing host", err)
			return
		}

		// Return existing host
		writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host already registered", map[string]interface{}{
			"host": existingHost,
		}))
		return
	}

	// Create new host
	host := &models.Host{
		Hostname:            req.Hostname,
		IPAddress:           req.IPAddress,
		LastSeenAt:          time.Now(),
		Status:              req.Status,
		CertificateFingerprint: req.CertificateFingerprint,
		ConfigID:           nil,
	}

	if err := s.config.HostRepo.Create(host); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to register host", err)
		return
	}

	log.Printf("Host registered: %s (ID: %d)", host.Hostname, host.ID)

	writeJSON(w, http.StatusCreated, models.NewSuccessResponse("Host registered successfully", map[string]interface{}{
		"host": host,
	}))
}

// listHosts lists all registered hosts
func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters for filtering
	query := r.URL.Query()
	statusFilter := query.Get("status")
	hostnameFilter := query.Get("hostname")

	// Get all hosts
	hosts, err := s.config.HostRepo.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list hosts", err)
		return
	}

	// Apply filters
	var filteredHosts []*models.Host
	for _, host := range hosts {
		// Filter by status
		if statusFilter != "" && host.Status != statusFilter {
			continue
		}

		// Filter by hostname
		if hostnameFilter != "" {
			if !strings.Contains(host.Hostname, hostnameFilter) {
				continue
			}
		}

		filteredHosts = append(filteredHosts, host)
	}

	// Get configuration names for each host
	var hostsWithConfig []map[string]interface{}
	for _, host := range filteredHosts {
		hostData := map[string]interface{}{
			"id":                  host.ID,
			"hostname":            host.Hostname,
			"ip_address":          host.IPAddress,
			"last_seen_at":       host.LastSeenAt,
			"status":              host.Status,
			"certificate_fingerprint": host.CertificateFingerprint,
			"created_at":          host.CreatedAt,
			"config_id":           host.ConfigID,
		}

		// Add configuration name if assigned
		if host.ConfigID != nil {
			config, err := s.config.ConfigRepo.GetByID(*host.ConfigID)
			if err == nil && config != nil {
				hostData["config_name"] = config.Name
			}
		}

		// Check dynamic group assignments
		if config, err := s.getHostEffectiveConfig(host); err == nil && config != nil {
			hostData["effective_config_id"] = config.ID
			hostData["effective_config_name"] = config.Name
		} else {
			hostData["effective_config_id"] = nil
			hostData["effective_config_name"] = nil
		}

		hostsWithConfig = append(hostsWithConfig, hostData)
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Hosts listed successfully", map[string]interface{}{
		"hosts": hostsWithConfig,
		"total": len(filteredHosts),
	}))
}

// getHost retrieves a specific host by ID
func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	hostIDStr := chi.URLParam(r, "id")

	var hostID uint
	if _, err := fmt.Sscanf(hostIDStr, "%d", &hostID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid host ID", err)
		return
	}

	host, err := s.config.HostRepo.GetByID(hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get host", err)
		return
	}

	if host == nil {
		writeError(w, http.StatusNotFound, "Host not found", nil)
		return
	}

	// Get effective configuration
	effectiveConfig, err := s.getHostEffectiveConfig(host)
	if err != nil {
		log.Printf("Warning: failed to get effective config for host %d: %v", hostID, err)
	}

	hostData := map[string]interface{}{
		"host": host,
		"effective_config": effectiveConfig,
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host retrieved successfully", hostData))
}

// updateHost updates a host
func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) {
	hostIDStr := chi.URLParam(r, "id")

	var hostID uint
	if _, err := fmt.Sscanf(hostIDStr, "%d", &hostID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid host ID", err)
		return
	}

	// Get existing host
	host, err := s.config.HostRepo.GetByID(hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get host", err)
		return
	}

	if host == nil {
		writeError(w, http.StatusNotFound, "Host not found", nil)
		return
	}

	// Parse update request
	var req struct {
		IPAddress           *string `json:"ip_address,omitempty"`
		Status              *string `json:"status,omitempty"`
		CertificateFingerprint *string `json:"certificate_fingerprint,omitempty"`
		ConfigID           *uint   `json:"config_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Apply updates
	if req.IPAddress != nil {
		host.IPAddress = *req.IPAddress
	}
	if req.Status != nil {
		// Validate status
		if *req.Status != "" && *req.Status != "unconfigured" && *req.Status != "configured" && *req.Status != "error" {
			writeError(w, http.StatusBadRequest, "invalid status", nil)
			return
		}
		host.Status = *req.Status
	}
	if req.CertificateFingerprint != nil {
		host.CertificateFingerprint = *req.CertificateFingerprint
	}
	if req.ConfigID != nil {
		// Validate config exists
		if *req.ConfigID != 0 {
			config, err := s.config.ConfigRepo.GetByID(*req.ConfigID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "Failed to validate config", err)
				return
			}
			if config == nil {
				writeError(w, http.StatusBadRequest, "Config not found", nil)
				return
			}
		}
		host.ConfigID = req.ConfigID
	}

	if err := s.config.HostRepo.Update(host); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update host", err)
		return
	}

	// Notify about configuration change via WebSocket
	if host.ConfigID != nil {
		s.hub.BroadcastConfigurationUpdate(hostID, *host.ConfigID)
		
		// Send the full configuration
		if config, err := s.config.ConfigRepo.GetByID(*host.ConfigID); err == nil && config != nil {
			s.hub.SendConfiguration(hostID, config.ConvertToEgressConfig())
		}
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host updated successfully", map[string]interface{}{
		"host": host,
	}))
}

// deleteHost deletes a host
func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	hostIDStr := chi.URLParam(r, "id")

	var hostID uint
	if _, err := fmt.Sscanf(hostIDStr, "%d", &hostID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid host ID", err)
		return
	}

	// Get host to verify it exists
	host, err := s.config.HostRepo.GetByID(hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get host", err)
		return
	}

	if host == nil {
		writeError(w, http.StatusNotFound, "Host not found", nil)
		return
	}

	if err := s.config.HostRepo.Delete(hostID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete host", err)
		return
	}

	log.Printf("Host deleted: %s (ID: %d)", host.Hostname, hostID)

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host deleted successfully", nil))
}

// getHostConfiguration retrieves the effective configuration for a host
func (s *Server) getHostConfiguration(w http.ResponseWriter, r *http.Request) {
	hostIDStr := chi.URLParam(r, "id")

	var hostID uint
	if _, err := fmt.Sscanf(hostIDStr, "%d", &hostID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid host ID", err)
		return
	}

	host, err := s.config.HostRepo.GetByID(hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get host", err)
		return
	}

	if host == nil {
		writeError(w, http.StatusNotFound, "Host not found", nil)
		return
	}

	// Get effective configuration
	effectiveConfig, err := s.getHostEffectiveConfig(host)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get host configuration", err)
		return
	}

	if effectiveConfig == nil {
		// Host is unconfigured
		writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host has no configuration", map[string]interface{}{
			"host_id": host.ID,
			"configured": false,
		}))
		return
	}

	// Convert to egress filter config
	egressConfig := effectiveConfig.ConvertToEgressConfig()

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host configuration retrieved", map[string]interface{}{
		"host_id":         host.ID,
		"host_hostname":   host.Hostname,
		"configured":      true,
		"configuration":   egressConfig,
	}))
}

// getHostEffectiveConfig resolves the effective configuration for a host
// Priority: direct config > static group > dynamic group
func (s *Server) getHostEffectiveConfig(host *models.Host) (*models.Configuration, error) {
	// 1. Check direct config assignment
	if host.ConfigID != nil {
		return s.config.ConfigRepo.GetByID(*host.ConfigID)
	}

	// 2. Check static group assignments
	config, err := s.getConfigFromStaticGroups(host)
	if err != nil {
		return nil, err
	}
	if config != nil {
		return config, nil
	}

	// 3. Check dynamic group assignments
	config, err = s.getConfigFromDynamicGroups(host)
	if err != nil {
		return nil, err
	}
	if config != nil {
		return config, nil
	}

	// No configuration assigned
	return nil, nil
}

// getConfigFromStaticGroups finds configuration from static host groups
func (s *Server) getConfigFromStaticGroups(host *models.Host) (*models.Configuration, error) {
	// In a full implementation, we would query host_group_members table
	// For now, we'll query all groups and check membership
	// This is a simplified version - in production, use a join query

	// Note: In the current database schema, static groups don't have explicit members
	// The schema has host_group_members table but no repository for it yet
	// For Phase 2, we'll use a simplified approach: check if any group has this host
	
	// For now, return nil as static group membership is not fully implemented
	// This will be enhanced when we implement the full group membership system
	return nil, nil
}

// getConfigFromDynamicGroups finds configuration from dynamic host groups
func (s *Server) getConfigFromDynamicGroups(host *models.Host) (*models.Configuration, error) {
	dynamicGroups, err := s.config.DynamicGroupRepo.List()
	if err != nil {
		return nil, err
	}

	// Find matching dynamic groups
	for _, group := range dynamicGroups {
		if group.ConfigID == nil {
			continue
		}

		// Match hostname against pattern
		if matchHostnamePattern(host.Hostname, group.Pattern) {
			return s.config.ConfigRepo.GetByID(*group.ConfigID)
		}
	}

	return nil, nil
}

// matchHostnamePattern matches a hostname against a pattern
// Supports: exact match, wildcard (*), prefix (*.example.com), suffix (web-*)
func matchHostnamePattern(hostname, pattern string) bool {
	// Direct match
	if hostname == pattern {
		return true
	}

	// Convert pattern to regex
	regexPattern := regexp.QuoteMeta(pattern)
	// Replace * with .* for wildcard matching
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, `.*`)
	// Anchor the pattern
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, hostname)
	if err == nil && matched {
		return true
	}

	// Try simpler patterns
	// Pattern like "web-*" should match "web-01", "web-02", etc.
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(hostname, prefix) {
			return true
		}
	}

	// Pattern like "*.example.com" should match "host.example.com", "app.example.com", etc.
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		if strings.HasSuffix(hostname, suffix) {
			return true
		}
	}

	return false
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for reverse proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	// RemoteAddr is in the form "IP:port"
	addr := r.RemoteAddr
	if colonIdx := strings.LastIndex(addr, ":"); colonIdx != -1 {
		return addr[:colonIdx]
	}

	return addr
}
