// Package api provides host assignment-related REST API handlers for the configuration server
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/models"
	"github.com/go-chi/chi/v5"
)

// assignHostToConfig assigns a host directly to a configuration
func (s *Server) assignHostToConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HostID   uint `json:"host_id"`
		ConfigID uint `json:"config_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.HostID == 0 {
		writeError(w, http.StatusBadRequest, "host_id is required", nil)
		return
	}

	if req.ConfigID == 0 {
		writeError(w, http.StatusBadRequest, "config_id is required", nil)
		return
	}

	// Validate host exists
	host, err := s.config.HostRepo.GetByID(req.HostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to validate host", err)
		return
	}

	if host == nil {
		writeError(w, http.StatusNotFound, "Host not found", nil)
		return
	}

	// Validate config exists
	config, err := s.config.ConfigRepo.GetByID(req.ConfigID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to validate config", err)
		return
	}

	if config == nil {
		writeError(w, http.StatusBadRequest, "Config not found", nil)
		return
	}

	// Update host with new config assignment
	host.ConfigID = &req.ConfigID
	host.Status = "configured"

	if err := s.config.HostRepo.Update(host); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to assign config to host", err)
		return
	}

	log.Printf("Host %d (%s) assigned to config %d (%s)", host.ID, host.Hostname, config.ID, config.Name)

	// Notify about configuration change via WebSocket
	s.hub.BroadcastConfigurationUpdate(req.HostID, req.ConfigID)
	
	// Also send the full configuration
	s.hub.SendConfiguration(req.HostID, config.ConvertToEgressConfig())

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host assigned to configuration successfully", map[string]interface{}{
		"host_id":   req.HostID,
		"config_id": req.ConfigID,
		"host":     host,
		"config":   config,
	}))
}

// assignHostToGroup assigns a host to a static host group
func (s *Server) assignHostToGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HostID  uint `json:"host_id"`
		GroupID uint `json:"group_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.HostID == 0 {
		writeError(w, http.StatusBadRequest, "host_id is required", nil)
		return
	}

	if req.GroupID == 0 {
		writeError(w, http.StatusBadRequest, "group_id is required", nil)
		return
	}

	// Validate host exists
	host, err := s.config.HostRepo.GetByID(req.HostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to validate host", err)
		return
	}

	if host == nil {
		writeError(w, http.StatusNotFound, "Host not found", nil)
		return
	}

	// Validate group exists
	group, err := s.config.GroupRepo.GetByID(req.GroupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to validate group", err)
		return
	}

	if group == nil {
		writeError(w, http.StatusBadRequest, "Group not found", nil)
		return
	}

	// Note: In Phase 2, we're using a simplified approach where hosts get config from group
	// In a full implementation, we'd have a host_group_members table
	// For now, we'll assign the group's config to the host directly
	// This means the host inherits the config from the group

	if group.ConfigID == nil {
		// Group has no config assigned - set host to unconfigured
		host.ConfigID = nil
		host.Status = "unconfigured"
	} else {
		// Assign group's config to host
		host.ConfigID = group.ConfigID
		host.Status = "configured"
	}

	if err := s.config.HostRepo.Update(host); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to assign host to group", err)
		return
	}

	log.Printf("Host %d (%s) assigned to group %d (%s)", host.ID, host.Hostname, group.ID, group.Name)

	// Notify about configuration change via WebSocket
	if host.ConfigID != nil {
		s.hub.BroadcastConfigurationUpdate(req.HostID, *host.ConfigID)
		
		// Send the full configuration if available
		if group.ConfigID != nil {
			if config, err := s.config.ConfigRepo.GetByID(*group.ConfigID); err == nil && config != nil {
				s.hub.SendConfiguration(req.HostID, config.ConvertToEgressConfig())
			}
		}
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host assigned to group successfully", map[string]interface{}{
		"host_id":  req.HostID,
		"group_id": req.GroupID,
		"host":    host,
		"group":   group,
	}))
}

// assignHostToDynamicGroup assigns a host to a dynamic host group
// Note: Dynamic groups match automatically based on hostname patterns, so this is more about
// verifying the match and returning the effective configuration
func (s *Server) assignHostToDynamicGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		HostID  uint `json:"host_id"`
		GroupID uint `json:"dynamic_group_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.HostID == 0 {
		writeError(w, http.StatusBadRequest, "host_id is required", nil)
		return
	}

	if req.GroupID == 0 {
		writeError(w, http.StatusBadRequest, "dynamic_group_id is required", nil)
		return
	}

	// Validate host exists
	host, err := s.config.HostRepo.GetByID(req.HostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to validate host", err)
		return
	}

	if host == nil {
		writeError(w, http.StatusNotFound, "Host not found", nil)
		return
	}

	// Validate dynamic group exists
	dynamicGroup, err := s.config.DynamicGroupRepo.GetByID(req.GroupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to validate dynamic group", err)
		return
	}

	if dynamicGroup == nil {
		writeError(w, http.StatusBadRequest, "Dynamic group not found", nil)
		return
	}

	// Check if hostname matches pattern
	if !matchHostnamePattern(host.Hostname, dynamicGroup.Pattern) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Hostname '%s' does not match pattern '%s'", host.Hostname, dynamicGroup.Pattern), nil)
		return
	}

	// Note: In Phase 2, we're using a simplified approach
	// Dynamic groups automatically match hosts based on patterns
	// The assignment is implicit - if a host's hostname matches a dynamic group's pattern,
	// the host gets the config from that group
	
	// For this endpoint, we'll just verify the match and return the effective config
	// The actual config assignment happens automatically when resolving config for a host

	var effectiveConfig *models.Configuration
	var configID *uint

	if dynamicGroup.ConfigID != nil {
		effectiveConfig, err = s.config.ConfigRepo.GetByID(*dynamicGroup.ConfigID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to get group config", err)
			return
		}
		configID = dynamicGroup.ConfigID
	}

	// Note: We don't actually store this assignment in the database
	// The matching happens dynamically when resolving config for a host

	log.Printf("Host %d (%s) matches dynamic group %d (%s) with pattern '%s'",
		host.ID, host.Hostname, dynamicGroup.ID, dynamicGroup.Name, dynamicGroup.Pattern)

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host matches dynamic group", map[string]interface{}{
		"host_id":         req.HostID,
		"dynamic_group_id": req.GroupID,
		"matches":         true,
		"pattern":         dynamicGroup.Pattern,
		"config_id":       configID,
		"effective_config": effectiveConfig,
	}))
}

// getHostAssignments retrieves all assignments for a host
func (s *Server) getHostAssignments(w http.ResponseWriter, r *http.Request) {
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

	// Get direct config assignment
	var assignments = map[string]interface{}{
		"host":       host,
		"direct_config": nil,
		"static_groups": []*models.HostGroup{},
		"dynamic_groups": []*models.DynamicHostGroup{},
		"effective_config": nil,
	}

	// Check direct config
	if host.ConfigID != nil {
		config, err := s.config.ConfigRepo.GetByID(*host.ConfigID)
		if err == nil && config != nil {
			assignments["direct_config"] = config
		}
	}

	// Check static group memberships
	// In Phase 2, we use a simplified approach - check if any static group has this config
	// In a full implementation, we'd query host_group_members table
	var staticGroups []*models.HostGroup
	groups, err := s.config.GroupRepo.List()
	if err == nil {
		for _, group := range groups {
			// In Phase 2, we consider a host part of a static group if the group's config matches
			// This is a simplification - full implementation would have explicit membership
			if group.ConfigID != nil && host.ConfigID != nil && *group.ConfigID == *host.ConfigID {
				staticGroups = append(staticGroups, group)
			}
		}
	}
	assignments["static_groups"] = staticGroups

	// Check dynamic group matches
	var dynamicGroupsList []*models.DynamicHostGroup
	dynamicGroups, err := s.config.DynamicGroupRepo.List()
	if err == nil {
		for _, group := range dynamicGroups {
			if matchHostnamePattern(host.Hostname, group.Pattern) {
				dynamicGroupsList = append(dynamicGroupsList, group)
			}
		}
	}
	assignments["dynamic_groups"] = dynamicGroupsList

	// Get effective configuration
	effectiveConfig, err := s.getHostEffectiveConfig(host)
	if err == nil && effectiveConfig != nil {
		assignments["effective_config"] = effectiveConfig
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host assignments retrieved", assignments))
}
