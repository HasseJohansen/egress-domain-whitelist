// Package api provides host group-related REST API handlers for the configuration server
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/models"
	"github.com/go-chi/chi/v5"
)

// createHostGroup creates a new static host group
func (s *Server) createHostGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		ConfigID *uint   `json:"config_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required", nil)
		return
	}

	// Check if group with this name already exists
	existingGroup, err := s.config.GroupRepo.GetByName(req.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check existing group", err)
		return
	}

	if existingGroup != nil {
		writeError(w, http.StatusConflict, "Host group with this name already exists", nil)
		return
	}

	// Validate config if provided
	if req.ConfigID != nil && *req.ConfigID != 0 {
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

	// Create new group
	group := &models.HostGroup{
		Name:     req.Name,
		ConfigID: req.ConfigID,
	}

	if err := s.config.GroupRepo.Create(group); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create host group", err)
		return
	}

	log.Printf("Host group created: %s (ID: %d)", group.Name, group.ID)

	// Notify about configuration change via WebSocket
	// This would broadcast to all hosts that might be affected
	// For now, just log it
	if group.ConfigID != nil {
		log.Printf("Host group %s assigned to config %d - hosts should update", group.Name, *group.ConfigID)
	}

	writeJSON(w, http.StatusCreated, models.NewSuccessResponse("Host group created successfully", map[string]interface{}{
		"group": group,
	}))
}

// listHostGroups lists all static host groups
func (s *Server) listHostGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.config.GroupRepo.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list host groups", err)
		return
	}

	// Add config names to groups
	var groupsWithConfig []map[string]interface{}
	for _, group := range groups {
		groupData := map[string]interface{}{
			"id":         group.ID,
			"name":       group.Name,
			"config_id":  group.ConfigID,
			"created_at": group.CreatedAt,
		}

		if group.ConfigID != nil {
			config, err := s.config.ConfigRepo.GetByID(*group.ConfigID)
			if err == nil && config != nil {
				groupData["config_name"] = config.Name
			}
		}

		groupsWithConfig = append(groupsWithConfig, groupData)
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host groups listed successfully", map[string]interface{}{
		"groups": groupsWithConfig,
		"total": len(groups),
	}))
}

// getHostGroup retrieves a specific static host group by ID
func (s *Server) getHostGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := chi.URLParam(r, "id")

	var groupID uint
	if _, err := fmt.Sscanf(groupIDStr, "%d", &groupID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	group, err := s.config.GroupRepo.GetByID(groupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get host group", err)
		return
	}

	if group == nil {
		writeError(w, http.StatusNotFound, "Host group not found", nil)
		return
	}

	// Add config name if assigned
	var groupData = map[string]interface{}{
		"group": group,
	}

	if group.ConfigID != nil {
		config, err := s.config.ConfigRepo.GetByID(*group.ConfigID)
		if err == nil && config != nil {
			groupData["config"] = config
		}
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host group retrieved successfully", groupData))
}

// updateHostGroup updates a static host group
func (s *Server) updateHostGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := chi.URLParam(r, "id")

	var groupID uint
	if _, err := fmt.Sscanf(groupIDStr, "%d", &groupID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	// Get existing group
	group, err := s.config.GroupRepo.GetByID(groupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get host group", err)
		return
	}

	if group == nil {
		writeError(w, http.StatusNotFound, "Host group not found", nil)
		return
	}

	// Parse update request
	var req struct {
		Name     *string `json:"name,omitempty"`
		ConfigID *uint   `json:"config_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Apply updates
	if req.Name != nil {
		// Check if new name conflicts with existing group
		if *req.Name != group.Name {
			if existingGroup, err := s.config.GroupRepo.GetByName(*req.Name); err == nil && existingGroup != nil {
				writeError(w, http.StatusConflict, "Host group with this name already exists", nil)
				return
			}
		}
		group.Name = *req.Name
	}

	if req.ConfigID != nil {
		// Validate config if provided
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
		group.ConfigID = req.ConfigID
	}

	if err := s.config.GroupRepo.Update(group); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update host group", err)
		return
	}

	log.Printf("Host group updated: %s (ID: %d)", group.Name, groupID)

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host group updated successfully", map[string]interface{}{
		"group": group,
	}))
}

// deleteHostGroup deletes a static host group
func (s *Server) deleteHostGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := chi.URLParam(r, "id")

	var groupID uint
	if _, err := fmt.Sscanf(groupIDStr, "%d", &groupID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	// Get group to verify it exists
	group, err := s.config.GroupRepo.GetByID(groupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get host group", err)
		return
	}

	if group == nil {
		writeError(w, http.StatusNotFound, "Host group not found", nil)
		return
	}

	if err := s.config.GroupRepo.Delete(groupID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete host group", err)
		return
	}

	log.Printf("Host group deleted: %s (ID: %d)", group.Name, groupID)

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Host group deleted successfully", nil))
}

// createDynamicHostGroup creates a new dynamic host group
func (s *Server) createDynamicHostGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Pattern  string `json:"pattern"`
		ConfigID *uint   `json:"config_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required", nil)
		return
	}

	if req.Pattern == "" {
		writeError(w, http.StatusBadRequest, "pattern is required", nil)
		return
	}

	// Check if group with this name already exists
	existingGroup, err := s.config.DynamicGroupRepo.GetByName(req.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to check existing group", err)
		return
	}

	if existingGroup != nil {
		writeError(w, http.StatusConflict, "Dynamic host group with this name already exists", nil)
		return
	}

	// Validate config if provided
	if req.ConfigID != nil && *req.ConfigID != 0 {
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

	// Create new dynamic group
	group := &models.DynamicHostGroup{
		Name:     req.Name,
		Pattern:  req.Pattern,
		ConfigID: req.ConfigID,
	}

	if err := s.config.DynamicGroupRepo.Create(group); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create dynamic host group", err)
		return
	}

	log.Printf("Dynamic host group created: %s with pattern '%s' (ID: %d)", group.Name, group.Pattern, group.ID)

	writeJSON(w, http.StatusCreated, models.NewSuccessResponse("Dynamic host group created successfully", map[string]interface{}{
		"group": group,
	}))
}

// listDynamicHostGroups lists all dynamic host groups
func (s *Server) listDynamicHostGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.config.DynamicGroupRepo.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list dynamic host groups", err)
		return
	}

	// Add config names and matching host counts to groups
	var groupsWithInfo []map[string]interface{}
	for _, group := range groups {
		groupData := map[string]interface{}{
			"id":        group.ID,
			"name":      group.Name,
			"pattern":   group.Pattern,
			"config_id": group.ConfigID,
			"created_at": group.CreatedAt,
		}

		// Add config name if assigned
		if group.ConfigID != nil {
			config, err := s.config.ConfigRepo.GetByID(*group.ConfigID)
			if err == nil && config != nil {
				groupData["config_name"] = config.Name
			}
		}

		// Count matching hosts
		hosts, err := s.config.HostRepo.List()
		if err == nil {
			matchingCount := 0
			for _, host := range hosts {
				if matchHostnamePattern(host.Hostname, group.Pattern) {
					matchingCount++
				}
			}
			groupData["matching_hosts"] = matchingCount
		}

		groupsWithInfo = append(groupsWithInfo, groupData)
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Dynamic host groups listed successfully", map[string]interface{}{
		"groups": groupsWithInfo,
		"total": len(groups),
	}))
}

// getDynamicHostGroup retrieves a specific dynamic host group by ID
func (s *Server) getDynamicHostGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := chi.URLParam(r, "id")

	var groupID uint
	if _, err := fmt.Sscanf(groupIDStr, "%d", &groupID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	group, err := s.config.DynamicGroupRepo.GetByID(groupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get dynamic host group", err)
		return
	}

	if group == nil {
		writeError(w, http.StatusNotFound, "Dynamic host group not found", nil)
		return
	}

	// Add matching hosts to response
	var groupData = map[string]interface{}{
		"group": group,
	}

	// Add config name if assigned
	if group.ConfigID != nil {
		config, err := s.config.ConfigRepo.GetByID(*group.ConfigID)
		if err == nil && config != nil {
			groupData["config"] = config
		}
	}

	// List matching hosts
	hosts, err := s.config.HostRepo.List()
	if err == nil {
		var matchingHosts []*models.Host
		for _, host := range hosts {
			if matchHostnamePattern(host.Hostname, group.Pattern) {
				matchingHosts = append(matchingHosts, host)
			}
		}
		groupData["matching_hosts"] = matchingHosts
		groupData["matching_hosts_count"] = len(matchingHosts)
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Dynamic host group retrieved successfully", groupData))
}

// updateDynamicHostGroup updates a dynamic host group
func (s *Server) updateDynamicHostGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := chi.URLParam(r, "id")

	var groupID uint
	if _, err := fmt.Sscanf(groupIDStr, "%d", &groupID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	// Get existing group
	group, err := s.config.DynamicGroupRepo.GetByID(groupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get dynamic host group", err)
		return
	}

	if group == nil {
		writeError(w, http.StatusNotFound, "Dynamic host group not found", nil)
		return
	}

	// Parse update request
	var req struct {
		Name     *string `json:"name,omitempty"`
		Pattern  *string `json:"pattern,omitempty"`
		ConfigID *uint   `json:"config_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Apply updates
	if req.Name != nil {
		// Check if new name conflicts with existing group
		if *req.Name != group.Name {
			if existingGroup, err := s.config.DynamicGroupRepo.GetByName(*req.Name); err == nil && existingGroup != nil {
				writeError(w, http.StatusConflict, "Dynamic host group with this name already exists", nil)
				return
			}
		}
		group.Name = *req.Name
	}

	if req.Pattern != nil {
		group.Pattern = *req.Pattern
	}

	if req.ConfigID != nil {
		// Validate config if provided
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
		group.ConfigID = req.ConfigID
	}

	if err := s.config.DynamicGroupRepo.Update(group); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update dynamic host group", err)
		return
	}

	log.Printf("Dynamic host group updated: %s (ID: %d)", group.Name, groupID)

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Dynamic host group updated successfully", map[string]interface{}{
		"group": group,
	}))
}

// deleteDynamicHostGroup deletes a dynamic host group
func (s *Server) deleteDynamicHostGroup(w http.ResponseWriter, r *http.Request) {
	groupIDStr := chi.URLParam(r, "id")

	var groupID uint
	if _, err := fmt.Sscanf(groupIDStr, "%d", &groupID); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	// Get group to verify it exists
	group, err := s.config.DynamicGroupRepo.GetByID(groupID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get dynamic host group", err)
		return
	}

	if group == nil {
		writeError(w, http.StatusNotFound, "Dynamic host group not found", nil)
		return
	}

	if err := s.config.DynamicGroupRepo.Delete(groupID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete dynamic host group", err)
		return
	}

	log.Printf("Dynamic host group deleted: %s (ID: %d)", group.Name, groupID)

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Dynamic host group deleted successfully", nil))
}
