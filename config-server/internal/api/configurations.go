package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/models"
	"github.com/go-chi/chi/v5"
)

// listConfigurations lists all configurations
func (s *Server) listConfigurations(w http.ResponseWriter, r *http.Request) {
	configs, err := s.config.ConfigRepo.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list configurations", err)
		return
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Configurations listed successfully", configs))
}

// createConfiguration creates a new configuration
func (s *Server) createConfiguration(w http.ResponseWriter, r *http.Request) {
	var config models.Configuration
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate configuration
	if config.Name == "" {
		writeError(w, http.StatusBadRequest, "Configuration name is required", nil)
		return
	}

	// Set default values
	if config.DefaultTTL == 0 {
		config.DefaultTTL = 300
	}
	if config.MaxTTL == 0 {
		config.MaxTTL = 86400
	}
	if config.MinTTL == 0 {
		config.MinTTL = 5
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 300
	}

	if err := s.config.ConfigRepo.Create(&config); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create configuration", err)
		return
	}

	writeJSON(w, http.StatusCreated, models.NewSuccessResponse("Configuration created successfully", config))
}

// getConfiguration retrieves a configuration by ID
func (s *Server) getConfiguration(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid configuration ID", err)
		return
	}

	config, err := s.config.ConfigRepo.GetByID(uint(id))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get configuration", err)
		return
	}
	if config == nil {
		writeError(w, http.StatusNotFound, "Configuration not found", nil)
		return
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Configuration retrieved successfully", config))
}

// updateConfiguration updates a configuration
func (s *Server) updateConfiguration(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid configuration ID", err)
		return
	}

	config, err := s.config.ConfigRepo.GetByID(uint(id))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get configuration", err)
		return
	}
	if config == nil {
		writeError(w, http.StatusNotFound, "Configuration not found", nil)
		return
	}

	var update models.Configuration
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Update fields
	if update.Name != "" {
		config.Name = update.Name
	}
	if update.AllowedDNSServers != nil {
		config.AllowedDNSServers = update.AllowedDNSServers
	}
	if update.WhitelistedDomains != nil {
		config.WhitelistedDomains = update.WhitelistedDomains
	}
	if update.BlacklistedDomains != nil {
		config.BlacklistedDomains = update.BlacklistedDomains
	}
	if update.DefaultTTL != 0 {
		config.DefaultTTL = update.DefaultTTL
	}
	if update.MaxTTL != 0 {
		config.MaxTTL = update.MaxTTL
	}
	if update.MinTTL != 0 {
		config.MinTTL = update.MinTTL
	}
	if update.RefreshInterval != 0 {
		config.RefreshInterval = update.RefreshInterval
	}
	config.RestrictToAllowedDNS = update.RestrictToAllowedDNS

	if err := s.config.ConfigRepo.Update(config); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to update configuration", err)
		return
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Configuration updated successfully", config))
}

// deleteConfiguration deletes a configuration
func (s *Server) deleteConfiguration(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid configuration ID", err)
		return
	}

	if err := s.config.ConfigRepo.Delete(uint(id)); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to delete configuration", err)
		return
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Configuration deleted successfully", nil))
}