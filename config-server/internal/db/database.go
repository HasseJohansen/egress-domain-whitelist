// Package db provides database functionality for the configuration server
package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// Database holds the database connection
type Database struct {
	DB *sql.DB
}

// NewDatabase creates a new database connection
func NewDatabase(dbPath string) (*Database, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Enable foreign keys
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %v", err)
	}

	// Set journal mode to WAL for better performance
	_, err = db.Exec("PRAGMA journal_mode = WAL")
	if err != nil {
		log.Printf("Warning: failed to set journal mode: %v", err)
	}

	return &Database{DB: db}, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.DB.Close()
}

// Initialize creates the database tables
func (d *Database) Initialize() error {
	sqlStmts := []string{
		// Configurations table
		`CREATE TABLE IF NOT EXISTS configurations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			allowed_dns_resolvers TEXT NOT NULL,
			whitelisted_domains TEXT NOT NULL,
			blacklisted_domains TEXT NOT NULL,
			default_ttl INTEGER NOT NULL DEFAULT 300,
			max_ttl INTEGER NOT NULL DEFAULT 86400,
			min_ttl INTEGER NOT NULL DEFAULT 5,
			refresh_interval INTEGER NOT NULL DEFAULT 300,
			restrict_to_allowed_dns INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Hosts table
		`CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT UNIQUE NOT NULL,
			ip_address TEXT NOT NULL,
			last_seen_at TIMESTAMP NOT NULL,
			status TEXT NOT NULL DEFAULT 'unconfigured',
			certificate_fingerprint TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			config_id INTEGER REFERENCES configurations(id) ON DELETE SET NULL
		)`,

		// Host groups table
		`CREATE TABLE IF NOT EXISTS host_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			config_id INTEGER REFERENCES configurations(id) ON DELETE SET NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Dynamic host groups table
		`CREATE TABLE IF NOT EXISTS dynamic_host_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			pattern TEXT NOT NULL,
			config_id INTEGER REFERENCES configurations(id) ON DELETE SET NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Host group members (for static groups)
		`CREATE TABLE IF NOT EXISTS host_group_members (
			host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
			group_id INTEGER NOT NULL REFERENCES host_groups(id) ON DELETE CASCADE,
			PRIMARY KEY (host_id, group_id)
		)`,

		// Indexes for better performance
		`CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname)`,
		`CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status)`,
		`CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen_at)`,
		`CREATE INDEX IF NOT EXISTS idx_hosts_cert ON hosts(certificate_fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_configurations_name ON configurations(name)`,
		`CREATE INDEX IF NOT EXISTS idx_host_groups_name ON host_groups(name)`,
		`CREATE INDEX IF NOT EXISTS idx_host_groups_config ON host_groups(config_id)`,
		`CREATE INDEX IF NOT EXISTS idx_dynamic_host_groups_name ON dynamic_host_groups(name)`,
		`CREATE INDEX IF NOT EXISTS idx_dynamic_host_groups_config ON dynamic_host_groups(config_id)`,
	}

	for _, stmt := range sqlStmts {
		_, err := d.DB.Exec(stmt)
		if err != nil {
			return fmt.Errorf("failed to execute SQL: %v", err)
		}
	}

	return nil
}

// ConfigurationRepository handles configuration database operations
type ConfigurationRepository struct {
	db *Database
}

// NewConfigurationRepository creates a new configuration repository
func NewConfigurationRepository(db *Database) *ConfigurationRepository {
	return &ConfigurationRepository{db: db}
}

// Create creates a new configuration
func (r *ConfigurationRepository) Create(config *models.Configuration) error {
	config.CreatedAt = time.Now()
	config.UpdatedAt = time.Now()

	query := `INSERT INTO configurations (name, allowed_dns_resolvers, whitelisted_domains, blacklisted_domains, default_ttl, max_ttl, min_ttl, refresh_interval, restrict_to_allowed_dns, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.DB.Exec(query,
		config.Name,
		jsonArray(config.AllowedDNSServers),
		jsonArray(config.WhitelistedDomains),
		jsonArray(config.BlacklistedDomains),
		config.DefaultTTL,
		config.MaxTTL,
		config.MinTTL,
		config.RefreshInterval,
		boolToInt(config.RestrictToAllowedDNS),
		config.CreatedAt,
		config.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create configuration: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %v", err)
	}
	config.ID = uint(id)

	return nil
}

// GetByID retrieves a configuration by ID
func (r *ConfigurationRepository) GetByID(id uint) (*models.Configuration, error) {
	query := `SELECT id, name, allowed_dns_resolvers, whitelisted_domains, blacklisted_domains, default_ttl, max_ttl, min_ttl, refresh_interval, restrict_to_allowed_dns, created_at, updated_at 
		FROM configurations WHERE id = ?`

	var config models.Configuration
	var allowedDNSServers, whitelistedDomains, blacklistedDomains string
	var restrictToAllowedDNS int

	err := r.db.DB.QueryRow(query, id).Scan(
		&config.ID,
		&config.Name,
		&allowedDNSServers,
		&whitelistedDomains,
		&blacklistedDomains,
		&config.DefaultTTL,
		&config.MaxTTL,
		&config.MinTTL,
		&config.RefreshInterval,
		&restrictToAllowedDNS,
		&config.CreatedAt,
		&config.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get configuration: %v", err)
	}

	config.AllowedDNSServers = jsonSlice(allowedDNSServers)
	config.WhitelistedDomains = jsonSlice(whitelistedDomains)
	config.BlacklistedDomains = jsonSlice(blacklistedDomains)
	config.RestrictToAllowedDNS = restrictToAllowedDNS != 0

	return &config, nil
}

// GetByName retrieves a configuration by name
func (r *ConfigurationRepository) GetByName(name string) (*models.Configuration, error) {
	query := `SELECT id, name, allowed_dns_resolvers, whitelisted_domains, blacklisted_domains, default_ttl, max_ttl, min_ttl, refresh_interval, restrict_to_allowed_dns, created_at, updated_at 
		FROM configurations WHERE name = ?`

	var config models.Configuration
	var allowedDNSServers, whitelistedDomains, blacklistedDomains string
	var restrictToAllowedDNS int

	err := r.db.DB.QueryRow(query, name).Scan(
		&config.ID,
		&config.Name,
		&allowedDNSServers,
		&whitelistedDomains,
		&blacklistedDomains,
		&config.DefaultTTL,
		&config.MaxTTL,
		&config.MinTTL,
		&config.RefreshInterval,
		&restrictToAllowedDNS,
		&config.CreatedAt,
		&config.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get configuration: %v", err)
	}

	config.AllowedDNSServers = jsonSlice(allowedDNSServers)
	config.WhitelistedDomains = jsonSlice(whitelistedDomains)
	config.BlacklistedDomains = jsonSlice(blacklistedDomains)
	config.RestrictToAllowedDNS = restrictToAllowedDNS != 0

	return &config, nil
}

// List retrieves all configurations
func (r *ConfigurationRepository) List() ([]*models.Configuration, error) {
	query := `SELECT id, name, allowed_dns_resolvers, whitelisted_domains, blacklisted_domains, default_ttl, max_ttl, min_ttl, refresh_interval, restrict_to_allowed_dns, created_at, updated_at 
		FROM configurations ORDER BY name`

	rows, err := r.db.DB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list configurations: %v", err)
	}
	defer rows.Close()

	var configs []*models.Configuration
	for rows.Next() {
		var config models.Configuration
		var allowedDNSServers, whitelistedDomains, blacklistedDomains string
		var restrictToAllowedDNS int

		err := rows.Scan(
			&config.ID,
			&config.Name,
			&allowedDNSServers,
			&whitelistedDomains,
			&blacklistedDomains,
			&config.DefaultTTL,
			&config.MaxTTL,
			&config.MinTTL,
			&config.RefreshInterval,
			&restrictToAllowedDNS,
			&config.CreatedAt,
			&config.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan configuration: %v", err)
		}

		config.AllowedDNSServers = jsonSlice(allowedDNSServers)
		config.WhitelistedDomains = jsonSlice(whitelistedDomains)
		config.BlacklistedDomains = jsonSlice(blacklistedDomains)
		config.RestrictToAllowedDNS = restrictToAllowedDNS != 0

		configs = append(configs, &config)
	}

	return configs, nil
}

// Update updates a configuration
func (r *ConfigurationRepository) Update(config *models.Configuration) error {
	config.UpdatedAt = time.Now()

	query := `UPDATE configurations SET name = ?, allowed_dns_resolvers = ?, whitelisted_domains = ?, blacklisted_domains = ?, default_ttl = ?, max_ttl = ?, min_ttl = ?, refresh_interval = ?, restrict_to_allowed_dns = ?, updated_at = ? 
		WHERE id = ?`

	_, err := r.db.DB.Exec(query,
		config.Name,
		jsonArray(config.AllowedDNSServers),
		jsonArray(config.WhitelistedDomains),
		jsonArray(config.BlacklistedDomains),
		config.DefaultTTL,
		config.MaxTTL,
		config.MinTTL,
		config.RefreshInterval,
		boolToInt(config.RestrictToAllowedDNS),
		config.UpdatedAt,
		config.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update configuration: %v", err)
	}

	return nil
}

// Delete deletes a configuration
func (r *ConfigurationRepository) Delete(id uint) error {
	query := `DELETE FROM configurations WHERE id = ?`
	_, err := r.db.DB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete configuration: %v", err)
	}
	return nil
}

// HostRepository handles host database operations
type HostRepository struct {
	db *Database
}

// NewHostRepository creates a new host repository
func NewHostRepository(db *Database) *HostRepository {
	return &HostRepository{db: db}
}

// Create creates a new host
func (r *HostRepository) Create(host *models.Host) error {
	host.CreatedAt = time.Now()
	host.LastSeenAt = time.Now()

	query := `INSERT INTO hosts (hostname, ip_address, last_seen_at, status, certificate_fingerprint, created_at, config_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.DB.Exec(query,
		host.Hostname,
		host.IPAddress,
		host.LastSeenAt,
		host.Status,
		host.CertificateFingerprint,
		host.CreatedAt,
		host.ConfigID,
	)
	if err != nil {
		return fmt.Errorf("failed to create host: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get last insert id: %v", err)
	}
	host.ID = uint(id)

	return nil
}

// GetByID retrieves a host by ID
func (r *HostRepository) GetByID(id uint) (*models.Host, error) {
	query := `SELECT id, hostname, ip_address, last_seen_at, status, certificate_fingerprint, created_at, config_id 
		FROM hosts WHERE id = ?`

	var host models.Host
	err := r.db.DB.QueryRow(query, id).Scan(
		&host.ID,
		&host.Hostname,
		&host.IPAddress,
		&host.LastSeenAt,
		&host.Status,
		&host.CertificateFingerprint,
		&host.CreatedAt,
		&host.ConfigID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get host: %v", err)
	}

	return &host, nil
}

// GetByHostname retrieves a host by hostname
func (r *HostRepository) GetByHostname(hostname string) (*models.Host, error) {
	query := `SELECT id, hostname, ip_address, last_seen_at, status, certificate_fingerprint, created_at, config_id 
		FROM hosts WHERE hostname = ?`

	var host models.Host
	err := r.db.DB.QueryRow(query, hostname).Scan(
		&host.ID,
		&host.Hostname,
		&host.IPAddress,
		&host.LastSeenAt,
		&host.Status,
		&host.CertificateFingerprint,
		&host.CreatedAt,
		&host.ConfigID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get host: %v", err)
	}

	return &host, nil
}

// GetByCertificateFingerprint retrieves a host by certificate fingerprint
func (r *HostRepository) GetByCertificateFingerprint(fingerprint string) (*models.Host, error) {
	query := `SELECT id, hostname, ip_address, last_seen_at, status, certificate_fingerprint, created_at, config_id 
		FROM hosts WHERE certificate_fingerprint = ?`

	var host models.Host
	err := r.db.DB.QueryRow(query, fingerprint).Scan(
		&host.ID,
		&host.Hostname,
		&host.IPAddress,
		&host.LastSeenAt,
		&host.Status,
		&host.CertificateFingerprint,
		&host.CreatedAt,
		&host.ConfigID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get host: %v", err)
	}

	return &host, nil
}

// List retrieves all hosts
func (r *HostRepository) List() ([]*models.Host, error) {
	query := `SELECT id, hostname, ip_address, last_seen_at, status, certificate_fingerprint, created_at, config_id 
		FROM hosts ORDER BY hostname`

	rows, err := r.db.DB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts: %v", err)
	}
	defer rows.Close()

	var hosts []*models.Host
	for rows.Next() {
		var host models.Host
		err := rows.Scan(
			&host.ID,
			&host.Hostname,
			&host.IPAddress,
			&host.LastSeenAt,
			&host.Status,
			&host.CertificateFingerprint,
			&host.CreatedAt,
			&host.ConfigID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan host: %v", err)
		}
		hosts = append(hosts, &host)
	}

	return hosts, nil
}

// Update updates a host
func (r *HostRepository) Update(host *models.Host) error {
	host.LastSeenAt = time.Now()

	query := `UPDATE hosts SET ip_address = ?, last_seen_at = ?, status = ?, config_id = ? 
		WHERE id = ?`

	_, err := r.db.DB.Exec(query,
		host.IPAddress,
		host.LastSeenAt,
		host.Status,
		host.ConfigID,
		host.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update host: %v", err)
	}

	return nil
}

// Delete deletes a host
func (r *HostRepository) Delete(id uint) error {
	query := `DELETE FROM hosts WHERE id = ?`
	_, err := r.db.DB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete host: %v", err)
	}
	return nil
}

// ListUnconfigured retrieves all unconfigured hosts
func (r *HostRepository) ListUnconfigured() ([]*models.Host, error) {
	query := `SELECT id, hostname, ip_address, last_seen_at, status, certificate_fingerprint, created_at, config_id 
		FROM hosts WHERE status = 'unconfigured' ORDER BY hostname`

	rows, err := r.db.DB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list unconfigured hosts: %v", err)
	}
	defer rows.Close()

	var hosts []*models.Host
	for rows.Next() {
		var host models.Host
		err := rows.Scan(
			&host.ID,
			&host.Hostname,
			&host.IPAddress,
			&host.LastSeenAt,
			&host.Status,
			&host.CertificateFingerprint,
			&host.CreatedAt,
			&host.ConfigID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan host: %v", err)
		}
		hosts = append(hosts, &host)
	}

	return hosts, nil
}

// UpdateLastSeenOlderThan updates the last_seen_at for hosts older than cutoff
func (r *HostRepository) UpdateLastSeenOlderThan(cutoff time.Time) error {
	query := `UPDATE hosts SET last_seen_at = ? WHERE last_seen_at < ?`
	_, err := r.db.DB.Exec(query, cutoff, cutoff)
	if err != nil {
		return fmt.Errorf("failed to update last_seen_at: %v", err)
	}
	return nil
}

// Helper functions for JSON arrays
func jsonArray(slice []string) string {
	if len(slice) == 0 {
		return "[]"
	}
	bytes, _ := json.Marshal(slice)
	return string(bytes)
}

func jsonSlice(jsonStr string) []string {
	if jsonStr == "" || jsonStr == "[]" {
		return []string{}
	}
	var slice []string
	json.Unmarshal([]byte(jsonStr), &slice)
	return slice
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
