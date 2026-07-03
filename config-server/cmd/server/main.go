// Main package for the configuration server
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/api"
	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/auth"
	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/config"
	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/db"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "./config-server.yaml", "Path to configuration file")
	dbPath := flag.String("db", "./data/config-server.db", "Path to SQLite database")
	port := flag.Int("port", 8443, "Server port")
	devMode := flag.Bool("dev", false, "Run in development mode (HTTP, no TLS)")
	password := flag.String("password", "", "Web interface password (required)")
	sessionTimeout := flag.Int("session-timeout", 30, "Session timeout in minutes")
	flag.Parse()

	// Load configuration
	serverConfig, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Printf("Warning: failed to load config file, using defaults: %v", err)
		serverConfig = config.DefaultServerConfig()
	}

	// Override with command line flags
	if *port != 8443 {
		serverConfig.Port = *port
	}
	if *dbPath != "./data/config-server.db" {
		serverConfig.DatabasePath = *dbPath
	}
	if *password != "" {
		serverConfig.Password = *password
	}
	if *sessionTimeout != 30 {
		serverConfig.SessionTimeout = *sessionTimeout
	}

	// Initialize database
	log.Printf("Initializing database at %s", serverConfig.DatabasePath)
	database, err := db.NewDatabase(serverConfig.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	if err := database.Initialize(); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// Initialize repositories
	configRepo := db.NewConfigurationRepository(database)
	hostRepo := db.NewHostRepository(database)
	groupRepo := db.NewHostGroupRepository(database)
	dynamicGroupRepo := db.NewDynamicHostGroupRepository(database)

	// Check that password is set
	if serverConfig.Password == "" {
		log.Fatal("Error: Password is required. Use --password flag or set in config file.")
	}

	// Initialize authentication with password
	authService, err := auth.NewAuthServiceWithPassword(&auth.AuthConfigWithPassword{
		AuthConfig: &auth.AuthConfig{
			CertFile:       serverConfig.CertFile,
			KeyFile:        serverConfig.KeyFile,
			CACertFile:     serverConfig.CACertFile,
			DevMode:        *devMode || serverConfig.DevMode,
			AllowedSubnets: serverConfig.AllowedSubnets,
		},
		Password:     serverConfig.Password,
		SessionTimeout: time.Duration(serverConfig.SessionTimeout) * time.Minute,
	})
	if err != nil {
		log.Fatalf("Failed to initialize authentication: %v", err)
	}

	log.Printf("Web interface authentication enabled. Session timeout: %d minutes", serverConfig.SessionTimeout)

	// Create API server
	apiServer, err := api.NewServer(&api.ServerConfig{
		ConfigRepo:         configRepo,
		HostRepo:           hostRepo,
		GroupRepo:         groupRepo,
		DynamicGroupRepo:  dynamicGroupRepo,
		AuthService:        authService,
		Port:              serverConfig.Port,
		DevMode:           *devMode || serverConfig.DevMode,
	})
	if err != nil {
		log.Fatalf("Failed to create API server: %v", err)
	}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			// Clean up old hosts that haven't been seen in a while
			cutoff := time.Now().Add(-24 * time.Hour)
			if err := hostRepo.UpdateLastSeenOlderThan(cutoff); err != nil {
				log.Printf("Error during host cleanup: %v", err)
			}
		}
	}()

	// Start server
	log.Printf("Starting configuration server on port %d", serverConfig.Port)
	log.Printf("Dev mode: %v", *devMode || serverConfig.DevMode)
	log.Printf("Database: %s", serverConfig.DatabasePath)

	if *devMode || serverConfig.DevMode {
		log.Printf("Running in development mode (HTTP)")
		if err := http.ListenAndServe(fmt.Sprintf(":%d", serverConfig.Port), apiServer.Handler()); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	} else {
		// Production mode with HTTPS
		log.Printf("Running in production mode (HTTPS)")
		if err := http.ListenAndServeTLS(
			fmt.Sprintf(":%d", serverConfig.Port),
			serverConfig.CertFile,
			serverConfig.KeyFile,
			apiServer.Handler(),
		); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}

	// This line is never reached, but we need it for the signal handling
	waitForShutdown()
}

func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down...")
}
