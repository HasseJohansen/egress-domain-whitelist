// Main package for the host agent
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/config"
	"github.com/HasseJohansen/egress-domain-whitelist/host-agent/internal/ebpf"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "./host-agent.yaml", "Path to configuration file")
	serverURL := flag.String("server", "", "Config server URL (overrides config file)")
	password := flag.String("password", "", "Config server password for host registration")
	devMode := flag.Bool("dev", false, "Run in development mode")
	standalone := flag.Bool("standalone", false, "Run in standalone mode (no config server)")
	flag.Parse()

	// Load configuration
	hostConfig, err := config.LoadHostAgentConfig(*configPath)
	if err != nil {
		log.Printf("Warning: failed to load config file, using defaults: %v", err)
		hostConfig = config.DefaultHostAgentConfig()
	}

	// Override with command line flags
	if *serverURL != "" {
		hostConfig.ConfigServerURL = *serverURL
		hostConfig.ServerURL = *serverURL
	}
	if *password != "" {
		// Store password for registration
		os.Setenv("HOST_AGENT_PASSWORD", *password)
	}
	if *devMode {
		hostConfig.DevMode = true
	}
	if *standalone {
		hostConfig.ManagedMode = false
	}

	// Validate configuration
	if err := validateConfig(hostConfig); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Display configuration
	log.Printf("Starting host agent with configuration:")
	log.Printf("  Hostname: %s", hostConfig.Hostname)
	log.Printf("  Config Server: %s", hostConfig.ConfigServerURL)
	log.Printf("  Managed Mode: %v", hostConfig.ManagedMode)
	log.Printf("  Dev Mode: %v", hostConfig.DevMode)

	// Initialize eBPF manager
	ebpfManager, err := ebpf.NewHostAgentEBPFManager(hostConfig)
	if err != nil {
		log.Printf("Warning: failed to initialize eBPF manager: %v", err)
		// Continue without eBPF - might be using iptables or just DNS mode
	}
	defer ebpfManager.Close()

	// Start the appropriate mode
	if hostConfig.ManagedMode && hostConfig.ConfigServerURL != "" {
		// Managed mode - connect to config server
		if err := runManagedMode(hostConfig, ebpfManager); err != nil {
			log.Fatalf("Managed mode failed: %v", err)
		}
	} else {
		// Standalone mode - use local configuration
		if err := runStandaloneMode(hostConfig, ebpfManager); err != nil {
			log.Fatalf("Standalone mode failed: %v", err)
		}
	}

	// Wait for shutdown
	waitForShutdown()
}

// validateConfig validates the host agent configuration
func validateConfig(config *config.HostAgentConfig) error {
	if config.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}

	// If managed mode, server URL is required
	if config.ManagedMode && config.ConfigServerURL == "" {
		return fmt.Errorf("config server URL is required in managed mode")
	}

	return nil
}

// runManagedMode runs the agent in managed mode
func runManagedMode(hostConfig *config.HostAgentConfig, ebpfManager *ebpf.HostAgentEBPFManager) error {
	log.Printf("Running in managed mode - connecting to config server at %s", hostConfig.ConfigServerURL)
	
	// TODO: Implement managed mode
	// 1. Register with config server
	// 2. Get initial configuration
	// 3. Apply configuration to eBPF
	// 4. Start polling/websockets for updates
	// 5. Update eBPF maps when config changes
	
	log.Printf("Managed mode not yet implemented - running with placeholder")
	
	// For now, just apply local config as fallback
	return runStandaloneMode(hostConfig, ebpfManager)
}

// runStandaloneMode runs the agent in standalone mode
func runStandaloneMode(hostConfig *config.HostAgentConfig, ebpfManager *ebpf.HostAgentEBPFManager) error {
	log.Printf("Running in standalone mode")
	
	if hostConfig.LocalConfig == nil {
		return fmt.Errorf("local config is required in standalone mode")
	}

	// Apply local configuration to eBPF
	if err := ebpfManager.ApplyConfig(hostConfig.LocalConfig); err != nil {
		return fmt.Errorf("failed to apply local config to eBPF: %v", err)
	}

	// Start monitoring for changes (though in standalone mode, config doesn't change)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		for range ticker.C {
			// In standalone mode, we could reload config from file if it changes
			// For now, just log
			log.Printf("Standalone mode - checking for config updates...")
		}
	}()

	log.Printf("Standalone mode started successfully")
	return nil
}

func waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutting down host agent...")
}
