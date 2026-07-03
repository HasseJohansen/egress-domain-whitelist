// Package config provides configuration client for connecting to config server
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ConfigClient handles communication with the configuration server
type ConfigClient struct {
	ServerURL    string
	Hostname     string
	HostID       uint
	Certificate  string // Path to client certificate
	Key          string // Path to client key
	CACertificate string // Path to CA certificate
	DevMode      bool
	
	// Connection management
	wsConn     *websocket.Conn
	httpClient *http.Client
	connected  bool
	mu         sync.RWMutex
	
	// Callbacks
	onConfigUpdate func(*LocalEgressConfig) error
	onConnect      func()
	onDisconnect   func()
	onError        func(error)
	
	// Reconnection
	stopChan    chan struct{}
	reconnectChan chan struct{}
}

// NewConfigClient creates a new configuration client
func NewConfigClient(serverURL, hostname string, onConfigUpdate func(*LocalEgressConfig) error) (*ConfigClient, error) {
	// Validate server URL
	if serverURL == "" {
		return nil, fmt.Errorf("server URL is required")
	}

	// Ensure server URL ends with / or add it
	if !strings.HasSuffix(serverURL, "/") {
		serverURL += "/"
	}

	// Get hostname if not provided
	if hostname == "" {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname: %v", err)
		}
	}

	client := &ConfigClient{
		ServerURL:      serverURL,
		Hostname:       hostname,
		DevMode:        false,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		onConfigUpdate: onConfigUpdate,
		stopChan:       make(chan struct{}),
		reconnectChan:  make(chan struct{}, 1),
	}

	return client, nil
}

// Connect connects to the configuration server
func (c *ConfigClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil // Already connected
	}

	// Try to register first to get host ID
	if err := c.registerHost(); err != nil {
		return fmt.Errorf("failed to register host: %v", err)
	}

	// Connect WebSocket
	if err := c.connectWebSocket(); err != nil {
		return fmt.Errorf("failed to connect WebSocket: %v", err)
	}

	c.connected = true
	if c.onConnect != nil {
		c.onConnect()
	}
	
	log.Printf("Connected to config server at %s (host: %s, id: %d)", 
		c.ServerURL, c.Hostname, c.HostID)

	// Start keepalive and reconnection goroutines
	go c.keepalive()
	go c.monitorConnection()

	return nil
}

// Disconnect disconnects from the configuration server
func (c *ConfigClient) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return
	}

	close(c.stopChan)
	
	if c.wsConn != nil {
		c.wsConn.Close()
		c.wsConn = nil
	}

	c.connected = false
	if c.onDisconnect != nil {
		c.onDisconnect()
	}
	
	log.Printf("Disconnected from config server")
}

// registerHost registers the host with the configuration server
func (c *ConfigClient) registerHost() error {
	// Prepare registration data
	regData := map[string]interface{}{
		"hostname":       c.Hostname,
		"ip_address":     getLocalIP(),
		"status":         "unconfigured",
	}

	// If we already have a certificate fingerprint, include it
	if c.Certificate != "" {
		// In production, compute certificate fingerprint
		// For now, use hostname as placeholder
		regData["certificate_fingerprint"] = fmt.Sprintf("placeholder-%s", c.Hostname)
	}

	// Send registration request
	url := fmt.Sprintf("%sapi/v1/hosts/register", c.ServerURL)
	jsonData, err := json.Marshal(regData)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	// Extract host ID
	if hostIDFloat, ok := response["data"].(map[string]interface{})["id"].(float64); ok {
		c.HostID = uint(hostIDFloat)
		log.Printf("Host registered with ID: %d", c.HostID)
		return nil
	}

	return fmt.Errorf("no host ID in registration response")
}

// connectWebSocket establishes a WebSocket connection to the server
func (c *ConfigClient) connectWebSocket() error {
	// Build WebSocket URL
	wsURL := fmt.Sprintf("%sapi/v1/events?hostname=%s&host_id=%d", 
		strings.Replace(c.ServerURL, "http://", "ws://", 1),
		url.QueryEscape(c.Hostname),
		c.HostID)

	// Create dialer
	dialer := websocket.Dialer{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig:   nil, // In production, set TLS config with client certs
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins in development
		},
	}

	// Connect
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return err
	}

	c.wsConn = conn

	// Set ping/pong handlers
	conn.SetPingHandler(func(appData string) error {
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(60*time.Second))
	})
	conn.SetPongHandler(func(appData string) error {
		// Pong received, connection is alive
		return nil
	})

	// Start message handler
	go c.handleWebSocketMessages()

	// Send registration message
	regMsg := map[string]interface{}{
		"type":      "register_host",
		"hostname":  c.Hostname,
		"host_id":   c.HostID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	if err := conn.WriteJSON(regMsg); err != nil {
		log.Printf("Warning: failed to send registration message: %v", err)
	}

	return nil
}

// handleWebSocketMessages handles incoming WebSocket messages
func (c *ConfigClient) handleWebSocketMessages() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("WebSocket message handler panic: %v", r)
		}
	}()

	for {
		select {
		case <-c.stopChan:
			return
		default:
			// Read message
			_, message, err := c.wsConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket error: %v", err)
				}
				// Trigger reconnection
				c.triggerReconnect()
				return
			}

			// Process message
			var msg map[string]interface{}
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Printf("Warning: failed to parse WebSocket message: %v", err)
				continue
			}

			// Handle different message types
			if msgType, ok := msg["type"].(string); ok {
				switch msgType {
				case "configuration_update":
					if config, ok := msg["configuration"].(map[string]interface{}); ok {
						c.handleConfigurationUpdate(config)
					}
				case "pong":
					// Pong response, ignore
				case "host_status_update":
					// Status update from another host, ignore for now
				default:
					log.Printf("Warning: unknown message type: %s", msgType)
				}
			}
		}
	}
}

// handleConfigurationUpdate handles a configuration update message
func (c *ConfigClient) handleConfigurationUpdate(config map[string]interface{}) {
	log.Printf("Received configuration update from server")

	// Convert to local config
	localConfig := convertToLocalConfig(config)
	if localConfig == nil {
		log.Printf("Error: failed to convert server config to local config")
		if c.onError != nil {
			c.onError(fmt.Errorf("failed to convert configuration"))
		}
		return
	}

	// Log the received configuration
	log.Printf("Configuration update received:")
	log.Printf("  Allowed DNS Servers: %v", localConfig.AllowedDNSServers)
	log.Printf("  Whitelisted Domains: %v", localConfig.WhitelistedDomains)
	log.Printf("  Blacklisted Domains: %v", localConfig.BlacklistedDomains)
	log.Printf("  Default TTL: %d", localConfig.DefaultTTL)
	log.Printf("  Max TTL: %d", localConfig.MaxTTL)
	log.Printf("  Min TTL: %d", localConfig.MinTTL)

	// Apply the configuration
	if c.onConfigUpdate != nil {
		if err := c.onConfigUpdate(localConfig); err != nil {
			log.Printf("Error applying configuration: %v", err)
			if c.onError != nil {
				c.onError(err)
			}
			return
		}
	}

	log.Printf("Configuration update applied successfully")
}

// triggerReconnect triggers a reconnection attempt
func (c *ConfigClient) triggerReconnect() {
	select {
	case c.reconnectChan <- struct{}{}:
	default:
		// Reconnect already triggered
	}
}

// monitorConnection monitors the connection and handles reconnection
func (c *ConfigClient) monitorConnection() {
	for {
		select {
		case <-c.stopChan:
			return
		case <-c.reconnectChan:
			// Wait a bit before reconnecting
			time.Sleep(5 * time.Second)
			
			// Try to reconnect
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			
			if err := c.Connect(); err != nil {
				log.Printf("Reconnection failed: %v, will retry...", err)
				if c.onError != nil {
					c.onError(err)
				}
				// Trigger another reconnect
				c.triggerReconnect()
			}
		}
	}
}

// keepalive sends periodic keepalive messages
func (c *ConfigClient) keepalive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.mu.RLock()
			if c.wsConn != nil && c.connected {
				if err := c.wsConn.WriteJSON(map[string]interface{}{
					"type":      "ping",
					"host_id":   c.HostID,
					"hostname":  c.Hostname,
					"timestamp": time.Now().UTC().Format(time.RFC3339),
				}); err != nil {
					log.Printf("Warning: failed to send keepalive: %v", err)
					c.triggerReconnect()
				}
			}
			c.mu.RUnlock()
		}
	}
}

// GetConfiguration fetches the current configuration from the server
func (c *ConfigClient) GetConfiguration() (*LocalEgressConfig, error) {
	// Check if we have a host ID
	if c.HostID == 0 {
		if err := c.registerHost(); err != nil {
			return nil, err
		}
	}

	// Fetch configuration
	url := fmt.Sprintf("%sapi/v1/hosts/%d/config", c.ServerURL, c.HostID)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get configuration: %s - %s", resp.Status, string(body))
	}

	// Parse response
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	// Extract configuration
	if data, ok := response["data"].(map[string]interface{}); ok {
		localConfig := convertToLocalConfig(data)
		if localConfig != nil {
			return localConfig, nil
		}
	}

	return nil, fmt.Errorf("no configuration in response")
}

// PollConfiguration periodically fetches configuration from the server
func (c *ConfigClient) PollConfiguration(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopChan:
				return
			case <-ticker.C:
				if config, err := c.GetConfiguration(); err != nil {
					log.Printf("Warning: failed to poll configuration: %v", err)
					if c.onError != nil {
						c.onError(err)
					}
				} else if config != nil && c.onConfigUpdate != nil {
					log.Printf("Configuration update received via polling")
					if err := c.onConfigUpdate(config); err != nil {
						log.Printf("Error applying polled configuration: %v", err)
						if c.onError != nil {
							c.onError(err)
						}
					}
				}
			}
		}
	}()
}

// IsConnected returns whether the client is connected to the server
func (c *ConfigClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// GetHostID returns the host ID assigned by the server
func (c *ConfigClient) GetHostID() uint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.HostID
}

// SetCallbacks sets the callback functions
func (c *ConfigClient) SetCallbacks(
	onConnect func(),
	onDisconnect func(),
	onError func(error),
) {
	c.onConnect = onConnect
	c.onDisconnect = onDisconnect
	c.onError = onError
}

// getLocalIP returns the local IP address
func getLocalIP() string {
	// Try to get the first non-loopback IP address
	// This is a simplified version
	return "127.0.0.1" // Placeholder
}

// SetTLSConfig sets the TLS configuration for the HTTP client
func (c *ConfigClient) SetTLSConfig(certFile, keyFile, caCertFile string) {
	// In production, configure TLS with client certificates
	// For now, just store the paths
	c.Certificate = certFile
	c.Key = keyFile
	c.CACertificate = caCertFile
}
