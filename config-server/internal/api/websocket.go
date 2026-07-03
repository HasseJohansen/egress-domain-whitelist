package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Client represents a WebSocket client
type Client struct {
	Hub  *Hub
	Conn *websocket.Conn
	Send chan []byte
	// Host information
	HostID   uint
	Hostname string
	// Authentication
	SessionID   string
	Authenticated bool
	IsHost      bool // True if this is a host agent connection (vs web interface)
}

// Hub maintains the set of active clients and broadcasts messages to the clients
type Hub struct {
	Clients      map[*Client]bool
	Broadcast    chan []byte
	Register     chan *Client
	Unregister   chan *Client
	Mu           sync.RWMutex
	PingInterval time.Duration
	PongWait    time.Duration
	// Host to client mapping
	HostClients map[uint]*Client
}

// NewHub creates a new Hub
func NewHub(pingInterval, pongWait time.Duration) *Hub {
	return &Hub{
		Clients:      make(map[*Client]bool),
		Broadcast:    make(chan []byte, 256),
		Register:     make(chan *Client),
		Unregister:   make(chan *Client),
		HostClients:   make(map[uint]*Client),
		PingInterval: pingInterval,
		PongWait:    pongWait,
	}
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.Mu.Lock()
			h.Clients[client] = true
			if client.HostID > 0 {
				h.HostClients[client.HostID] = client
			}
			h.Mu.Unlock()
			log.Printf("WebSocket: Client registered (host: %s, id: %d)", client.Hostname, client.HostID)

		case client := <-h.Unregister:
			h.Mu.Lock()
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client.Send)
			}
			if client.HostID > 0 {
				delete(h.HostClients, client.HostID)
			}
			h.Mu.Unlock()
			log.Printf("WebSocket: Client unregistered (host: %s, id: %d)", client.Hostname, client.HostID)

		case message := <-h.Broadcast:
			h.Mu.RLock()
			for client := range h.Clients {
				select {
				case client.Send <- message:
				default:
					// Client buffer full, close connection
					close(client.Send)
					delete(h.Clients, client)
					if client.HostID > 0 {
						delete(h.HostClients, client.HostID)
					}
				}
			}
			h.Mu.RUnlock()
		}
	}
}

// SendToHost sends a message to a specific host by ID
func (h *Hub) SendToHost(hostID uint, message []byte) bool {
	h.Mu.RLock()
	client, exists := h.HostClients[hostID]
	h.Mu.RUnlock()

	if exists {
		select {
		case client.Send <- message:
			return true
		default:
			// Buffer full, client might be disconnected
			return false
		}
	}
	return false
}

// SendToAll sends a message to all connected clients
func (h *Hub) SendToAll(message []byte) {
	h.Broadcast <- message
}

// BroadcastConfigurationUpdate sends a configuration update to a specific host
func (h *Hub) BroadcastConfigurationUpdate(hostID uint, configID uint) bool {
	message, err := json.Marshal(map[string]interface{}{
		"type":         "configuration_update",
		"configuration_id": configID,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("Error marshaling configuration update: %v", err)
		return false
	}
	return h.SendToHost(hostID, message)
}

// SendConfiguration sends a full configuration object to a specific host
func (h *Hub) SendConfiguration(hostID uint, config interface{}) bool {
	message, err := json.Marshal(map[string]interface{}{
		"type":         "configuration_update",
		"configuration": config,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("Error marshaling configuration: %v", err)
		return false
	}
	return h.SendToHost(hostID, message)
}

// BroadcastHostStatusUpdate sends a host status update to the dashboard
func (h *Hub) BroadcastHostStatusUpdate(hostID uint, status string) {
	message, err := json.Marshal(map[string]interface{}{
		"type":     "host_status_update",
		"host_id":  hostID,
		"status":   status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("Error marshaling host status update: %v", err)
		return
	}
	h.Broadcast <- message
}

// Upgrader for WebSocket connections
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in development
	},
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Try session-based authentication first (for web interface)
	sessionID := ""
	if cookie, err := r.Cookie("session_id"); err == nil {
		sessionID = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			sessionID = authHeader[7:]
		}
	}

	// Try host-based authentication (for host agents)
	var isHostAuth bool
	var hostID uint
	var hostname string

	// Extract host information from query parameters or headers
	hostname = r.Header.Get("X-Host-Name")
	if hostname == "" {
		hostname = r.URL.Query().Get("hostname")
	}

	// Try to get host ID from header or query
	if hostIDStr := r.Header.Get("X-Host-ID"); hostIDStr != "" {
		if id, err := strconv.ParseUint(hostIDStr, 10, 32); err == nil {
			hostID = uint(id)
		}
	}
	if hostID == 0 {
		if hostIDStr := r.URL.Query().Get("host_id"); hostIDStr != "" {
			if id, err := strconv.ParseUint(hostIDStr, 10, 32); err == nil {
				hostID = uint(id)
			}
		}
	}

	// If we have host info, try host authentication
	if hostname != "" || hostID > 0 {
		isHostAuth = true
		
		// Validate host exists in database
		if hostID > 0 {
			// Try to get host by ID
			host, err := s.config.HostRepo.GetByID(hostID)
			if err != nil {
				log.Printf("Error validating host by ID: %v", err)
				writeError(w, http.StatusUnauthorized, "Invalid host credentials", nil)
				return
			}
			if host == nil || host.Hostname != hostname {
				writeError(w, http.StatusUnauthorized, "Invalid host credentials", nil)
				return
			}
		} else if hostname != "" {
			// Try to get host by hostname
			host, err := s.config.HostRepo.GetByHostname(hostname)
			if err != nil {
				log.Printf("Error validating host by hostname: %v", err)
				writeError(w, http.StatusUnauthorized, "Invalid host credentials", nil)
				return
			}
			if host == nil {
				writeError(w, http.StatusUnauthorized, "Invalid host credentials", nil)
				return
			}
			hostID = host.ID
		}
		
		// Host authentication successful
	} else {
		// Fall back to session authentication
		isHostAuth = false
		
		if sessionID == "" {
			writeError(w, http.StatusUnauthorized, "Authentication required", nil)
			return
		}

		// Validate session
		session := s.config.AuthService.GetSession(sessionID)
		if session == nil {
			writeError(w, http.StatusUnauthorized, "Invalid or expired session", nil)
			return
		}
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	// Create client
	client := &Client{
		Hub:         s.hub,
		Conn:        conn,
		Send:        make(chan []byte, 256),
		HostID:      hostID,
		Hostname:    hostname,
		SessionID:   sessionID,
		Authenticated: true,
		IsHost:      isHostAuth,
	}

	// Register client
	client.Hub.Register <- client

	// Configure connection settings
	// Set ping/pong handlers
	conn.SetPingHandler(func(appData string) error {
		// Handle ping - send pong
		return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(60*time.Second))
	})
	conn.SetPongHandler(func(appData string) error {
		// Handle pong
		return nil
	})

	// Start goroutines for reading and writing
	go client.writePump()
	go client.readPump()
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.Hub.Unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(512)
	c.Conn.SetReadDeadline(time.Now().Add(c.Hub.PongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(c.Hub.PongWait))
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Process message
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err == nil {
			if msgType, ok := msg["type"].(string); ok {
				switch msgType {
				case "ping":
					// Handle ping
					c.Send <- []byte(`{"type":"pong"}`)
				case "register_host":
					// Handle host registration
					if hostname, ok := msg["hostname"].(string); ok {
						c.Hostname = hostname
					}
					if hostIDFloat, ok := msg["host_id"].(float64); ok {
						c.HostID = uint(hostIDFloat)
						c.Hub.Mu.Lock()
						c.Hub.HostClients[c.HostID] = c
						c.Hub.Mu.Unlock()
					}
				case "status_update":
					// Handle status update from host
					if status, ok := msg["status"].(string); ok {
						c.Hub.BroadcastHostStatusUpdate(c.HostID, status)
					}
				}
			}
		}
	}
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(c.Hub.PingInterval)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(c.Hub.PongWait))
			if !ok {
				// Hub closed the channel
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current WebSocket message
			n := len(c.Send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.Send)
			}

			if err := w.Close(); err != nil {
				return
			}

			case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}


