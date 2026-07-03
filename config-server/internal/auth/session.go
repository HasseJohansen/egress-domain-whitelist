// Package auth provides session management for the configuration server
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session represents an authenticated session
type Session struct {
	SessionID    string    `json:"session_id"`
	Username    string    `json:"username"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
}

// SessionStore manages active sessions
type SessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	Timeout  time.Duration
}

// NewSessionStore creates a new session store
func NewSessionStore(timeout time.Duration) *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		Timeout:  timeout,
	}
}

// CreateSession creates a new session
func (s *SessionStore) CreateSession(username, ipAddress, userAgent string) *Session {
	sessionID := s.generateSessionID()
	
	session := &Session{
		SessionID:  sessionID,
		Username:   username,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(s.Timeout),
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	return session
}

// GetSession retrieves a session by ID
func (s *SessionStore) GetSession(sessionID string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		return nil
	}

	return session
}

// DeleteSession deletes a session by ID
func (s *SessionStore) DeleteSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// InvalidateAllSessions invalidates all active sessions
func (s *SessionStore) InvalidateAllSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]*Session)
}

// CleanupExpiredSessions removes all expired sessions
func (s *SessionStore) CleanupExpiredSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for sessionID, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, sessionID)
		}
	}
}

// generateSessionID generates a cryptographically secure session ID
func (s *SessionStore) generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to less secure method if crypto/rand fails
		b = []byte(time.Now().Format("2006-01-02 15:04:05.999999999"))
	}
	return hex.EncodeToString(b)
}

// StartCleanup starts a background goroutine to cleanup expired sessions
func (s *SessionStore) StartCleanup() {
	go func() {
		ticker := time.NewTicker(s.Timeout / 2)
		defer ticker.Stop()
		for range ticker.C {
			s.CleanupExpiredSessions()
		}
	}()
}

// AuthConfigWithPassword extends AuthConfig with password authentication
type AuthConfigWithPassword struct {
	*AuthConfig
	Password string
	SessionTimeout time.Duration
}

// AuthServiceWithPassword extends AuthService with password authentication
type AuthServiceWithPassword struct {
	*AuthService
	password    string
	sessionStore *SessionStore
}

// NewAuthServiceWithPassword creates a new authentication service with password support
func NewAuthServiceWithPassword(config *AuthConfigWithPassword) (*AuthServiceWithPassword, error) {
	// Create base auth service
	baseService, err := NewAuthService(config.AuthConfig)
	if err != nil {
		return nil, err
	}

	as := &AuthServiceWithPassword{
		AuthService: baseService,
		password:    config.Password,
		sessionStore: NewSessionStore(config.SessionTimeout),
	}

	// Start session cleanup
	as.sessionStore.StartCleanup()

	return as, nil
}

// ValidatePassword validates the provided password
func (a *AuthServiceWithPassword) ValidatePassword(password string) bool {
	// Use constant-time comparison to prevent timing attacks
	return constantTimeCompare(a.password, password)
}

// CreateSession creates a new session after successful authentication
func (a *AuthServiceWithPassword) CreateSession(username, ipAddress, userAgent string) *Session {
	return a.sessionStore.CreateSession(username, ipAddress, userAgent)
}

// GetSession retrieves a session by ID
func (a *AuthServiceWithPassword) GetSession(sessionID string) *Session {
	return a.sessionStore.GetSession(sessionID)
}

// DeleteSession deletes a session by ID
func (a *AuthServiceWithPassword) DeleteSession(sessionID string) {
	a.sessionStore.DeleteSession(sessionID)
}

// InvalidateAllSessions invalidates all active sessions
func (a *AuthServiceWithPassword) InvalidateAllSessions() {
	a.sessionStore.InvalidateAllSessions()
}

// constantTimeCompare performs a constant-time string comparison
func constantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i] ^ b[i])
	}
	return result == 0
}

// SetPassword sets a new password (for changing password at runtime)
func (a *AuthServiceWithPassword) SetPassword(password string) {
	a.password = password
}