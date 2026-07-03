package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/models"
)

// LoginRequest represents a login request
type LoginRequest struct {
	Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// logout handles user logout
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	// Get session ID from cookie or header
	sessionID := ""
	if cookie, err := r.Cookie("session_id"); err == nil {
		sessionID = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			sessionID = authHeader[7:]
		}
	}

	if sessionID != "" {
		s.config.AuthService.DeleteSession(sessionID)
	}

	// Clear the cookie
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Logged out successfully", nil))
}

// login handles user login
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "Password is required", nil)
		return
	}

	// Validate password
	if !s.config.AuthService.ValidatePassword(req.Password) {
		// Add a small delay to prevent brute force attacks
		time.Sleep(100 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "Invalid password", nil)
		return
	}

	// Create session
	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()
	session := s.config.AuthService.CreateSession("admin", ipAddress, userAgent)

	// Set session cookie
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    session.SessionID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		MaxAge:   int(time.Until(session.ExpiresAt).Seconds()),
		HttpOnly: true,
		Secure:   !s.config.DevMode, // Secure in production
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Return success response with session ID
	response := LoginResponse{
		Success:   true,
		Message:   "Login successful",
		SessionID: session.SessionID,
	}

	writeJSON(w, http.StatusOK, response)
}

// getAuthStatus checks the current authentication status
func (s *Server) getAuthStatus(w http.ResponseWriter, r *http.Request) {
	// Get session ID from cookie or header
	sessionID := ""
	if cookie, err := r.Cookie("session_id"); err == nil {
		sessionID = cookie.Value
	} else {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			sessionID = authHeader[7:]
		}
	}

	if sessionID == "" {
		writeJSON(w, http.StatusOK, models.NewSuccessResponse("Not authenticated", map[string]interface{}{
			"authenticated": false,
		}))
		return
	}

	session := s.config.AuthService.GetSession(sessionID)
	if session == nil {
		writeJSON(w, http.StatusOK, models.NewSuccessResponse("Not authenticated", map[string]interface{}{
			"authenticated": false,
			"message":       "Invalid or expired session",
		}))
		return
	}

	writeJSON(w, http.StatusOK, models.NewSuccessResponse("Authenticated", map[string]interface{}{
		"authenticated": true,
		"username":      session.Username,
		"expires_at":    session.ExpiresAt,
		"ip_address":    session.IPAddress,
	}))
}