// Package api provides the REST API server for the configuration server
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/auth"
	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/db"
	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/models"
	"github.com/HasseJohansen/egress-domain-whitelist/config-server/internal/web"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// ServerConfig holds the configuration for the API server
type ServerConfig struct {
	ConfigRepo      *db.ConfigurationRepository
	HostRepo        *db.HostRepository
	AuthService     *auth.AuthServiceWithPassword
	Port           int
	DevMode        bool
	SessionTimeout time.Duration
}

// Server represents the API server
type Server struct {
	config *ServerConfig
	router *chi.Mux
}

// NewServer creates a new API server
func NewServer(config *ServerConfig) (*Server, error) {
	s := &Server{
		config: config,
		router: chi.NewRouter(),
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s, nil
}

// setupMiddleware sets up HTTP middleware
func (s *Server) setupMiddleware() {
	// Recovery middleware
	s.router.Use(middleware.Recoverer)

	// Request ID middleware
	s.router.Use(middleware.RequestID)

	// Logger middleware
	s.router.Use(middleware.Logger)

	// CORS middleware
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})
	s.router.Use(corsMiddleware.Handler)

	// Custom authentication middleware
	s.router.Use(s.authMiddleware)
}

// setupRoutes sets up the API routes
func (s *Server) setupRoutes() {
	// API v1 routes
	s.router.Route("/api/v1", func(r chi.Router) {
		// Configuration endpoints
		r.Route("/configurations", func(r chi.Router) {
			r.Get("/", s.listConfigurations)
			r.Post("/", s.createConfiguration)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", s.getConfiguration)
				r.Put("/", s.updateConfiguration)
				r.Delete("/", s.deleteConfiguration)
			})
		})

		// Host endpoints
		r.Route("/hosts", func(r chi.Router) {
			r.Get("/", s.listHosts)
			r.Post("/register", s.registerHost)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", s.getHost)
				r.Put("/", s.updateHost)
				r.Delete("/", s.deleteHost)
				r.Get("/config", s.getHostConfiguration)
			})
		})

		// Host group endpoints
		r.Route("/host-groups", func(r chi.Router) {
			r.Get("/", s.listHostGroups)
			r.Post("/", s.createHostGroup)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", s.getHostGroup)
				r.Put("/", s.updateHostGroup)
				r.Delete("/", s.deleteHostGroup)
			})
		})

		// Dynamic host group endpoints
		r.Route("/dynamic-host-groups", func(r chi.Router) {
			r.Get("/", s.listDynamicHostGroups)
			r.Post("/", s.createDynamicHostGroup)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", s.getDynamicHostGroup)
				r.Put("/", s.updateDynamicHostGroup)
				r.Delete("/", s.deleteDynamicHostGroup)
			})
		})

		// Host assignment endpoints
		r.Route("/assignments", func(r chi.Router) {
			r.Post("/host-to-config", s.assignHostToConfig)
			r.Post("/host-to-group", s.assignHostToGroup)
			r.Post("/host-to-dynamic-group", s.assignHostToDynamicGroup)
			r.Get("/host/{id}", s.getHostAssignments)
		})

		// Authentication endpoints
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", s.login)
			r.Post("/logout", s.logout)
			r.Get("/status", s.getAuthStatus)
		})

		// Status endpoints
		r.Get("/status", s.getStatus)
		r.Get("/health", s.getHealth)
	})

	// Web interface routes - serve static files from embedded filesystem
	s.router.Mount("/web/", http.StripPrefix("/web/", web.NewHandler()))
	s.router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/web/login.html", http.StatusFound)
	})
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	return s.router
}

// authMiddleware is the authentication middleware
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for certain endpoints
		path := r.URL.Path
		
		// Always allow health checks and status
		if strings.HasPrefix(path, "/api/v1/status") ||
			strings.HasPrefix(path, "/api/v1/health") {
			next.ServeHTTP(w, r)
			return
		}

		// Allow login/logout endpoints
		if strings.HasPrefix(path, "/api/v1/auth/login") ||
			strings.HasPrefix(path, "/api/v1/auth/logout") {
			next.ServeHTTP(w, r)
			return
		}

		// Allow web interface root for redirect to login
		if path == "/" || path == "/web/" || path == "/web/login" {
			next.ServeHTTP(w, r)
			return
		}

		// For API endpoints and web interface, require authentication
		if strings.HasPrefix(path, "/api/v1/") || strings.HasPrefix(path, "/web/") {
			// Check for session cookie or Authorization header
			sessionID := ""
			
			// Check cookie first
			if cookie, err := r.Cookie("session_id"); err == nil {
				sessionID = cookie.Value
			} else {
				// Check Authorization header (Bearer token)
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					sessionID = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if sessionID == "" {
				// No session provided
				writeError(w, http.StatusUnauthorized, "Authentication required", nil)
				return
			}

			// Validate session
			session := s.config.AuthService.GetSession(sessionID)
			if session == nil {
				// Invalid or expired session
				// Clear the cookie if it exists
				cookie := &http.Cookie{
					Name:     "session_id",
					Value:    "",
					Path:     "/",
					Expires:  time.Unix(0, 0),
					MaxAge:   -1,
					HttpOnly: true,
				}
				http.SetCookie(w, cookie)
				
				writeError(w, http.StatusUnauthorized, "Invalid or expired session", nil)
				return
			}

			// Session is valid, proceed
			next.ServeHTTP(w, r)
			return
		}

		// For other paths, allow in dev mode or if no specific auth required
		if s.config.DevMode {
			next.ServeHTTP(w, r)
			return
		}

		// Default: allow
		next.ServeHTTP(w, r)
	})
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON: %v", err)
	}
}

// writeError writes an error response
func writeError(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(models.APIResponse{
		Success: false,
		Message: message,
		Error:   err.Error(),
	})
}