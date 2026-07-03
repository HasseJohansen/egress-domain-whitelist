// Package web provides web interface handlers for the configuration server
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed templates/*
var templateFS embed.FS

// NewHandler creates a new web interface handler
func NewHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the path relative to /web/
		path := strings.TrimPrefix(r.URL.Path, "/web/")
		
		// If path is empty, serve login.html
		if path == "" || path == "/" {
			path = "login.html"
		}

		// Try to serve the file from embedded templates
		data, err := templateFS.ReadFile(filepath.Join("templates", path))
		if err == nil {
			ServeTemplateContent(w, r, data, path)
			return
		}



		// If we get here, try adding .html extension
		if !strings.HasSuffix(path, ".html") {
			htmlPath := path + ".html"
			data, err = templateFS.ReadFile(filepath.Join("templates", htmlPath))
			if err == nil {
				ServeTemplateContent(w, r, data, htmlPath)
				return
			}
		}

		// File not found
		http.NotFound(w, r)
	})
}

// ServeTemplate serves a template file
func ServeTemplate(w http.ResponseWriter, r *http.Request, name string) {
	// Read the template file from embedded filesystem
	data, err := templateFS.ReadFile(filepath.Join("templates", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Set content type
	if strings.HasSuffix(name, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else if strings.HasSuffix(name, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	} else if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}

	w.Write(data)
}

// NewHandlerWithFallback creates a web handler with fallback to file system
func NewHandlerWithFallback(templateDir string) http.Handler {
	mux := http.NewServeMux()

	// Try embedded first, then fallback to filesystem
	mux.HandleFunc("/web/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/web/")
		if path == "" {
			path = "index.html"
		}

		// Try embedded
		data, err := templateFS.ReadFile(filepath.Join("templates", path))
		if err == nil {
			ServeTemplateContent(w, r, data, path)
			return
		}

		// Fallback to filesystem
		if templateDir != "" {
			fsPath := filepath.Join(templateDir, path)
			if _, err := os.Stat(fsPath); err == nil {
				http.ServeFile(w, r, fsPath)
				return
			}
		}

		http.NotFound(w, r)
	})

	return mux
}

// ServeTemplateContent serves template content with proper headers
func ServeTemplateContent(w http.ResponseWriter, r *http.Request, data []byte, path string) {
	if strings.HasSuffix(path, ".html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}
	w.Write(data)
}

// osFS is a helper for filesystem access
var osFS fs.FS = osFSImpl{}

type osFSImpl struct{}

func (osFSImpl) Open(name string) (fs.File, error) {
	return os.Open(name)
}
