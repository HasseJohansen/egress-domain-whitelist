// Package auth provides authentication services for the configuration server
package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	CertFile       string
	KeyFile        string
	CACertFile     string
	DevMode        bool
	AllowedSubnets []string
}

// AuthService provides authentication functionality
type AuthService struct {
	config         *AuthConfig
	caCertPool    *x509.CertPool
	serverCert    *x509.Certificate
	serverTLSConfig *tls.Config
}

// NewAuthService creates a new authentication service
func NewAuthService(config *AuthConfig) (*AuthService, error) {
	as := &AuthService{
		config: config,
		caCertPool: x509.NewCertPool(),
	}

	// Load CA certificate
	if config.CACertFile != "" {
		caCert, err := os.ReadFile(config.CACertFile)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to read CA cert: %v", err)
		} else if err == nil {
			as.caCertPool.AppendCertsFromPEM(caCert)
		}
	}

	// Load server certificate for client verification
	if config.CertFile != "" {
		cert, err := os.ReadFile(config.CertFile)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("Warning: failed to read server cert: %v", err)
		} else if err == nil {
			x509Cert, parseErr := parseCertificate(cert)
			if parseErr != nil {
				log.Printf("Warning: failed to parse server cert: %v", parseErr)
			} else {
				as.serverCert = x509Cert
			}
		}
	}

	// Configure TLS
	as.serverTLSConfig = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  as.caCertPool,
		MinVersion: tls.VersionTLS13,
	}

	if config.DevMode {
		// In dev mode, don't require client certificates
		as.serverTLSConfig.ClientAuth = tls.NoClientCert
		log.Printf("Running in dev mode - client certificate verification disabled")
	}

	return as, nil
}

// GetTLSConfig returns the TLS configuration for the server
func (a *AuthService) GetTLSConfig() *tls.Config {
	return a.serverTLSConfig
}

// VerifyClientCertificate verifies a client certificate and returns the hostname
func (a *AuthService) VerifyClientCertificate(cert *x509.Certificate) (string, error) {
	// Extract hostname from certificate
	hostname := extractHostnameFromCert(cert)
	if hostname == "" {
		return "", fmt.Errorf("no hostname found in certificate")
	}

	// Check if client IP is in allowed subnets (if we have peer info)
	// This would be called from the HTTP handler with the connection info
	return hostname, nil
}

// ExtractHostnameFromCert extracts the hostname from a certificate
func extractHostnameFromCert(cert *x509.Certificate) string {
	// Check Common Name first
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Check DNS names in Subject Alternative Names
	for _, dnsName := range cert.DNSNames {
		if dnsName != "" {
			return dnsName
		}
	}

	// Check Email addresses
	for _, email := range cert.EmailAddresses {
		if email != "" {
			return email
		}
	}

	return ""
}

// GenerateCertificateFingerprint generates a SHA-256 fingerprint of a certificate
func GenerateCertificateFingerprint(cert *x509.Certificate) string {
	raw := cert.Raw
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

// GenerateCertificateFingerprintFromPEM generates a fingerprint from PEM-encoded certificate
func GenerateCertificateFingerprintFromPEM(pemCert []byte) (string, error) {
	cert, err := parseCertificate(pemCert)
	if err != nil {
		return "", err
	}
	return GenerateCertificateFingerprint(cert), nil
}

// ValidateHostname validates that a hostname is not empty and is reasonable
func ValidateHostname(hostname string) bool {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return false
	}

	// Basic validation - hostname should not contain special characters
	// that could be used for path traversal or injection
	for _, char := range hostname {
		if char < 32 || char > 126 {
			return false
		}
		// Allow alphanumeric, hyphens, underscores, dots
		if !(char >= 'a' && char <= 'z') &&
			!(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') &&
			char != '-' && char != '_' && char != '.' {
			return false
		}
	}

	return true
}

// IsIPInAllowedSubnets checks if an IP address is in any of the allowed subnets
func (a *AuthService) IsIPInAllowedSubnets(ipStr string) bool {
	if a.config.DevMode {
		return true // In dev mode, allow all
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, subnet := range a.config.AllowedSubnets {
		_, cidr, err := net.ParseCIDR(subnet)
		if err != nil {
			log.Printf("Warning: invalid subnet %s: %v", subnet, err)
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// IsHostnameInAllowedSubnets checks if a hostname resolves to an IP in allowed subnets
func (a *AuthService) IsHostnameInAllowedSubnets(hostname string) bool {
	if a.config.DevMode {
		return true
	}

	// Try to resolve the hostname
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if a.IsIPInAllowedSubnets(ip.String()) {
			return true
		}
	}

	return false
}

// parseCertificate parses a PEM-encoded certificate
func parseCertificate(pemCert []byte) (*x509.Certificate, error) {
	// Try to parse directly (might work if it's already DER encoded)
	if cert, err := x509.ParseCertificate(pemCert); err == nil {
		return cert, nil
	}

	// Try to decode PEM
	block, _ := pem.Decode(pemCert)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	
	return cert, nil
}
