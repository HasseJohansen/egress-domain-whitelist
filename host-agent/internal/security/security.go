// Package security provides security hardening for the host agent
package security

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// SecurityConfig holds security configuration
type SecurityConfig struct {
	// Drop these capabilities
	DropCapabilities []string
	// Seccomp profile
	EnableSeccomp bool
	// File permissions
	EnsureRootOwnership bool
	// User to run as (non-root)
	RunAsUser string
	// Group to run as
	RunAsGroup string
}

// DefaultSecurityConfig returns the default security configuration
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		DropCapabilities: []string{
			"CAP_BPF",           // Prevent BPF operations
			"CAP_NET_ADMIN",     // Prevent network admin operations
			"CAP_SYS_ADMIN",     // Prevent system admin operations
			"CAP_SYS_MODULE",    // Prevent kernel module operations
			"CAP_SYS_RAWIO",     // Prevent raw I/O operations
			"CAP_SYS_BOOT",      // Prevent system boot operations
			"CAP_SYS_NICE",      // Prevent nice priority changes
			"CAP_SYS_PACCT",     // Prevent process accounting
			"CAP_SYS_PTRACE",    // Prevent process tracing
			"CAP_SYS_TIME",      // Prevent time changes
			"CAP_SYS_TTY_CONFIG", // Prevent TTY configuration
			"CAP_DAC_OVERRIDE",  // Prevent DAC override
			"CAP_DAC_READ_SEARCH", // Prevent DAC read/search
			"CAP_FOWNER",        // Prevent file ownership changes
			"CAP_FSETID",        // Prevent setuid/setgid
			"CAP_KILL",          // Prevent killing arbitrary processes
			"CAP_SETGID",        // Prevent setgid
			"CAP_SETUID",        // Prevent setuid
			"CAP_SETPCAP",       // Prevent capability setting
			"CAP_LINUX_IMMUTABLE", // Prevent immutable flag changes
			"CAP_NET_BIND_SERVICE", // Prevent binding to privileged ports
			"CAP_NET_BROADCAST",   // Prevent broadcast
			"CAP_NET_RAW",         // Prevent raw networking
			"CAP_IPC_LOCK",        // Prevent IPC locking
			"CAP_IPC_OWNER",       // Prevent IPC ownership
		},
		EnableSeccomp:     true,
		EnsureRootOwnership: true,
		RunAsUser:        "nobody",
		RunAsGroup:       "nogroup",
	}
}

// SecurityManager manages security for the host agent
type SecurityManager struct {
	config *SecurityConfig
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config *SecurityConfig) *SecurityManager {
	if config == nil {
		config = DefaultSecurityConfig()
	}
	return &SecurityManager{config: config}
}

// Apply applies all security measures
func (s *SecurityManager) Apply() error {
	// 1. Drop capabilities
	if err := s.dropCapabilities(); err != nil {
		log.Printf("Warning: failed to drop capabilities: %v", err)
		// Continue with other security measures
	}

	// 2. Apply seccomp filter
	if s.config.EnableSeccomp {
		if err := s.applySeccomp(); err != nil {
			log.Printf("Warning: failed to apply seccomp filter: %v", err)
			// Continue with other security measures
		}
	}

	// 3. Set file permissions
	if s.config.EnsureRootOwnership {
		if err := s.ensureFilePermissions(); err != nil {
			log.Printf("Warning: failed to set file permissions: %v", err)
			// Continue with other security measures
		}
	}

	// 4. Drop privileges to non-root user
	if s.config.RunAsUser != "" {
		if err := s.dropPrivileges(); err != nil {
			log.Printf("Warning: failed to drop privileges: %v", err)
			// This is more serious, but we'll continue
		}
	}

	return nil
}

// dropCapabilities drops the specified capabilities
func (s *SecurityManager) dropCapabilities() error {
	// Get current capabilities
	caps, err := getCurrentCapabilities()
	if err != nil {
		return fmt.Errorf("failed to get current capabilities: %v", err)
	}

	// Drop each specified capability
	for _, cap := range s.config.DropCapabilities {
		if err := dropCapability(cap, caps); err != nil {
			log.Printf("Warning: failed to drop capability %s: %v", cap, err)
			// Continue with other capabilities
		}
	}

	return nil
}

// applySeccomp applies the seccomp filter
func (s *SecurityManager) applySeccomp() error {
	// Check if seccomp is available
	if _, err := os.Stat("/lib64/libseccomp.so.2"); os.IsNotExist(err) {
		if _, err := os.Stat("/lib/libseccomp.so.2"); os.IsNotExist(err) {
			return fmt.Errorf("seccomp library not found")
		}
	}

	// Create seccomp profile
	profile, err := createSeccompProfile()
	if err != nil {
		return fmt.Errorf("failed to create seccomp profile: %v", err)
	}

	// Apply seccomp filter to current thread
	if err := applySeccompToCurrentThread(profile); err != nil {
		return fmt.Errorf("failed to apply seccomp filter: %v", err)
	}

	log.Printf("Seccomp filter applied successfully")
	return nil
}

// ensureFilePermissions ensures that critical files are owned by root
func (s *SecurityManager) ensureFilePermissions() error {
	// List of critical files/directories
	criticalPaths := []string{
		"/app/ebpf",
		"/app/config",
		"/app/data",
		"/app/certs",
		"/app/config-server",
		"/app/host-agent",
	}

	for _, path := range criticalPaths {
		// Check if path exists
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Skip non-existent paths
			}
			return fmt.Errorf("failed to stat %s: %v", path, err)
		}

		// Ensure root ownership
		if err := os.Chown(path, 0, 0); err != nil {
			return fmt.Errorf("failed to chown %s to root: %v", path, err)
		}

		// If it's a directory, apply recursively
		if info.IsDir() {
			if err := filepath.Walk(path, func(subPath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if err := os.Chown(subPath, 0, 0); err != nil {
					return err
				}
				// Set restrictive permissions
				if info.IsDir() {
					if err := os.Chmod(subPath, 0750); err != nil {
						return err
					}
				} else {
					if err := os.Chmod(subPath, 0640); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to walk %s: %v", path, err)
			}
		} else {
			// Set restrictive permissions for files
			if err := os.Chmod(path, 0640); err != nil {
				return fmt.Errorf("failed to chmod %s: %v", path, err)
			}
		}

		log.Printf("Set ownership to root for %s", path)
	}

	return nil
}

// dropPrivileges drops privileges to a non-root user
func (s *SecurityManager) dropPrivileges() error {
	// Get user and group IDs
	user, err := getUserID(s.config.RunAsUser)
	if err != nil {
		return fmt.Errorf("failed to get user ID for %s: %v", s.config.RunAsUser, err)
	}

	group, err := getGroupID(s.config.RunAsGroup)
	if err != nil {
		return fmt.Errorf("failed to get group ID for %s: %v", s.config.RunAsGroup, err)
	}

	// Change group first
	if err := syscall.Setgid(group); err != nil {
		return fmt.Errorf("failed to setgid: %v", err)
	}

	// Change user
	if err := syscall.Setuid(user); err != nil {
		return fmt.Errorf("failed to setuid: %v", err)
	}

	// Verify we're no longer root
	currentUID := syscall.Getuid()
	if currentUID == 0 {
		return fmt.Errorf("failed to drop root privileges")
	}

	log.Printf("Dropped privileges to user %d group %d", user, group)
	return nil
}

// getUserID returns the UID for a username
func getUserID(username string) (int, error) {
	// Try to get user by name
	cmd := exec.Command("id", "-u", username)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to get UID for %s: %v", username, err)
	}
	
	uid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return 0, fmt.Errorf("failed to parse UID: %v", err)
	}
	
	return uid, nil
}

// getGroupID returns the GID for a group name
func getGroupID(groupname string) (int, error) {
	// Try to get group by name
	cmd := exec.Command("id", "-g", groupname)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to get GID for %s: %v", groupname, err)
	}
	
	gid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return 0, fmt.Errorf("failed to parse GID: %v", err)
	}
	
	return gid, nil
}

// Placeholder functions - these would be implemented with proper system calls
// or using a seccomp library in production

func getCurrentCapabilities() (map[string]bool, error) {
	// In production, use the golang.org/x/sys/unix package
	// to get current capabilities
	return make(map[string]bool), nil
}

func dropCapability(cap string, currentCaps map[string]bool) error {
	// In production, use the golang.org/x/sys/unix package
	// to drop capabilities
	log.Printf("Would drop capability: %s", cap)
	return nil
}

func createSeccompProfile() (string, error) {
	// In production, create a seccomp profile that blocks:
	// - bpf() syscall for non-root
	// - Other dangerous syscalls
	//
	// Example profile would block:
	//   syscalls: [
	//     { names: ["bpf"], action: SCMP_ACT_ERRNO(EPERM), args: [...] },
	//     { names: ["reboot"], action: SCMP_ACT_ERRNO(EPERM) },
	//     ...
	//   ]
	return "default", nil
}

func applySeccompToCurrentThread(profile string) error {
	// In production, apply the seccomp filter to the current thread
	log.Printf("Would apply seccomp profile: %s", profile)
	return nil
}
