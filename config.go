package licensing

import (
	"os"
	"path/filepath"
	"time"

	"github.com/oarkflow/licensing/pkg/client"
)

// Config controls how the licensing client persists data and contacts the server.
// It extends the underlying client.Config with additional security features.
type Config struct {
	ConfigDir         string        // Directory for license storage (default: ~/.licensing)
	DefaultDir        string        // Default config directory name (default: .licensing)
	LicenseFile       string        // License filename (default: .license.dat)
	ServerURL         string        // License server URL (default: https://localhost:6601)
	AppName           string        // Application name for User-Agent
	AppVersion        string        // Application version for User-Agent
	ProductID         string        // Product ID or slug to validate license against
	HTTPTimeout       time.Duration // HTTP request timeout (default: 15s)
	CACertPath        string        // Custom CA certificate path
	AllowInsecureHTTP bool          // Allow non-TLS connections (dev only!)

	DeviceKeyFile     string // Software fallback key file
	DeviceKeyProvider string // "auto", "tpm", "os", or "software"
	DeviceKeyName     string // OS keyring key label
	TPMDevice         string // TPM path when forcing TPM

	SSHKeyPath         string        // Path to SSH private key for Ed25519 request signing
	ClientID           string        // Client identifier for SSH auth
	TamperDetection    bool          // Enable runtime tamper detection
	CertPinning        bool          // Enable TLS certificate pinning
	PinnedCertHash     string        // Hex-encoded SHA-256 of pinned server certificate DER
	OfflineGracePeriod time.Duration // Grace period for offline validation (default: 7 days)
	MaxOfflineDays     int           // Maximum offline days allowed (default: 30)
}

func (cfg Config) toClientConfig() client.Config {
	return client.Config{
		ConfigDir:         cfg.ConfigDir,
		DefaultDir:        cfg.DefaultDir,
		LicenseFile:       cfg.LicenseFile,
		ServerURL:         cfg.ServerURL,
		AppName:           cfg.AppName,
		AppVersion:        cfg.AppVersion,
		ProductID:         cfg.ProductID,
		HTTPTimeout:       cfg.HTTPTimeout,
		CACertPath:        cfg.CACertPath,
		AllowInsecureHTTP: cfg.AllowInsecureHTTP,
		DeviceKeyFile:     cfg.DeviceKeyFile,
		DeviceKeyProvider: cfg.DeviceKeyProvider,
		DeviceKeyName:     cfg.DeviceKeyName,
		TPMDevice:         cfg.TPMDevice,
	}
}

// ResolveClientConfig builds a Config with SDK defaults without reading environment variables.
func ResolveClientConfig(cfg Config) Config {
	home, _ := os.UserHomeDir()
	if cfg.DefaultDir == "" && home != "" {
		cfg.DefaultDir = DefaultConfigDir
	}
	if cfg.ConfigDir == "" && home != "" {
		cfg.ConfigDir = filepath.Join(home, cfg.DefaultDir)
	}
	if cfg.LicenseFile == "" {
		cfg.LicenseFile = DefaultLicenseFile
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = DefaultServerURL
	}
	if cfg.OfflineGracePeriod <= 0 {
		cfg.OfflineGracePeriod = 7 * 24 * time.Hour
	}
	if cfg.MaxOfflineDays <= 0 {
		cfg.MaxOfflineDays = 30
	}
	return cfg
}

// ResolveCredentials returns nil - credentials must be provided via interactive prompt only.
// This ensures license credentials cannot be passed via environment variables, flags, or files.
func ResolveCredentials() (*Credentials, error) {
	return nil, nil
}
