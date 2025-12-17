package licensing

import (
	"os"
	"path/filepath"
	"time"
)

// ResolveClientConfig builds a Config with immutable security settings
func ResolveClientConfig(cfg Config) Config {
	home, _ := os.UserHomeDir()
	if cfg.DefaultDir == "" && home != "" {
		cfg.DefaultDir = ".licensing"
	}
	if cfg.ConfigDir == "" && home != "" {
		cfg.ConfigDir = filepath.Join(home, cfg.DefaultDir)
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}
	return cfg
}

// ResolveCredentials returns nil - credentials must be provided via interactive prompt only.
// This ensures license credentials cannot be passed via environment variables, flags, or files.
func ResolveCredentials() (*Credentials, error) {
	return nil, nil
}
