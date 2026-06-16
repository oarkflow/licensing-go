// Package licensing provides a secure Go SDK for the device-bound licensing service.
//
// This package provides:
// - Device Proof v2 authentication with TPM, OS keyring, or software keys
// - TLS connections with optional custom CA configuration
// - RSA-PSS license signature verification
// - AES-GCM encrypted local license storage
// - Encrypted checksum verification for local tamper detection
// - Background verification scheduling
//
// # Quick Start
//
//	cfg := licensing.Config{
//	    ServerURL:         "https://licensing.example.com",
//	    ProductID:         "my-product",
//	    DeviceKeyProvider: "auto",
//	}
//	client, err := licensing.NewClient(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Activate a new device
//	err = client.Activate("user@example.com", "client-123", "ABCD-EFGH-...")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify the encrypted, device-bound local license.
//	license, err := client.Verify()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Licensed plan: %s\n", license.PlanSlug)
//
// # Security Features
//
// Device Proof v2:
//
//	cfg := licensing.Config{
//	    ServerURL:         "https://licensing.example.com",
//	    DeviceKeyProvider: "auto", // tpm, os, or software may be forced
//	    DeviceKeyFile:     "device_ed25519.pem",
//	}
//
// TLS with Custom CA:
//
//	cfg := licensing.Config{
//	    ServerURL:  "https://licensing.example.com",
//	    CACertPath: "/path/to/ca.pem",
//	}
package licensing

import (
	"fmt"
	"path/filepath"

	"github.com/oarkflow/licensing/pkg/client"
	off "github.com/oarkflow/licensing/pkg/client/offline"
)

// Re-export core types from the internal client package.
type (
	// LicenseData is the decrypted license information consumed by applications.
	LicenseData = client.LicenseData

	// LicenseDevice represents device metadata tied to a license.
	LicenseDevice = client.LicenseDevice

	// StoredLicense is the encrypted payload persisted locally.
	StoredLicense = client.StoredLicense

	// ActivationRequest is sent to the licensing server.
	ActivationRequest = client.ActivationRequest

	// ActivationResponse is returned by the licensing server.
	ActivationResponse = client.ActivationResponse

	// LicenseEntitlements contains all features and scopes granted by a license.
	LicenseEntitlements = client.LicenseEntitlements

	// FeatureGrant represents a feature enabled for a license.
	FeatureGrant = client.FeatureGrant

	// ScopeGrant represents a scope permission granted for a feature.
	ScopeGrant = client.ScopeGrant

	// ScopePermission defines the permission level for a scope.
	ScopePermission = client.ScopePermission

	// CredentialsFile represents a JSON file containing license activation credentials.
	CredentialsFile = client.CredentialsFile

	// TrialRequest is sent to the licensing server to request a trial license.
	TrialRequest = client.TrialRequest

	// TrialCheckRequest is sent to check if a device is eligible for trial.
	TrialCheckRequest = client.TrialCheckRequest

	// TrialCheckResponse is returned when checking trial eligibility.
	TrialCheckResponse = client.TrialCheckResponse

	// TrialInfo contains information about the trial status and expiration.
	TrialInfo = client.TrialInfo

	// TrialStatus represents the current status of a trial license.
	TrialStatus = client.TrialStatus

	// DeviceIdentity describes the proof-key-backed local identity used for activation.
	DeviceIdentity = client.DeviceIdentity

	// Types for usage restrictions exported from the core client
	ScopeRestriction     = client.ScopeRestriction
	UsageRestrictionType = client.UsageRestrictionType
	SubjectType          = client.SubjectType
	UsageContext         = client.UsageContext
)

// Re-export constants.
const (
	// DefaultLicenseFile is the default license file name.
	DefaultLicenseFile = client.DefaultLicenseFile

	// DefaultConfigDir is the default configuration directory name.
	DefaultConfigDir = client.DefaultConfigDir

	// DefaultServerURL is the default licensing server URL.
	DefaultServerURL = client.DefaultServerURL

	// ScopePermissionAllow indicates the scope action is allowed.
	ScopePermissionAllow = client.ScopePermissionAllow

	// ScopePermissionDeny indicates the scope action is denied.
	ScopePermissionDeny = client.ScopePermissionDeny

	// ScopePermissionLimit indicates the scope action is allowed with limits.
	ScopePermissionLimit = client.ScopePermissionLimit

	// TrialStatusNotTrial indicates this is not a trial license.
	TrialStatusNotTrial = client.TrialStatusNotTrial

	// TrialStatusActive indicates the trial is currently active.
	TrialStatusActive = client.TrialStatusActive

	// TrialStatusExpired indicates the trial has expired.
	TrialStatusExpired = client.TrialStatusExpired
	// Usage restriction constants
	UsageRestrictionStorage = client.UsageRestrictionStorage
	UsageRestrictionUser    = client.UsageRestrictionUser
	UsageRestrictionDevice  = client.UsageRestrictionDevice
	// Subject type constants
	SubjectTypeStorage = client.SubjectTypeStorage
	SubjectTypeUser    = client.SubjectTypeUser
	SubjectTypeDevice  = client.SubjectTypeDevice
)

// EnvServerURL is kept for backward compatibility only.
// This wrapper does not read environment variables for licensing configuration.
const EnvServerURL = "LICENSE_CLIENT_SERVER"

// Re-export errors.
var (
	// ErrServerUnavailable is returned when the licensing server cannot be reached.
	ErrServerUnavailable = client.ErrServerUnavailable
)

// Client manages license activation, verification, and coupon redemption for Go applications.
type Client struct {
	*client.Client
	config       Config
	licensePath  string
	checksumPath string

	TamperEnabled      bool
	TamperDetector     *TamperDetector
	SecurityMetrics    *SecurityMetrics
	KeyRotationManager *KeyRotationManager
}

// NewClient creates a new licensing client with the given configuration.
func NewClient(cfg Config) (*Client, error) {
	resolved := ResolveClientConfig(cfg)
	inner, err := client.New(resolved.toClientConfig())
	if err != nil {
		return nil, err
	}
	c := &Client{
		Client:       inner,
		config:       resolved,
		licensePath:  filepath.Join(resolved.ConfigDir, resolved.LicenseFile),
		checksumPath: filepath.Join(resolved.ConfigDir, resolved.LicenseFile+".chk"),
	}
	if cfg.TamperDetection {
		c.EnableTamperDetection()
	}
	return c, nil
}

// New creates a new licensing client with the given configuration.
func New(cfg Config) (*Client, error) {
	return NewClient(cfg)
}

// LoadCredentialsFile loads license activation credentials from a JSON file.
// The file should contain: {"email": "...", "client_id": "...", "license_key": "..."}
func LoadCredentialsFile(path string) (*CredentialsFile, error) {
	return client.LoadCredentialsFile(path)
}

// Offline re-exports for offline verification SDK
type (
	OfflineConfig = off.Config
	OfflineClient = off.OfflineClient
)

// NewOfflineClient creates a new offline verification client using the shared SDK.
func NewOfflineClient(cfg OfflineConfig) (*OfflineClient, error) {
	return off.New(cfg)
}

// RunIntegrityChecks performs immediate integrity checks and returns any failures.
func (c *Client) RunIntegrityChecks() []TamperFailure {
	if c.TamperDetector == nil {
		c.TamperDetector = NewTamperDetector(0)
	}
	checkDebugger()
	checkPermissions()
	checkEnvironment()
	return c.TamperDetector.Failures()
}

// EnableTamperDetection starts the background tamper detection goroutine.
func (c *Client) EnableTamperDetection() {
	if c.TamperDetector == nil {
		c.TamperDetector = NewTamperDetector(0)
	}
	c.TamperDetector.Start()
	c.TamperEnabled = true
	if c.SecurityMetrics == nil {
		c.SecurityMetrics = NewSecurityMetrics()
	}
}

// VerifyWithIntegrity verifies the local license and runs integrity checks.
// Returns the license data, integrity failures, and any error.
func (c *Client) VerifyWithIntegrity() (*LicenseData, []TamperFailure, error) {
	failures := c.RunIntegrityChecks()
	if c.SecurityMetrics != nil {
		c.SecurityMetrics.RecordTamperCheck(len(failures) == 0)
	}

	data, err := c.Verify()
	success := err == nil && data != nil
	if c.SecurityMetrics != nil {
		c.SecurityMetrics.RecordValidation(success)
	}

	if err != nil {
		return nil, failures, err
	}
	return data, failures, nil
}

// GetSecurityMetrics returns the current security metrics snapshot.
func (c *Client) GetSecurityMetrics() (*SecurityMetricsSnapshot, error) {
	if c.SecurityMetrics == nil {
		return nil, fmt.Errorf("security metrics not initialized")
	}
	snap := c.SecurityMetrics.Snapshot()
	return &snap, nil
}


