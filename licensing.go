// Package licensing provides a secure Go SDK for the hardware-key licensing service.
//
// This package provides enterprise-grade security features including:
// - SSH key authentication
// - TLS 1.3 with certificate pinning
// - Multi-layer license verification
// - Tamper detection
// - Automatic key rotation support
// - Comprehensive audit logging
//
// # Quick Start
//
//	cfg := licensing.Config{
//	    ServerURL: "https://licensing.example.com",
//	    ProductID: "my-product",
//	    SSHKeyPath: "/path/to/client_key",  // Optional: SSH key authentication
//	    CertPinning: true,                   // Optional: Enable certificate pinning
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
//	// Verify with multi-layer verification
//	license, err := client.Verify()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Licensed plan: %s\n", license.PlanSlug)
//
// # Security Features
//
// SSH Key Authentication:
//
//	cfg := licensing.Config{
//	    ServerURL: "https://licensing.example.com",
//	    SSHKeyPath: "/home/user/.ssh/licensing_client",
//	    ClientID: "client-12345",
//	}
//
// TLS Certificate Pinning:
//
//	cfg := licensing.Config{
//	    ServerURL: "https://licensing.example.com",
//	    CertPinning: true,
//	    PinnedCertHash: []byte{...}, // SHA256 hash of server cert
//	}
//
// Tamper Detection:
//
//	client.EnableTamperDetection(true)
package licensing

import (
	"github.com/oarkflow/licensing/pkg/client"
	off "github.com/oarkflow/licensing/pkg/client/offline"
)

// Re-export core types from the internal client package.
type (
	// Config controls how the licensing client persists data and contacts the server.
	Config = client.Config

	// Client manages license activation and verification for Go applications.
	Client = client.Client

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
	// Types for usage restrictions exported from the core client
	ScopeRestriction     = client.ScopeRestriction
	UsageRestrictionType = client.UsageRestrictionType
	SubjectType          = client.SubjectType
	UsageContext         = client.UsageContext
)

// Re-export constants.
const (
	// EnvServerURL is the environment variable for the licensing server URL.
	EnvServerURL = client.EnvServerURL

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

// Re-export errors.
var (
	// ErrServerUnavailable is returned when the licensing server cannot be reached.
	ErrServerUnavailable = client.ErrServerUnavailable
)

// NewClient creates a new licensing client with the given configuration.
func NewClient(cfg Config) (*Client, error) {
	return client.New(cfg)
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
