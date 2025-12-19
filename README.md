# Go Licensing SDK

A Go SDK for integrating hardware-bound software licensing into Go applications with enterprise-grade security features. This SDK provides the full licensing client with activation, verification, background scheduling, encrypted license storage, and comprehensive security controls.

## Features

### Core Licensing
- 🔐 **AES-256-GCM encryption** for secure license transport and storage
- ✅ **RSA-PSS signature verification** to ensure license authenticity
- 🖥️ **Hardware fingerprinting** for device-bound licenses
- ⏰ **Background verification** with configurable check modes
- 🔄 **Automatic retry** with exponential backoff for network failures
- 📦 **Zero external dependencies** for crypto operations

### Security Features (New in v2.0)
- 🔑 **SSH Key Authentication** using Ed25519 cryptography
- 🛡️ **Tamper Detection** with multi-layer integrity verification
- 🔒 **TLS 1.3** with optional certificate pinning
- 📊 **Security Monitoring** and audit logging
- 🔐 **Multi-Layer Verification** (signature, integrity, hardware, time)
- 🗝️ **Key Rotation** support for long-lived deployments
- 📴 **Offline Grace Period** with configurable limits
- 🎯 **Hardware Binding** with multiple fingerprint strategies

## Requirements

- Go 1.21 or later

## Installation

```bash
go get github.com/oarkflow/licensing-golang
```

## Quick Start

### 1. Generate SSH Keys (Recommended)

For enhanced security, generate SSH keys for client authentication:

```bash
# Generate Ed25519 key pair
ssh-keygen -t ed25519 -f ~/.ssh/licensing_client -N ""

# Or use the SDK helper
go run examples/secure/main.go --generate-key
```

Register your public key with the licensing server before activation.

### 2. Basic Usage with SSH Authentication

```go
package main

import (
    "log"
    "os"
    "time"

    licensing "github.com/oarkflow/licensing-go"
)

func main() {
    // Create client with security features
    client, err := licensing.NewClient(licensing.Config{
        ServerURL:          "https://licensing.example.com",
        ConfigDir:          os.Getenv("HOME") + "/.myapp",
        LicenseFile:        ".license.dat",
        AppName:            "MyApp",
        AppVersion:         "2.0.0",

        // Security features
        SSHKeyPath:         os.Getenv("HOME") + "/.ssh/licensing_client",
        ClientID:           "client-123",
        TamperDetection:    true,
        CertPinning:        true,
        OfflineGracePeriod: 7 * 24 * time.Hour,
        MaxOfflineDays:     30,
    })
    if err != nil {
        log.Fatalf("failed to create client: %v", err)
    }

    // Check if already activated
    if !client.IsActivated() {
        // Activate with SSH key authentication
        err := client.Activate(
            "user@example.com",
            "client-123",
            "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
        )
        if err != nil {
            log.Fatalf("activation failed: %v", err)
        }
    }

    // Verify license with integrity checks
    license, integrityResult, err := client.VerifyWithIntegrity()
    if err != nil {
        log.Fatalf("verification failed: %v", err)
    }

    if !integrityResult.IsValid {
        log.Fatalf("integrity check failed: %v", integrityResult.FailedChecks)
    }

    log.Printf("License: %s (plan: %s)", license.ID, license.PlanSlug)
    log.Printf("Expires: %s", license.ExpiresAt)
    log.Printf("Integrity Score: %.2f%%", integrityResult.Score*100)
}
```

### 3. Feature Gating with Entitlements

```go
package main

import (
    "log"
    "os"

    licensing "github.com/oarkflow/licensing-go"
)

func main() {
    // Create client with configuration
    client, err := licensing.New(licensing.Config{
        ServerURL:   "https://licensing.example.com",
        ConfigDir:   os.Getenv("HOME") + "/.myapp",
        LicenseFile: ".license.dat",
        AppName:     "MyApp",
        AppVersion:  "1.0.0",
    })
    if err != nil {
        log.Fatalf("failed to create client: %v", err)
    }

    // Check if already activated
    if !client.IsActivated() {
        // Activate with credentials
        err := client.Activate(
            "user@example.com",
            "client-123",
            "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
        )
        if err != nil {
            log.Fatalf("activation failed: %v", err)
        }
    }

    // Verify license is valid (returns *LicenseData and error)
    license, err := client.Verify()
    if err != nil {
        log.Fatalf("verification failed: %v", err)
    }

    log.Printf("License: %s (plan: %s)", license.ID, license.PlanSlug)
    log.Printf("Expires: %s", license.ExpiresAt)
}
```

### 2. Feature Gating with Entitlements

The SDK provides built-in entitlement checking methods on `LicenseData`:

```go
// Check if a feature is available
if license.HasFeature("api") {
    enableAPIAccess()
}

// Check scope permissions
if license.HasScope("billing", "create") {
    enableBillingCreate()
}

// Check if an operation is allowed (and get limit if any)
allowed, limit := license.CanPerform("users", "create")
if allowed {
    if limit > 0 {
        log.Printf("User creation enabled (limit: %d)", limit)
    } else {
        log.Println("User creation enabled (unlimited)")
    }
}

// Get feature details
if feature, ok := license.GetFeature("api"); ok {
    log.Printf("API feature: permission=%s", feature.Permission)
}
```
```

### 3. Background Verification

```go
import (
    "context"
### 4. Background Verification with Security Monitoring

```go
import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
)

func main() {
    client, _ := licensing.NewClient(cfg)

    // Initial verification with integrity checks
    license, integrityResult, err := client.VerifyWithIntegrity()
    if err != nil {
        log.Fatalf("verification failed: %v", err)
    }

    if !integrityResult.IsValid {
        log.Fatalf("integrity check failed: score=%.2f%%", integrityResult.Score*100)
    }

    // Start background verification with security monitoring
    ctx, cancel := context.WithCancel(context.Background())
    go client.RunBackgroundVerification(
        ctx,
        license,
        log.Printf, // logging function
        func(updated *licensing.LicenseData) {
            // Handle license updates
            log.Printf("License updated: %s", updated.ID)

            // Check security metrics
            metrics := client.GetSecurityMetrics()
            if metrics.TamperingAttempts > 0 {
                log.Printf("WARNING: %d tampering attempts detected", metrics.TamperingAttempts)
            }
        },
    )

    // Periodic security checks
    ticker := time.NewTicker(15 * time.Minute)
    go func() {
        for {
            select {
            case <-ticker.C:
                result := client.RunIntegrityChecks()
                if result.TamperingDetected {
                    log.Printf("ALERT: Tampering detected: %v", result.FailedChecks)
                }
            case <-ctx.Done():
                return
            }
        }
    }()

    // Handle graceful shutdown
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh

    ticker.Stop()
    cancel() // Stop background verification
}
```

## Configuration

### Config Struct

```go
type Config struct {
    // Basic Configuration
    ConfigDir         string        // Directory for license storage (default: ~/.licensing)
    LicenseFile       string        // License filename (default: .license.dat)
    ServerURL         string        // License server URL (default: https://localhost:6601)
    AppName           string        // Application name for User-Agent
    AppVersion        string        // Application version for User-Agent
    HTTPTimeout       time.Duration // HTTP request timeout (default: 15s)
    CACertPath        string        // Custom CA certificate path
    AllowInsecureHTTP bool          // Allow non-TLS connections (dev only!)

    // Security Configuration (v2.0+)
    SSHKeyPath         string        // Path to SSH private key for authentication
    ClientID           string        // Client identifier for SSH auth
    TamperDetection    bool          // Enable runtime tamper detection
    CertPinning        bool          // Enable TLS certificate pinning
    OfflineGracePeriod time.Duration // Grace period for offline validation (default: 7 days)
    MaxOfflineDays     int           // Maximum offline days allowed (default: 30)

    // Hardware Fingerprinting
    FingerprintStrategy string       // "auto", "cpu-serial", "mac-address", "disk-serial"
}
```

### Environment Variables

The SDK respects these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `LICENSE_CLIENT_SERVER` | License server URL | `https://localhost:6601` |
| `LICENSE_CLIENT_CONFIG_DIR` | License storage directory | `~/.licensing` |
| `LICENSE_CLIENT_LICENSE_FILE` | License filename | `.license.dat` |
| `LICENSE_CLIENT_EMAIL` | Activation email | — |
| `LICENSE_CLIENT_ID` | Client identifier | — |
| `LICENSE_CLIENT_LICENSE_KEY` | License key | — |
| `LICENSE_CLIENT_SSH_KEY` | Path to SSH private key | — |
| `LICENSE_CLIENT_ALLOW_INSECURE_HTTP` | Allow non-TLS | `false` |
| `LICENSE_CLIENT_TAMPER_DETECTION` | Enable tamper detection | `false` |
| `LICENSE_CLIENT_CERT_PINNING` | Enable certificate pinning | `false` |

## API Reference

### Types

#### `LicenseData`

```go
type LicenseData struct {
    ID                 string          // Unique license identifier
    ClientID           string          // Owner client ID
    SubjectClientID    string          // Runtime client ID
    Email              string          // License owner email
    ProductID          string          // Product ID (if configured)
    PlanID             string          // Plan ID (if configured)
    PlanSlug           string          // Plan for feature gating
    Relationship       string          // "direct" or "delegated"
    GrantedBy          string          // Granting client (delegated)
    LicenseKey         string          // The license key
    IssuedAt           time.Time       // Issue timestamp
    ExpiresAt          time.Time       // Expiration timestamp
    LastActivatedAt    time.Time       // Last activation time
    CurrentActivations int             // Current activation count
    MaxDevices         int             // Maximum allowed devices
    DeviceCount        int             // Current device count
    IsRevoked          bool            // Revocation status
    RevokedAt          time.Time       // Revocation timestamp
    RevokeReason       string          // Revocation reason
    Devices            []LicenseDevice // Registered devices
    DeviceFingerprint  string          // Current device fingerprint
    CheckMode          string          // Verification schedule
    CheckIntervalSecs  int64           // Custom interval (seconds)
    NextCheckAt        time.Time       // Next scheduled check
    LastCheckAt        time.Time       // Last check timestamp
    Entitlements       *LicenseEntitlements // Feature entitlements (optional)
}
```

#### `LicenseEntitlements`

The `Entitlements` field in `LicenseData` contains the complete set of features and scopes granted to the license holder. This is only populated when a product/plan is configured on the server.

```go
type LicenseEntitlements struct {
    ProductID   string                  // Product UUID
    ProductSlug string                  // Product slug (e.g., "my-app")
    PlanID      string                  // Plan UUID
    PlanSlug    string                  // Plan slug (e.g., "enterprise")
    Features    map[string]FeatureGrant // Map of feature slug → grant
}

type FeatureGrant struct {
    FeatureID   string                // Feature UUID
    FeatureSlug string                // Feature slug (e.g., "api")
    Category    string                // Category (e.g., "gui", "cli", "api")
    Enabled     bool                  // Whether feature is enabled
    Scopes      map[string]ScopeGrant // Map of scope slug → grant
}

type ScopeGrant struct {
    ScopeID    string            // Scope UUID
    ScopeSlug  string            // Scope slug (e.g., "create")
    Permission ScopePermission   // "allow", "deny", or "limit"
    Limit      int               // Limit value (when permission is "limit")
    Metadata   map[string]string // Additional metadata
}

type ScopePermission string // "allow" | "deny" | "limit"
```

**Example JSON payload** (as received from the server):

```json
{
  "id": "lic_abc123",
  "client_id": "client_xyz",
  "email": "user@example.com",
  "plan_slug": "enterprise",
  "product_id": "prod_001",
  "plan_id": "plan_001",
  "entitlements": {
    "product_id": "prod_001",
    "product_slug": "my-saas-app",
    "plan_id": "plan_001",
    "plan_slug": "enterprise",
    "features": {
      "gui": {
        "feature_id": "feat_gui",
        "feature_slug": "gui",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "list": {
            "scope_id": "scope_list",
            "scope_slug": "list",
            "permission": "allow",
            "limit": 0
          },
          "create": {
            "scope_id": "scope_create",
            "scope_slug": "create",
            "permission": "allow",
            "limit": 0
          },
          "update": {
            "scope_id": "scope_update",
            "scope_slug": "update",
            "permission": "allow",
            "limit": 0
          },
          "delete": {
            "scope_id": "scope_delete",
            "scope_slug": "delete",
            "permission": "allow",
            "limit": 0
          }
        }
      },
      "cli": {
        "feature_id": "feat_cli",
        "feature_slug": "cli",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "execute": {
            "scope_id": "scope_exec",
            "scope_slug": "execute",
            "permission": "allow",
            "limit": 0
          }
        }
      },
      "api": {
        "feature_id": "feat_api",
        "feature_slug": "api",
        "category": "integration",
        "enabled": true,
        "scopes": {
          "requests": {
            "scope_id": "scope_req",
            "scope_slug": "requests",
            "permission": "limit",
            "limit": 10000,
            "metadata": {
              "period": "monthly"
            }
          }
        }
      },
      "premium": {
        "feature_id": "feat_premium",
        "feature_slug": "premium",
        "category": "addon",
        "enabled": false,
        "scopes": {}
      }
    }
  },
  "issued_at": "2025-01-01T00:00:00Z",
  "expires_at": "2026-01-01T00:00:00Z"
}
```

**Key concepts:**

| Field | Description |
|-------|-------------|
| `features` | Map where keys are feature slugs (e.g., "gui", "api") |
| `enabled` | Whether the feature is available for this plan |
| `scopes` | Map where keys are scope slugs (e.g., "create", "delete") |
| `permission` | `"allow"` = permitted, `"deny"` = forbidden, `"limit"` = permitted with quota |
| `limit` | Numeric quota when `permission` is `"limit"` (0 = unlimited for `"allow"`) |
| `metadata` | Optional key-value pairs for additional configuration |

#### `CredentialsFile`

```go
type CredentialsFile struct {
    Email      string // Activation email
    ClientID   string // Client identifier
    LicenseKey string // License key
}
```

**JSON format:**
```json
{
  "email": "user@example.com",
  "client_id": "client-123",
  "license_key": "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
}
```

#### `StoredLicense`

```go
type StoredLicense struct {
    EncryptedData     []byte    // AES-GCM encrypted license + session key
    Nonce             []byte    // 12-byte GCM nonce
    Signature         []byte    // RSA-PSS signature
    PublicKey         []byte    // DER-encoded public key
    DeviceFingerprint string    // Device fingerprint (hex)
    ExpiresAt         time.Time // License expiration
}
```

### Client Methods

```go
// New creates a new licensing client
func New(cfg Config) (*Client, error)

// IsActivated returns true if a local license exists
func (c *Client) IsActivated() bool

// Activate activates with explicit credentials
func (c *Client) Activate(email, clientID, licenseKey string) error

// Verify checks license validity (online if due, offline otherwise)
// Returns the license data and an error if invalid
func (c *Client) Verify() (*LicenseData, error)

// ServerURL returns the configured license server URL
func (c *Client) ServerURL() string

// RunBackgroundVerification starts the verification scheduler
func (c *Client) RunBackgroundVerification(
    ctx context.Context,
    initial *LicenseData,
    logf func(string, ...interface{}),
    onUpdate func(*LicenseData),
) error
```

### LicenseData Helper Methods

```go
// HasFeature checks if a feature is enabled
func (ld *LicenseData) HasFeature(featureSlug string) bool

// GetFeature returns the feature grant if available
func (ld *LicenseData) GetFeature(featureSlug string) (FeatureGrant, bool)

// HasScope checks if a scope is enabled for a feature
func (ld *LicenseData) HasScope(featureSlug, scopeSlug string) bool

// GetScope returns the scope grant if available
func (ld *LicenseData) GetScope(featureSlug, scopeSlug string) (ScopeGrant, bool)

// CanPerform checks if an operation is allowed and returns the limit
func (ld *LicenseData) CanPerform(featureSlug, scopeSlug string) (allowed bool, limit int)
```

### Standalone Crypto Functions

For SDK testing and fixture verification:

```goas


// DecryptStoredLicense decrypts a stored license. Accepts the current device fingerprint
// so that decryption is only possible on the device the license was issued to.
func DecryptStoredLicense(stored *StoredLicense, currentFingerprint string) (*LicenseData, []byte, error)

// VerifyStoredLicenseSignature verifies the RSA-PSS signature
func VerifyStoredLicenseSignature(stored *StoredLicense) error

// BuildStoredLicenseFromResponse constructs a StoredLicense from API response
func BuildStoredLicenseFromResponse(resp *ActivationResponse, fingerprint string) (*StoredLicense, error)
```

## Error Handling

```go
import "errors"

license, err := client.Verify()
if err != nil {
    switch {
    case errors.Is(err, licensing.ErrLicenseNotFound):
        log.Println("No license found - please activate")
    case errors.Is(err, licensing.ErrLicenseExpired):
        log.Fatal("License has expired - please renew")
    case errors.Is(err, licensing.ErrLicenseRevoked):
        log.Fatal("License has been revoked")
    case errors.Is(err, licensing.ErrSignatureInvalid):
        log.Fatal("License file tampered - please re-activate")
    case errors.Is(err, licensing.ErrServerUnavailable):
        log.Println("Server unavailable - using cached license")
    default:
        log.Fatalf("Verification failed: %v", err)
    }
}

// License is valid, continue
log.Printf("License valid: %s", license.ID)
```

## Check Modes

The SDK supports various verification schedules:

| Mode | Behavior |
|------|----------|
| `none` | No automatic verification after initial activation |
| `each_execution` | Verify with server on every startup |
| `monthly` | Verify at the start of each month |
| `yearly` | Verify at the start of each year |
| `custom` | Use `check_interval_seconds` for custom scheduling |

```go
license, _ := client.Verify()
switch license.CheckMode {
case "each_execution":
    // Always verify on startup
case "monthly":
    // Check if we're past next_check_at
case "custom":
    interval := time.Duration(license.CheckIntervalSecs) * time.Second
    // Schedule next check
}
```

## HTTP Handler Integration

```go
import (
    "net/http"
    "encoding/json"
)

type LicenseMiddleware struct {
    client *licensing.Client
}

func (m *LicenseMiddleware) Handler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        license, err := m.client.Verify()
        if err != nil {
            w.WriteHeader(http.StatusForbidden)
            json.NewEncoder(w).Encode(map[string]string{
                "error": "License validation failed",
            })
            return
        }

        ctx := context.WithValue(r.Context(), "license", license)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Usage
mux := http.NewServeMux()
middleware := &LicenseMiddleware{client: client}
http.ListenAndServe(":8080", middleware.Handler(mux))
```

## GoFiber Integration

For a complete GoFiber example, see the [examples/fiber-server](examples/fiber-server/) directory.

## gRPC Integration

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

func LicenseInterceptor(client *licensing.Client) grpc.UnaryServerInterceptor {
    return func(
        ctx context.Context,
        req interface{},
        info *grpc.UnaryServerInfo,
        handler grpc.UnaryHandler,
    ) (interface{}, error) {
        license, err := client.Verify()
        if err != nil {
            return nil, status.Error(codes.PermissionDenied, "license validation failed")
        }

        // Optionally add license to context
        ctx = context.WithValue(ctx, "license", license)
        return handler(ctx, req)
    }
}

// Usage
server := grpc.NewServer(
    grpc.UnaryInterceptor(LicenseInterceptor(client)),
)
```

## Examples

See the [examples](examples/) directory for complete working examples:

- **[basic](examples/basic/)** - Minimal example showing activation and verification
- **[fiber-server](examples/fiber-server/)** - Full GoFiber HTTP server with license protection and entitlements

## Testing

### Run Fixture Tests

```bash
cd sdks/golang
go test -v ./...
```

### Using Fixtures in Your Tests

```go
func TestLicenseValidation(t *testing.T) {
    // Load fixture
    data, _ := os.ReadFile("../../docs/fixtures/v1/license.dat")
    var stored licensing.StoredLicense
    json.Unmarshal(data, &stored)

    // Verify signature
    err := licensing.VerifyStoredLicenseSignature(&stored)
    require.NoError(t, err)

    // Decrypt (provide the device fingerprint to enforce binding)
    license, _, err := licensing.DecryptStoredLicense(&stored, stored.DeviceFingerprint)
    require.NoError(t, err)

    assert.Equal(t, "lic_fixture_v1", license.ID)
    assert.Equal(t, "enterprise", license.PlanSlug)
}
```

## Security Best Practices

### 1. Use SSH Key Authentication

**Always use SSH keys** in production for enhanced security:

```go
client, err := licensing.NewClient(licensing.Config{
    ServerURL:  "https://licensing.example.com",
    SSHKeyPath: "/path/to/private_key",
    ClientID:   "your-client-id",
})
```

Generate keys using:
```bash
# Using SDK
go run examples/secure/main.go --generate-key

# Or using ssh-keygen
ssh-keygen -t ed25519 -f ~/.ssh/licensing_client -N ""
```

### 2. Enable Tamper Detection

Enable runtime integrity monitoring to detect tampering attempts:

```go
client, err := licensing.NewClient(licensing.Config{
    TamperDetection: true,
    // ...
})

// Periodic integrity checks
result := client.RunIntegrityChecks()
if result.TamperingDetected {
    log.Fatalf("Tampering detected: %v", result.FailedChecks)
}
```

### 3. Use TLS with Certificate Pinning

**Always use TLS in production** and consider certificate pinning:

```go
client, err := licensing.NewClient(licensing.Config{
    ServerURL:   "https://licensing.example.com",
    CertPinning: true,  // Enable certificate pinning
    CACertPath:  "/path/to/ca-cert.pem",  // Optional: custom CA
})

// NEVER do this in production:
// AllowInsecureHTTP: true  ❌
```

### 4. Configure Offline Grace Period

Set appropriate offline validation limits:

```go
client, err := licensing.NewClient(licensing.Config{
    OfflineGracePeriod: 7 * 24 * time.Hour,  // 7 days grace period
    MaxOfflineDays:     30,                   // 30 days maximum
})
```

### 5. Monitor Security Metrics

Regularly check security metrics for anomalies:

```go
metrics := client.GetSecurityMetrics()
if metrics.TamperingAttempts > 0 {
    log.Printf("WARNING: %d tampering attempts detected", metrics.TamperingAttempts)
    // Take appropriate action (notify admin, block access, etc.)
}
if metrics.FailedVerifications > 10 {
    log.Printf("WARNING: High failure rate: %d/%d",
        metrics.FailedVerifications, metrics.TotalVerifications)
}
```

### 6. Protect License Files

The SDK automatically sets `0600` permissions on license files. Ensure the config directory is also protected:

```bash
chmod 700 ~/.myapp
```

### 7. Handle Expiration Proactively

Alert users before expiration:

```go
if time.Until(license.ExpiresAt) < 7*24*time.Hour {
    log.Warn("License expires in less than 7 days!")
    // Show renewal prompt to user
}
```

### 8. Don't Embed Secrets in Code

```go
// ❌ Don't do this
licenseKey := "ABCD-EFGH-..."
sshKey := "/home/hardcoded/.ssh/key"

// ✅ Use environment variables or config files
licenseKey := os.Getenv("LICENSE_KEY")
sshKey := os.Getenv("SSH_KEY_PATH")
```

### 9. Use Multi-Layer Verification

For critical applications, use `VerifyWithIntegrity()` instead of basic `Verify()`:

```go
// Basic verification (fast)
license, err := client.Verify()

// Multi-layer verification (recommended for security-critical apps)
license, integrity, err := client.VerifyWithIntegrity()
if err != nil || !integrity.IsValid {
    log.Fatalf("Security verification failed")
}
```

### 10. Implement Secure Error Handling

Don't expose detailed error messages to end users:

```go
if err := client.Activate(...); err != nil {
    // ❌ Don't show technical details to users
    // fmt.Printf("Activation failed: %v", err)

    // ✅ Show user-friendly message, log details
    log.Printf("Activation error: %v", err)
    fmt.Println("Unable to activate license. Please contact support.")
}
```

## Protocol Details

### Key Algorithms

- **Transport Key**: `SHA-256(fingerprint + hex(nonce))` → 32-byte AES key
- **Encryption**: AES-256-GCM with 12-byte nonce
- **Signature**: RSA-PSS with SHA-256 (max salt length = 222 bytes for 2048-bit keys)
- **SSH Authentication**: Ed25519 signature with SHA-512
- **Checksum Key**: `SHA-256("github.com/oarkflow/licensing/client-checksum/v1" + fingerprint)`

### Device Fingerprint

```go
fingerprint = SHA256("HOST:<hostname>|OS:<os>|ARCH:<arch>|MAC:<mac>|CPU:<cpu_hash>")
```

### Multi-Layer Verification

The SDK performs these checks during `VerifyWithIntegrity()`:

1. **Signature Layer**: Verify RSA-PSS signature on license data
2. **Integrity Layer**: Check for file tampering and unauthorized modifications
3. **Hardware Layer**: Validate device fingerprint matches
4. **Time Layer**: Verify license not expired and within grace period
5. **Network Layer**: Check revocation status (if online)

## Cryptographic Operations

The SDK provides helper functions for advanced cryptographic operations:

```go
// Generate Ed25519 key pair
privateKeyPEM, publicKeyPEM, err := licensing.GenerateEd25519KeyPair()

// Sign data with Ed25519
signature, err := licensing.SignRequest(privateKey, data)

// Verify Ed25519 signature
valid := licensing.VerifyEd25519Signature(publicKey, data, signature)

// AES-256-GCM encryption/decryption
ciphertext, err := licensing.EncryptAESGCM(key, plaintext)
plaintext, err := licensing.DecryptAESGCM(key, ciphertext)

// Compute SHA-256 hash
hash := licensing.ComputeSHA256(data)
fileHash, err := licensing.ComputeFileSHA256("/path/to/file")

// Secure random bytes
randomBytes, err := licensing.SecureRandomBytes(32)

// Secure file deletion
err := licensing.SecureDelete("/path/to/sensitive/file")
```

## Related Documentation

- [Client Security Guide](../../backend/CLIENT_SECURITY.md)
- [SDK Developer Guide](../../docs/SDK_GUIDE.md)
- [SDK Protocol Specification](../../docs/sdk_protocol.md)
- [OpenAPI Specification](../../docs/api/licensing_openapi.yaml)

## License

MIT License - see LICENSE file for details.
