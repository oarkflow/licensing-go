package licensing

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplyCouponRefreshesStoredLicenseEntitlements(t *testing.T) {
	var couponCalls atomic.Int32
	var verifyCalls atomic.Int32

	initial := &LicenseData{
		ID:         "lic-123",
		ClientID:   "client-123",
		Email:      "user@example.com",
		ProductID:  "prod-1",
		PlanSlug:   "starter",
		LicenseKey: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CheckMode:  "none",
		Entitlements: &LicenseEntitlements{
			ProductID: "prod-1",
			PlanSlug:  "starter",
			Features: map[string]FeatureGrant{
				"files": {
					FeatureSlug: "files",
					Enabled:     true,
					Scopes: map[string]ScopeGrant{
						"export": {ScopeSlug: "export", Permission: ScopePermissionDeny},
					},
				},
			},
		},
	}

	updated := &LicenseData{
		ID:         initial.ID,
		ClientID:   initial.ClientID,
		Email:      initial.Email,
		ProductID:  initial.ProductID,
		PlanSlug:   initial.PlanSlug,
		LicenseKey: initial.LicenseKey,
		ExpiresAt:  initial.ExpiresAt,
		CheckMode:  initial.CheckMode,
		Entitlements: &LicenseEntitlements{
			ProductID: "prod-1",
			PlanSlug:  "starter",
			Features: map[string]FeatureGrant{
				"files": {
					FeatureSlug: "files",
					Enabled:     true,
					Scopes: map[string]ScopeGrant{
						"export": {ScopeSlug: "export", Permission: ScopePermissionAllow},
					},
				},
			},
		},
	}

	var fingerprint string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/licenses/lic-123/coupons":
			couponCalls.Add(1)
			var req redeemCouponRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode coupon request: %v", err)
			}
			if req.Code != "BONUS_EXPORT" {
				t.Fatalf("unexpected coupon code %q", req.Code)
			}
			_ = json.NewEncoder(w).Encode(redeemCouponResponse{
				License: updated,
				Redemption: &CouponRedemption{
					ID:         "red-1",
					CouponID:   "coupon-1",
					CouponCode: req.Code,
					LicenseID:  initial.ID,
					ClientID:   initial.ClientID,
					RedeemedBy: initial.Email,
					RedeemedAt: time.Now().UTC(),
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/verify":
			verifyCalls.Add(1)
			resp := mustActivationResponse(t, fingerprint, updated)
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := Config{
		ServerURL:         server.URL,
		ConfigDir:         t.TempDir(),
		LicenseFile:       "license.dat",
		AppName:           "coupon-test",
		AppVersion:        "1.0.0",
		AllowInsecureHTTP: true,
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	fingerprint, err = client.GetDeviceFingerprint()
	if err != nil {
		t.Fatalf("failed to get fingerprint: %v", err)
	}

	stored, err := BuildStoredLicenseFromResponse(mustActivationResponse(t, fingerprint, initial), fingerprint)
	if err != nil {
		t.Fatalf("failed to build stored license: %v", err)
	}
	if err := client.writeStoredLicense(stored); err != nil {
		t.Fatalf("failed to seed stored license: %v", err)
	}

	before, err := client.Verify()
	if err != nil {
		t.Fatalf("failed to verify initial license: %v", err)
	}
	if before.HasScope("files", "export") {
		t.Fatal("expected export scope to be unavailable before coupon redemption")
	}

	refreshed, redemption, err := client.ApplyCoupon("BONUS_EXPORT")
	if err != nil {
		t.Fatalf("apply coupon failed: %v", err)
	}
	if redemption == nil || redemption.CouponCode != "BONUS_EXPORT" {
		t.Fatalf("unexpected redemption response: %#v", redemption)
	}
	if !refreshed.HasScope("files", "export") {
		t.Fatal("expected refreshed license to include export scope")
	}

	after, err := client.Verify()
	if err != nil {
		t.Fatalf("failed to verify refreshed license: %v", err)
	}
	if !after.HasScope("files", "export") {
		t.Fatal("expected stored license file to contain refreshed entitlements")
	}
	if couponCalls.Load() != 1 {
		t.Fatalf("expected one coupon request, got %d", couponCalls.Load())
	}
	if verifyCalls.Load() != 1 {
		t.Fatalf("expected one verify refresh request, got %d", verifyCalls.Load())
	}
	if _, err := os.Stat(filepath.Join(cfg.ConfigDir, cfg.LicenseFile+".chk")); err != nil {
		t.Fatalf("expected checksum file to be updated: %v", err)
	}
}

func TestApplyCouponRequiresCode(t *testing.T) {
	cfg := Config{
		ConfigDir:         t.TempDir(),
		ServerURL:         "http://127.0.0.1:1",
		AllowInsecureHTTP: true,
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, _, err = client.ApplyCoupon("   ")
	if err == nil {
		t.Fatal("expected error for empty coupon code")
	}
	if !strings.Contains(err.Error(), "coupon code is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyCouponReturnsRedeemFailureWithoutRewritingLicense(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/licenses/lic-123/coupons" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "coupon has expired"})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	initial := &LicenseData{
		ID:         "lic-123",
		ClientID:   "client-123",
		Email:      "user@example.com",
		ProductID:  "prod-1",
		PlanSlug:   "starter",
		LicenseKey: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CheckMode:  "none",
		Entitlements: &LicenseEntitlements{
			ProductID: "prod-1",
			PlanSlug:  "starter",
			Features: map[string]FeatureGrant{
				"files": {
					FeatureSlug: "files",
					Enabled:     true,
					Scopes: map[string]ScopeGrant{
						"export": {ScopeSlug: "export", Permission: ScopePermissionDeny},
					},
				},
			},
		},
	}

	cfg := Config{
		ServerURL:         server.URL,
		ConfigDir:         t.TempDir(),
		LicenseFile:       "license.dat",
		AppName:           "coupon-test",
		AppVersion:        "1.0.0",
		AllowInsecureHTTP: true,
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	fingerprint, err := client.GetDeviceFingerprint()
	if err != nil {
		t.Fatalf("failed to get fingerprint: %v", err)
	}
	stored, err := BuildStoredLicenseFromResponse(mustActivationResponse(t, fingerprint, initial), fingerprint)
	if err != nil {
		t.Fatalf("failed to build stored license: %v", err)
	}
	if err := client.writeStoredLicense(stored); err != nil {
		t.Fatalf("failed to seed stored license: %v", err)
	}

	before, err := client.Verify()
	if err != nil {
		t.Fatalf("failed to verify initial license: %v", err)
	}
	if before.HasScope("files", "export") {
		t.Fatal("expected export scope to be unavailable before coupon redemption")
	}

	_, _, err = client.ApplyCoupon("EXPIRED")
	if err == nil {
		t.Fatal("expected coupon redemption error")
	}
	if !strings.Contains(err.Error(), "coupon has expired") {
		t.Fatalf("unexpected error: %v", err)
	}

	after, err := client.Verify()
	if err != nil {
		t.Fatalf("failed to verify license after failed redemption: %v", err)
	}
	if after.HasScope("files", "export") {
		t.Fatal("license entitlements should remain unchanged after failed redemption")
	}
}

func mustActivationResponse(t *testing.T, fingerprint string, license *LicenseData) *ActivationResponse {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	licenseJSON, err := json.Marshal(license)
	if err != nil {
		t.Fatalf("failed to marshal license: %v", err)
	}
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatalf("failed to generate session key: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	transportKey := sha256.Sum256([]byte(fingerprint + hex.EncodeToString(nonce)))
	block, err := aes.NewCipher(transportKey[:])
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to create gcm: %v", err)
	}
	encrypted := gcm.Seal(nil, nonce, append(sessionKey, licenseJSON...), nil)

	hash := sha256.Sum256(append(encrypted, []byte(strings.TrimSpace(fingerprint))...))
	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		t.Fatalf("failed to sign license: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	return &ActivationResponse{
		Success:          true,
		Message:          "ok",
		EncryptedLicense: hex.EncodeToString(encrypted),
		Nonce:            hex.EncodeToString(nonce),
		Signature:        hex.EncodeToString(signature),
		PublicKey:        string(pubPEM),
		ExpiresAt:        license.ExpiresAt,
	}
}
