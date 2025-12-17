package licensing

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const fixturesDir = "../../docs/fixtures/v1"

func TestFixtureDecryption(t *testing.T) {
	// Load activation_response.json
	respData, err := os.ReadFile(filepath.Join(fixturesDir, "activation_response.json"))
	if err != nil {
		t.Fatalf("failed to read activation_response.json: %v", err)
	}
	var resp ActivationResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("failed to unmarshal activation response: %v", err)
	}

	// Load activation_request.json to get fingerprint
	reqData, err := os.ReadFile(filepath.Join(fixturesDir, "activation_request.json"))
	if err != nil {
		t.Fatalf("failed to read activation_request.json: %v", err)
	}
	var req map[string]interface{}
	if err := json.Unmarshal(reqData, &req); err != nil {
		t.Fatalf("failed to unmarshal activation request: %v", err)
	}
	fingerprint := req["device_fingerprint"].(string)

	// Build stored license from response
	stored, err := BuildStoredLicenseFromResponse(&resp, fingerprint)
	if err != nil {
		t.Fatalf("failed to build stored license: %v", err)
	}

	// Test signature verification
	if err := VerifyStoredLicenseSignature(stored); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
	t.Log("✓ Signature verification passed")

	// Test decryption (provide the device fingerprint to ensure binding)
	license, _, err := DecryptStoredLicense(stored, fingerprint)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	t.Log("✓ Decryption passed")

	// Load expected license_data.json for comparison
	expectedData, err := os.ReadFile(filepath.Join(fixturesDir, "license_data.json"))
	if err != nil {
		t.Fatalf("failed to read license_data.json: %v", err)
	}
	var expected LicenseData
	if err := json.Unmarshal(expectedData, &expected); err != nil {
		t.Fatalf("failed to unmarshal expected license: %v", err)
	}

	// Compare fields
	if license.ID != expected.ID {
		t.Errorf("ID mismatch: got %s, want %s", license.ID, expected.ID)
	}
	if license.PlanSlug != expected.PlanSlug {
		t.Errorf("PlanSlug mismatch: got %s, want %s", license.PlanSlug, expected.PlanSlug)
	}
	if license.MaxDevices != expected.MaxDevices {
		t.Errorf("MaxDevices mismatch: got %d, want %d", license.MaxDevices, expected.MaxDevices)
	}
	if len(license.Devices) != len(expected.Devices) {
		t.Errorf("Devices length mismatch: got %d, want %d", len(license.Devices), len(expected.Devices))
	}
	t.Log("✓ License data matches expected values")
}

func TestStoredLicenseDecryption(t *testing.T) {
	// Load stored_license.json
	storedData, err := os.ReadFile(filepath.Join(fixturesDir, "stored_license.json"))
	if err != nil {
		t.Fatalf("failed to read stored_license.json: %v", err)
	}
	var stored StoredLicense
	if err := json.Unmarshal(storedData, &stored); err != nil {
		t.Fatalf("failed to unmarshal stored license: %v", err)
	}

	// Verify signature
	if err := VerifyStoredLicenseSignature(&stored); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
	t.Log("✓ Stored license signature verification passed")

	// Decrypt (provide the stored fingerprint)
	license, _, err := DecryptStoredLicense(&stored, stored.DeviceFingerprint)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	t.Log("✓ Stored license decryption passed")

	// Verify product info is present
	if license.ID == "" {
		t.Error("ID is empty")
	}
	if license.PlanSlug == "" {
		t.Error("PlanSlug is empty")
	}
	t.Logf("✓ License: %s for plan %s", license.ID, license.PlanSlug)
}

func TestChecksumVerification(t *testing.T) {
	// Load license.dat (the compact version - this is what the checksum is calculated on)
	licenseData, err := os.ReadFile(filepath.Join(fixturesDir, "license.dat"))
	if err != nil {
		t.Fatalf("failed to read license.dat: %v", err)
	}
	var stored StoredLicense
	if err := json.Unmarshal(licenseData, &stored); err != nil {
		t.Fatalf("failed to unmarshal license.dat: %v", err)
	}

	// Load checksum_pretty.json
	checksumData, err := os.ReadFile(filepath.Join(fixturesDir, "checksum_pretty.json"))
	if err != nil {
		t.Fatalf("failed to read checksum_pretty.json: %v", err)
	}
	var checksumObj struct {
		Version   int    `json:"version"`
		Nonce     string `json:"nonce"`
		Payload   string `json:"payload"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(checksumData, &checksumObj); err != nil {
		t.Fatalf("failed to unmarshal checksum: %v", err)
	}

	// Compute checksum of license.dat (raw JSON)
	computedHash := sha256.Sum256(licenseData)
	t.Logf("Computed hash: %s", hex.EncodeToString(computedHash[:]))

	// Verify encrypted checksum can be decrypted to the hash
	err = verifyEncryptedChecksum(stored.DeviceFingerprint, checksumObj.Payload, checksumObj.Nonce, computedHash[:])
	if err != nil {
		t.Fatalf("checksum verification failed: %v", err)
	}
	t.Log("✓ Encrypted checksum verification passed")
}

// checksumKeySalt is the constant used in the licensing library
const checksumKeySalt = "github.com/oarkflow/licensing/client-checksum/v1"

func verifyEncryptedChecksum(fingerprint, encryptedHex, nonceHex string, expectedHash []byte) error {
	// Derive key: SHA256(checksumKeySalt + fingerprint)
	keyMaterial := checksumKeySalt + fingerprint
	key := sha256.Sum256([]byte(keyMaterial))

	// Decode encrypted hash and nonce
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return fmt.Errorf("failed to decode encrypted hash: %w", err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Decrypt
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}
	decrypted, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	if !bytes.Equal(decrypted, expectedHash) {
		return fmt.Errorf("decrypted hash mismatch: got %s, want %s", hex.EncodeToString(decrypted), hex.EncodeToString(expectedHash))
	}

	return nil
}

func TestBinaryLicenseFile(t *testing.T) {
	// Load license.dat
	licenseData, err := os.ReadFile(filepath.Join(fixturesDir, "license.dat"))
	if err != nil {
		t.Fatalf("failed to read license.dat: %v", err)
	}

	// Verify it can be unmarshaled as StoredLicense
	var stored StoredLicense
	if err := json.Unmarshal(licenseData, &stored); err != nil {
		t.Fatalf("failed to unmarshal license.dat: %v", err)
	}

	// Verify signature
	if err := VerifyStoredLicenseSignature(&stored); err != nil {
		t.Fatalf("license.dat signature verification failed: %v", err)
	}
	t.Log("✓ license.dat signature verification passed")

	// Decrypt (use the fingerprint embedded in the file)
	license, _, err := DecryptStoredLicense(&stored, stored.DeviceFingerprint)
	if err != nil {
		t.Fatalf("license.dat decryption failed: %v", err)
	}
	t.Logf("✓ license.dat decrypted: %s (plan: %s)", license.ID, license.PlanSlug)
}

func TestDecryptFailsWithWrongFingerprint(t *testing.T) {
	// Load stored_license.json
	storedData, err := os.ReadFile(filepath.Join(fixturesDir, "stored_license.json"))
	if err != nil {
		t.Fatalf("failed to read stored_license.json: %v", err)
	}
	var stored StoredLicense
	if err := json.Unmarshal(storedData, &stored); err != nil {
		t.Fatalf("failed to unmarshal stored license: %v", err)
	}

	// Attempt to decrypt using an incorrect fingerprint
	_, _, err = DecryptStoredLicense(&stored, "incorrect-fingerprint")
	if err == nil {
		t.Fatalf("expected decryption to fail with wrong fingerprint")
	}
	t.Logf("✓ Decryption failed with wrong fingerprint as expected: %v", err)
}

func TestCanPerformWithContextSDK(t *testing.T) {
	lic := LicenseData{}
	lic.Entitlements = &LicenseEntitlements{Features: map[string]FeatureGrant{
		"file": {
			Enabled: true,
			Scopes: map[string]ScopeGrant{
				"basic_storage": {ScopeSlug: "basic_storage", Permission: ScopePermissionLimit, Limit: 0, Restrictions: []ScopeRestriction{{Type: UsageRestrictionStorage, Limit: 10}}},
				"export":        {ScopeSlug: "export", Permission: ScopePermissionLimit, Limit: 0, Restrictions: []ScopeRestriction{{Type: UsageRestrictionDevice, Limit: 2}, {Type: UsageRestrictionUser, Limit: 3}}},
			},
		},
	}}

	ok, _, _ := lic.CanPerformWithContext("file", "basic_storage", UsageContext{SubjectType: SubjectTypeStorage, Amount: 5})
	if !ok {
		t.Fatal("expected allowed for storage amount 5")
	}
	ok, _, reason := lic.CanPerformWithContext("file", "basic_storage", UsageContext{SubjectType: SubjectTypeStorage, Amount: 15})
	if ok {
		t.Fatalf("expected denied for storage amount 15 (%v)", reason)
	}

	ok, _, _ = lic.CanPerformWithContext("file", "export", UsageContext{SubjectType: SubjectTypeDevice, SubjectID: "dev1", Amount: 1})
	if !ok {
		t.Fatal("device 1 should be allowed")
	}
	ok, _, _ = lic.CanPerformWithContext("file", "export", UsageContext{SubjectType: SubjectTypeDevice, SubjectID: "dev1", Amount: 3})
	if ok {
		t.Fatal("device 3 should be denied")
	}
	ok, _, _ = lic.CanPerformWithContext("file", "export", UsageContext{SubjectType: SubjectTypeUser, SubjectID: "user1", Amount: 2})
	if !ok {
		t.Fatal("user 2 should be allowed")
	}
	ok, _, _ = lic.CanPerformWithContext("file", "export", UsageContext{SubjectType: SubjectTypeUser, SubjectID: "user1", Amount: 4})
	if ok {
		t.Fatal("user 4 should be denied")
	}
}
