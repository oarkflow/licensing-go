package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTamperDetector(t *testing.T) {
	td := NewTamperDetector(100 * time.Millisecond)
	if td == nil {
		t.Fatal("expected non-nil TamperDetector")
	}
	td.Start()
	time.Sleep(50 * time.Millisecond)
	td.Stop()
	failures := td.Failures()
	_ = failures
}

func TestEnableTamperDetection(t *testing.T) {
	cfg := ResolveClientConfig(Config{
		ServerURL:         "http://localhost:9999",
		AllowInsecureHTTP: true,
	})
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	c.EnableTamperDetection()
	if !c.TamperEnabled {
		t.Fatal("expected TamperEnabled to be true")
	}
	if c.TamperDetector == nil {
		t.Fatal("expected TamperDetector to be non-nil")
	}
	if c.SecurityMetrics == nil {
		t.Fatal("expected SecurityMetrics to be non-nil")
	}
}

func TestRunIntegrityChecks(t *testing.T) {
	cfg := ResolveClientConfig(Config{
		ServerURL:         "http://localhost:9999",
		AllowInsecureHTTP: true,
	})
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	failures := c.RunIntegrityChecks()
	_ = failures
}

func TestVerifyWithIntegrity(t *testing.T) {
	cfg := ResolveClientConfig(Config{
		ServerURL:         "http://localhost:9999",
		AllowInsecureHTTP: true,
	})
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	c.EnableTamperDetection()
	_, failures, err := c.VerifyWithIntegrity()
	if err == nil {
		t.Log("expected error (no server), got nil")
	}
	_ = failures
}

func TestGetSecurityMetrics(t *testing.T) {
	cfg := ResolveClientConfig(Config{
		ServerURL:         "http://localhost:9999",
		AllowInsecureHTTP: true,
	})
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	_, err = c.GetSecurityMetrics()
	if err == nil {
		t.Fatal("expected error when security metrics not initialized")
	}
	c.EnableTamperDetection()
	snap, err := c.GetSecurityMetrics()
	if err != nil {
		t.Fatalf("GetSecurityMetrics failed: %v", err)
	}
	if snap.TotalValidations != 0 {
		t.Fatalf("expected 0 validations, got %d", snap.TotalValidations)
	}
}

func TestPinnedCertVerifier(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: nil,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}
	h := sha256.Sum256(certDER)
	pinnedHash := hex.EncodeToString(h[:])
	verifier := pinnedCertVerifier(pinnedHash)
	err = verifier([][]byte{certDER}, nil)
	if err != nil {
		t.Fatalf("expected no error with matching hash, got: %v", err)
	}
	verifier2 := pinnedCertVerifier(hex.EncodeToString([]byte{1, 2, 3, 4}))
	err = verifier2([][]byte{certDER}, nil)
	if err == nil {
		t.Fatal("expected error with wrong hash")
	}
	err = verifier(nil, nil)
	if err == nil {
		t.Fatal("expected error with empty certs")
	}
}

func TestEncryptDecryptEnvelope(t *testing.T) {
	key := DeriveSessionKey([]byte("test-secret"))
	plaintext := []byte("hello, secure world!")
	env, err := EncryptEnvelope(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptEnvelope failed: %v", err)
	}
	decrypted, err := DecryptEnvelope(env, key)
	if err != nil {
		t.Fatalf("DecryptEnvelope failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %s, want %s", decrypted, plaintext)
	}
	wrongKey := DeriveSessionKey([]byte("wrong-secret"))
	_, err = DecryptEnvelope(env, wrongKey)
	if err == nil {
		t.Fatal("expected error with wrong key")
	}
	env[0] ^= 0xFF
	_, err = DecryptEnvelope(env, key)
	if err == nil {
		t.Fatal("expected error with corrupted envelope")
	}
}

func TestKeyRotationManager(t *testing.T) {
	krm := NewKeyRotationManager(90*24*time.Hour, 7*24*time.Hour)
	rec, err := krm.GenerateAndRotate()
	if err != nil {
		t.Fatalf("GenerateAndRotate failed: %v", err)
	}
	if rec.ID == "" {
		t.Fatal("expected non-empty key ID")
	}
	if !rec.Active {
		t.Fatal("expected new key to be active")
	}
	active := krm.ActiveKeys()
	if len(active) != 1 {
		t.Fatalf("expected 1 active key, got %d", len(active))
	}
}

func TestDeriveSessionKey(t *testing.T) {
	key1 := DeriveSessionKey([]byte("shared-secret"))
	key2 := DeriveSessionKey([]byte("shared-secret"))
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key1))
	}
	if string(key1) != string(key2) {
		t.Fatal("expected deterministic key derivation")
	}
}

func TestSecurityMetrics(t *testing.T) {
	sm := NewSecurityMetrics()
	sm.RecordValidation(true)
	sm.RecordValidation(false)
	sm.RecordValidation(true)
	sm.RecordTamperCheck(true)
	sm.RecordTamperCheck(false)
	sm.SetDebuggerDetected()
	snap := sm.Snapshot()
	if snap.TotalValidations != 3 {
		t.Fatalf("expected 3 total validations, got %d", snap.TotalValidations)
	}
	if snap.FailedValidations != 1 {
		t.Fatalf("expected 1 failed validation, got %d", snap.FailedValidations)
	}
	if snap.TamperFailures != 1 {
		t.Fatalf("expected 1 tamper failure, got %d", snap.TamperFailures)
	}
	if !snap.DebuggerDetected {
		t.Fatal("expected debugger detected")
	}
}

func TestSSHKeyAuth(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	keyFile := filepath.Join(t.TempDir(), "test_key.pem")
	if err := os.WriteFile(keyFile, privPEM, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg := ResolveClientConfig(Config{
		ServerURL:         "http://localhost:9999",
		SSHKeyPath:        keyFile,
		ClientID:          "test-client",
		AllowInsecureHTTP: true,
	})
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	c.addSSHKeyAuth(req)
	if req.Header.Get("X-Client-ID") != "test-client" {
		t.Fatal("expected X-Client-ID header")
	}
	if req.Header.Get("X-Timestamp") == "" {
		t.Fatal("expected X-Timestamp header")
	}
	if req.Header.Get("X-Signature") == "" {
		t.Fatal("expected X-Signature header")
	}

	sigHex := req.Header.Get("X-Signature")
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("DecodeString failed: %v", err)
	}
	msg := "test-client:" + req.Header.Get("X-Timestamp")
	if !ed25519.Verify(pubKey, []byte(msg), sig) {
		t.Fatal("signature verification failed")
	}
}

func BenchmarkTamperDetection(b *testing.B) {
	td := NewTamperDetector(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		td.runChecks()
	}
}
