package licensing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"
)

// KeyRecord represents a key used for signing or encryption within a rotation window.
type KeyRecord struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"public_key"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// KeyRotationManager manages periodic key rotation with overlap windows.
type KeyRotationManager struct {
	mu       sync.Mutex
	keys     []KeyRecord
	rotation time.Duration
	overlap  time.Duration
}

// NewKeyRotationManager creates a new key rotation manager.
func NewKeyRotationManager(rotationInterval, overlapWindow time.Duration) *KeyRotationManager {
	if rotationInterval <= 0 {
		rotationInterval = 90 * 24 * time.Hour
	}
	if overlapWindow <= 0 {
		overlapWindow = 7 * 24 * time.Hour
	}
	return &KeyRotationManager{
		rotation: rotationInterval,
		overlap:  overlapWindow,
	}
}

// GenerateAndRotate generates a new key pair, adds it as active, and expires old keys.
func (krm *KeyRotationManager) GenerateAndRotate() (*KeyRecord, error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	h := sha256.Sum256(pubKeyBytes)
	id := fmt.Sprintf("%x", h[:8])

	now := time.Now()
	record := KeyRecord{
		ID:        id,
		PublicKey: string(pubPEM),
		Active:    true,
		CreatedAt: now,
		ExpiresAt: now.Add(krm.rotation + krm.overlap),
	}

	for i := range krm.keys {
		if now.After(krm.keys[i].ExpiresAt) {
			krm.keys[i].Active = false
		}
	}

	krm.keys = append(krm.keys, record)
	_ = privateKey

	return &record, nil
}

// ActiveKeys returns all currently active key records.
func (krm *KeyRotationManager) ActiveKeys() []KeyRecord {
	krm.mu.Lock()
	defer krm.mu.Unlock()
	var active []KeyRecord
	for _, k := range krm.keys {
		if k.Active {
			active = append(active, k)
		}
	}
	return active
}
