package licensing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// DeriveSessionKey derives a 32-byte AES key from a shared secret using SHA-256.
func DeriveSessionKey(secret []byte) []byte {
	h := sha256.Sum256(secret)
	return h[:]
}

// EncryptEnvelope encrypts plaintext using AES-256-GCM with a random nonce.
// Returns nonce||ciphertext.
func EncryptEnvelope(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// DecryptEnvelope decrypts a nonce||ciphertext envelope using AES-256-GCM.
func DecryptEnvelope(envelope []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(envelope) < nonceSize {
		return nil, fmt.Errorf("envelope too short")
	}
	nonce, ciphertext := envelope[:nonceSize], envelope[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt envelope: %w", err)
	}
	return plaintext, nil
}
