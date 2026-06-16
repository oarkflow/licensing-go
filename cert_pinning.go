package licensing

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// pinnedCertVerifier creates a certificate verification callback that enforces
// SHA-256 pinning on the server's leaf certificate.
func pinnedCertVerifier(pinnedHash string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no server certificates presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("failed to parse server certificate: %w", err)
		}
		der := cert.Raw
		h := sha256.Sum256(der)
		got := hex.EncodeToString(h[:])
		if got != pinnedHash {
			return fmt.Errorf("certificate pin mismatch: expected %s, got %s", pinnedHash, got)
		}
		return nil
	}
}
