package licensing

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const checksumKeySalt = "github.com/oarkflow/licensing/client-checksum/v1"

type CouponRedemption struct {
	ID         string            `json:"id"`
	CouponID   string            `json:"coupon_id"`
	CouponCode string            `json:"coupon_code"`
	LicenseID  string            `json:"license_id"`
	ClientID   string            `json:"client_id"`
	RedeemedBy string            `json:"redeemed_by,omitempty"`
	RedeemedAt time.Time         `json:"redeemed_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type redeemCouponRequest struct {
	Code       string            `json:"code"`
	RedeemedBy string            `json:"redeemed_by,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type redeemCouponResponse struct {
	License    *LicenseData      `json:"license"`
	Redemption *CouponRedemption `json:"redemption"`
}

type checksumRecord struct {
	Version   int       `json:"version"`
	Nonce     string    `json:"nonce"`
	Payload   string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

// ApplyCoupon redeems a coupon for the active license and refreshes the stored
// local license file so the updated entitlements are available immediately.
func (c *Client) ApplyCoupon(code string) (*LicenseData, *CouponRedemption, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, nil, fmt.Errorf("coupon code is required")
	}

	license, err := c.Verify()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load active license: %w", err)
	}

	reqBody, err := json.Marshal(redeemCouponRequest{
		Code:       code,
		RedeemedBy: strings.TrimSpace(license.Email),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal coupon request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.ServerURL()+"/api/licenses/"+license.ID+"/coupons", bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build coupon request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent())

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to redeem coupon: %w", err)
	}
	defer resp.Body.Close()

	var redeemResp redeemCouponResponse
	if err := decodeAPIResponse(resp, &redeemResp); err != nil {
		return nil, nil, err
	}

	refreshed, err := c.refreshLicense(license)
	if err != nil {
		return redeemResp.License, redeemResp.Redemption, fmt.Errorf("coupon redeemed but failed to refresh local license file: %w", err)
	}
	return refreshed, redeemResp.Redemption, nil
}

func (c *Client) refreshLicense(current *LicenseData) (*LicenseData, error) {
	fingerprint, err := c.GetDeviceFingerprint()
	if err != nil {
		return nil, fmt.Errorf("failed to get device fingerprint: %w", err)
	}

	reqBody, err := json.Marshal(ActivationRequest{
		Email:             strings.TrimSpace(current.Email),
		ClientID:          strings.TrimSpace(current.ClientID),
		LicenseKey:        strings.TrimSpace(current.LicenseKey),
		DeviceFingerprint: fingerprint,
		ProductID:         strings.TrimSpace(current.ProductID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal verify request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.ServerURL()+"/api/verify", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to build verify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent())

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServerUnavailable, err)
	}
	defer resp.Body.Close()

	var verifyResp ActivationResponse
	if err := decodeAPIResponse(resp, &verifyResp); err != nil {
		return nil, err
	}
	if !verifyResp.Success {
		msg := strings.TrimSpace(verifyResp.Message)
		if msg == "" {
			msg = "license verification failed"
		}
		return nil, fmt.Errorf("%s", msg)
	}

	stored, err := BuildStoredLicenseFromResponse(&verifyResp, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to build refreshed license: %w", err)
	}
	if err := c.writeStoredLicense(stored); err != nil {
		return nil, err
	}
	return c.Verify()
}

func (c *Client) writeStoredLicense(stored *StoredLicense) error {
	if stored == nil {
		return fmt.Errorf("license payload missing")
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal stored license: %w", err)
	}
	tmpPath := c.licensePath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("failed to write license: %w", err)
	}
	if err := c.persistLicenseChecksum(stored.DeviceFingerprint, raw); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to persist license checksum: %w", err)
	}
	if err := os.Rename(tmpPath, c.licensePath); err != nil {
		_ = os.Remove(tmpPath)
		_ = os.Remove(c.checksumPath)
		return fmt.Errorf("failed to finalize license: %w", err)
	}
	return nil
}

func (c *Client) persistLicenseChecksum(fingerprint string, licenseJSON []byte) error {
	checksum := sha256.Sum256(licenseJSON)
	key := sha256.Sum256([]byte(checksumKeySalt + strings.TrimSpace(fingerprint)))
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate checksum nonce: %w", err)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return fmt.Errorf("failed to create checksum cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to initialize checksum cipher: %w", err)
	}
	record := checksumRecord{
		Version:   1,
		Nonce:     hex.EncodeToString(nonce),
		Payload:   hex.EncodeToString(gcm.Seal(nil, nonce, checksum[:], nil)),
		CreatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal checksum record: %w", err)
	}
	tmpPath := c.checksumPath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("failed to write checksum file: %w", err)
	}
	if err := os.Rename(tmpPath, c.checksumPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize checksum file: %w", err)
	}
	return nil
}

func (c *Client) httpClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(c.config.CACertPath) != "" {
		caBytes, err := os.ReadFile(c.config.CACertPath)
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(caBytes) {
				tlsConfig.RootCAs = pool
			}
		}
	}
	if c.config.AllowInsecureHTTP {
		tlsConfig.InsecureSkipVerify = true
	}
	if c.config.PinnedCertHash != "" {
		verifier := pinnedCertVerifier(c.config.PinnedCertHash)
		orig := tlsConfig.VerifyPeerCertificate
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if err := verifier(rawCerts, verifiedChains); err != nil {
				return err
			}
			if orig != nil {
				return orig(rawCerts, verifiedChains)
			}
			return nil
		}
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: c.config.HTTPTimeout, Transport: transport}
}

func (c *Client) addSSHKeyAuth(r *http.Request) {
	if c.config.SSHKeyPath == "" || c.config.ClientID == "" {
		return
	}
	data, err := os.ReadFile(c.config.SSHKeyPath)
	if err != nil {
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	edKey, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	msg := c.config.ClientID + ":" + ts
	sig, err := edKey.Sign(rand.Reader, []byte(msg), crypto.Hash(0))
	if err != nil {
		return
	}
	r.Header.Set("X-Client-ID", c.config.ClientID)
	r.Header.Set("X-Timestamp", ts)
	r.Header.Set("X-Signature", hex.EncodeToString(sig))
}

func (c *Client) userAgent() string {
	appName := strings.TrimSpace(c.config.AppName)
	if appName == "" {
		appName = "licensing-go"
	}
	appVersion := strings.TrimSpace(c.config.AppVersion)
	if appVersion == "" {
		appVersion = "dev"
	}
	return appName + "/" + appVersion
}

func decodeAPIResponse(resp *http.Response, out interface{}) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(extractResponseMessage(body))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("%s", msg)
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

func extractResponseMessage(body []byte) string {
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		if strings.TrimSpace(payload.Error) != "" {
			return payload.Error
		}
		if strings.TrimSpace(payload.Message) != "" {
			return payload.Message
		}
	}
	return string(bytes.TrimSpace(body))
}
