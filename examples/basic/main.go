package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/oarkflow/licensing-go"
)

func main() {
	serverURL := flag.String("server", "http://localhost:6601", "License server URL (use HTTPS in production)")
	configDir := flag.String("config-dir", "", "Directory for license/device key storage")
	insecure := flag.Bool("insecure", false, "Allow insecure HTTP (dev only, not recommended)")
	productID := flag.String("product-id", "secretr", "Product ID or slug to validate the license against")
	licenseFile := flag.String("license-file", "", "Path to JSON file with license credentials")
	deviceKeyProvider := flag.String("device-key-provider", "software", "Device key provider: auto, tpm, os, or software")
	deviceKeyFile := flag.String("device-key-file", "", "Software device key filename/path")
	deviceKeyName := flag.String("device-key-name", "", "OS keyring key label")
	tpmDevice := flag.String("tpm-device", "", "TPM device path when forcing TPM")
	flag.Parse()
	cfg := licensing.Config{
		ServerURL:         *serverURL,
		ConfigDir:         *configDir,
		AppName:           "BasicExample",
		AppVersion:        "1.0.0",
		HTTPTimeout:       15 * time.Second,
		AllowInsecureHTTP: *insecure,
		LicenseFile:       *licenseFile,
		ProductID:         *productID,
		DeviceKeyProvider: *deviceKeyProvider,
		DeviceKeyFile:     *deviceKeyFile,
		DeviceKeyName:     *deviceKeyName,
		TPMDevice:         *tpmDevice,
	}
	licensing.Run(cfg, runApplication)
}

func runApplication(ctx context.Context, licenseData *licensing.LicenseData) error {
	printLicenseHeader(licenseData)
	fmt.Println("Application is running with a valid license.")
	return nil
}

func printLicenseHeader(licenseData *licensing.LicenseData) {
	if licenseData == nil {
		return
	}

	plan := strings.TrimSpace(licenseData.PlanSlug)
	client := strings.TrimSpace(licenseData.ClientID)
	email := strings.TrimSpace(licenseData.Email)
	expires := "Perpetual"
	var daysLeft string
	if !licenseData.ExpiresAt.IsZero() {
		expires = licenseData.ExpiresAt.Format("2006-01-02")
		remaining := time.Until(licenseData.ExpiresAt)
		days := int(remaining.Hours() / 24)
		if days >= 0 {
			daysLeft = fmt.Sprintf(" (%d days left)", days)
		}
	}

	status := "Active"
	if licenseData.IsTrial {
		status = "In Trial"
	}
	if licenseData.IsRevoked {
		status = "Revoked"
	}

	parts := []string{fmt.Sprintf("Status: %s", status)}
	if plan != "" {
		parts = append(parts, fmt.Sprintf("Plan: %s", plan))
	}
	if client != "" {
		parts = append(parts, fmt.Sprintf("Client: %s", client))
	}
	if email != "" {
		parts = append(parts, fmt.Sprintf("Email: %s", email))
	}
	if !licenseData.IssuedAt.IsZero() {
		parts = append(parts, fmt.Sprintf("Issued: %s", licenseData.IssuedAt.Format("2006-01-02")))
	}
	parts = append(parts, fmt.Sprintf("Expires: %s%s", expires, daysLeft))

	content := strings.Join(parts, " • ")
	box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Render(content)
	fmt.Println(box)
	fmt.Println()
}
