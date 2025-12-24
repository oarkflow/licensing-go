package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/oarkflow/licensing-go"
)

func main() {
	os.Setenv("PG_DISABLE_RATE_LIMIT", "1")
	serverURL := flag.String("server", "http://localhost:6601", "License server URL (use HTTPS in production)")
	insecure := flag.Bool("insecure", false, "Allow insecure HTTP (dev only, not recommended)")
	productID := flag.String("product-id", "processgate", "Product ID for trial (optional)")
	licenseFile := flag.String("license-file", "", "Path to JSON file with license credentials")
	flag.Parse()
	cfg := licensing.Config{
		ServerURL:         *serverURL,
		AppName:           "BasicExample",
		AppVersion:        "1.0.0",
		HTTPTimeout:       15 * time.Second,
		AllowInsecureHTTP: *insecure,
		LicenseFile:       *licenseFile,
		ProductID:         *productID,
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
