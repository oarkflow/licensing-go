// Example: Basic license activation and verification with security
//
// This example shows the minimal code needed to:
// 1. Request a trial license (if eligible)
// 2. Activate a license with credentials
// 3. Verify the license is valid
// 4. Handle trial expiration with subscription prompts
// 5. Access license data and check features
// 6. Use SSH key authentication (recommended)
//
// Usage:
//    go run main.go --license-key "XXXX-XXXX-..." --email "user@example.com" --client-id "client-123"
//
// Or using a credentials file:
//    go run main.go --license-file "/path/to/credentials.json"
//
// Or start a trial:
//    go run main.go --trial --email "user@example.com"
//
// With SSH authentication (recommended):
//    go run main.go --license-key "XXXX-XXXX-..." --email "user@example.com" --client-id "client-123" --ssh-key ~/.ssh/licensing_client
//
// Credentials file format:
//    {"email": "user@example.com", "client_id": "client-123", "license_key": "XXXX-XXXX-..."}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	licensing "github.com/oarkflow/licensing-go"
)

func main() {
	// Command line flags
	serverURL := flag.String("server", "http://localhost:6601", "License server URL (use HTTPS in production)")
	email := flag.String("email", "", "Email for activation")
	licenseFile := flag.String("license-file", "", "Path to JSON file with license credentials")
	startTrial := flag.Bool("trial", false, "Start a trial license")
	productID := flag.String("product-id", "", "Product ID for trial (optional)")
	subscriptionURL := flag.String("subscription-url", "https://example.com/subscribe", "URL to subscribe after trial")
	sshKeyPath := flag.String("ssh-key", "", "Path to SSH private key for authentication (recommended)")
	offlineBundle := flag.String("offline-bundle", "", "Path to a signed offline bundle JSON to verify locally")
	offlineCache := flag.String("offline-cache", "", "Directory to cache revocation manifest for offline verification")
	insecure := flag.Bool("insecure", false, "Allow insecure HTTP (dev only, not recommended)")
	flag.Parse()

	fmt.Println("=== Go Licensing SDK - Basic Example ===")
	fmt.Println()

	// Collect CLI-provided credentials (lowest precedence). The SDK will handle
	// reading piped JSON and local files according to configured precedence.
	var credEmail string
	credEmail = *email

	// If an offline bundle path is provided, run offline verification path and exit
	if *offlineBundle != "" {
		fmt.Println("🔎 Offline verification mode — using offline verification SDK")
		oc, err := licensing.NewOfflineClient(licensing.OfflineConfig{ServerURL: *serverURL, CacheDir: *offlineCache})
		if err != nil {
			log.Fatalf("failed to create offline client: %v", err)
		}
		data, err := os.ReadFile(*offlineBundle)
		if err != nil {
			log.Fatalf("failed to read bundle: %v", err)
		}
		ctx := context.Background()
		payload, err := oc.VerifySignedBundle(ctx, string(data), "")
		if err != nil {
			log.Fatalf("offline verification failed: %v", err)
		}
		fmt.Printf("✅ Offline bundle verified: %+v\n", payload)
		// attempt to sync manifest
		if _, err := oc.SyncManifest(ctx, ""); err == nil {
			fmt.Println("manifest synced — revocation checks applied if any")
		}
		return
	}

	// Create licensing client
	client, err := licensing.NewClient(licensing.Config{
		ServerURL:         *serverURL,
		AppName:           "BasicExample",
		AppVersion:        "1.0.0",
		HTTPTimeout:       15 * time.Second,
		AllowInsecureHTTP: *insecure,
		ProductID:         "secretr",
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	if *sshKeyPath != "" {
		fmt.Printf("🔐 SSH key path provided: %s (Note: SSH auth integration pending)\n", *sshKeyPath)
	}

	// Define the application handler that runs after successful activation/verification.
	appHandler := func(ctx context.Context, license *licensing.LicenseData) error {
		// Check for trial status and handle expiration
		if license.IsTrial {
			trialInfo := license.GetTrialInfo()
			fmt.Println()
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("🎁 TRIAL LICENSE")
			fmt.Println("═══════════════════════════════════════════════════════════════")

			if trialInfo.IsExpired {
				// Trial has expired - show subscription prompt
				fmt.Println("⚠️  Your trial has expired!")
				fmt.Println()
				fmt.Printf("🔗 Subscribe now: %s\n", *subscriptionURL)
				fmt.Println()
				fmt.Println("Or enter your license credentials:")
				fmt.Println("  go run main.go --license-key KEY --email EMAIL --client-id ID")
				fmt.Println("═══════════════════════════════════════════════════════════════")
				return fmt.Errorf("trial license expired")
			}

			// Trial is still active
			fmt.Printf("📅 %s\n", trialInfo.Message)
			if trialInfo.DaysRemaining <= 3 {
				fmt.Println()
				fmt.Println("⚠️  Your trial is ending soon!")
				fmt.Printf("🔗 Subscribe to continue: %s\n", *subscriptionURL)
			}
			fmt.Println("═══════════════════════════════════════════════════════════════")
		}

		// Display license info
		fmt.Println()
		fmt.Println("=== License Information ===")
		fmt.Printf("ID:          %s\n", license.ID)
		fmt.Printf("Email:       %s\n", license.Email)
		fmt.Printf("Plan:        %s\n", license.PlanSlug)
		if license.IsTrial {
			fmt.Printf("Type:        🎁 Trial\n")
			fmt.Printf("Trial Ends:  %s\n", license.TrialExpiresAt.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("Type:        Licensed\n")
		}
		fmt.Printf("Issued:      %s\n", license.IssuedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Expires:     %s\n", license.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Max Devices: %d\n", license.MaxDevices)
		fmt.Printf("Activated:   %d device(s)\n", license.CurrentActivations)

		// Step 5: Check features (if entitlements are configured)
		fmt.Println()
		fmt.Println("=== Feature Access ===")

		if license.Entitlements != nil {
			fmt.Printf("Product: %s\n", license.Entitlements.ProductSlug)
			fmt.Printf("Plan:    %s\n", license.Entitlements.PlanSlug)
			fmt.Println()

			// List all features
			for slug, feature := range license.Entitlements.Features {
				status := "❌ Disabled"
				if feature.Enabled {
					status = "✅ Enabled"
				}
				fmt.Printf("  Feature: %s - %s\n", slug, status)

				// List scopes
				for scopeSlug, scope := range feature.Scopes {
					permission := string(scope.Permission)
					if scope.Limit > 0 {
						permission = fmt.Sprintf("%s (limit: %d)", permission, scope.Limit)
					}
					fmt.Printf("    - %s: %s\n", scopeSlug, permission)
				}
			}
		} else {
			fmt.Println("No feature entitlements configured for this license.")
			fmt.Println("Configure a product, plan, and features in the license server")
			fmt.Println("to enable feature-based access control.")
		}

		// Step 6: Demonstrate feature checking
		fmt.Println()
		fmt.Println("=== Feature Checks ===")

		features := []string{"gui", "cli", "api", "premium"}
		for _, feat := range features {
			if license.HasFeature(feat) {
				fmt.Printf("✅ Feature '%s' is available\n", feat)
			} else {
				fmt.Printf("❌ Feature '%s' is not available\n", feat)
			}
		}

		// Step 7: Demonstrate scope checking
		fmt.Println()
		fmt.Println("=== Scope Checks ===")

		scopes := [][2]string{
			{"gui", "list"},
			{"gui", "create"},
			{"gui", "update"},
			{"gui", "delete"},
			{"api", "read"},
			{"api", "write"},
		}

		for _, scope := range scopes {
			feature, scopeName := scope[0], scope[1]
			allowed, limit := license.CanPerform(feature, scopeName)
			if allowed {
				if limit > 0 {
					fmt.Printf("✅ Can %s:%s (limit: %d)\n", feature, scopeName, limit)
				} else {
					fmt.Printf("✅ Can %s:%s\n", feature, scopeName)
				}
			} else {
				fmt.Printf("❌ Cannot %s:%s\n", feature, scopeName)
			}
		}

		fmt.Println()
		fmt.Println("=== Done ===")
		return nil
	}

	// If user explicitly requested a trial, perform trial activation using the client
	if *startTrial {
		if credEmail == "" {
			fmt.Println("❌ Email is required for trial. Use --email flag.")
			os.Exit(1)
		}

		fmt.Println("🎁 Requesting trial license...")

		// Check trial eligibility first
		eligibility, err := client.CheckTrialEligibility(*productID)
		if err != nil {
			log.Fatalf("❌ Failed to check trial eligibility: %v", err)
		}

		if !eligibility.Eligible {
			fmt.Printf("❌ Trial not available: %s\n", eligibility.Message)
			if eligibility.HasUsedTrial {
				fmt.Println()
				fmt.Println("═══════════════════════════════════════════════════════════════")
				fmt.Println("⚠️  This device has already used a trial.")
				fmt.Println()
				fmt.Printf("🔗 Subscribe now: %s\n", *subscriptionURL)
				fmt.Println()
				fmt.Println("Or enter your license credentials:")
				fmt.Println("  go run main.go --license-key KEY --email EMAIL --client-id ID")
				fmt.Println("═══════════════════════════════════════════════════════════════")
			}
			os.Exit(1)
		}

		// Request trial license
		lic, err := client.RequestTrial(credEmail, *productID, "", 14)
		if err != nil {
			log.Fatalf("❌ Trial activation failed: %v", err)
		}
		fmt.Println("✅ Trial license activated successfully!")

		// Call handler with trial license
		if err := appHandler(context.Background(), lic); err != nil {
			log.Fatalf("❌ Application error: %v", err)
		}
		return
	}

	// Non-trial path: use Run to handle activation and run the handler
	cfg := licensing.Config{
		ServerURL:         *serverURL,
		AppName:           "BasicExample",
		AppVersion:        "1.0.0",
		HTTPTimeout:       15 * time.Second,
		AllowInsecureHTTP: *insecure,
		LicenseFile:       *licenseFile,
		ProductID:         *productID,
	}

	licensing.Run(cfg, func(ctx context.Context, license *licensing.LicenseData) error {
		return appHandler(ctx, license)
	})

	// Run has executed the handler and we're done.
	return
}
