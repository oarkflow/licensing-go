package licensing

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/phuslu/log"
)

// Credentials holds license activation credentials
type Credentials struct {
	Email      string `json:"email"`
	ClientID   string `json:"client_id"`
	LicenseKey string `json:"license_key"`
	IsTrial    bool   `json:"is_trial,omitempty"`
}

// LicensedAppFunc is the function signature for the licensed application handler
type LicensedAppFunc func(ctx context.Context, license *LicenseData) error

// CredentialPrompter collects license credentials using a custom UI.
type CredentialPrompter func(client *Client) (*Credentials, error)

var (
	credentialPrompter  CredentialPrompter
	originalArgs        []string
	activatedDuringRun  bool
	restartOnActivation bool // When true, restart after activation (GUI mode)
)

// SetCredentialPrompter overrides the interactive credential prompt handler.
func SetCredentialPrompter(p CredentialPrompter) {
	credentialPrompter = p
}

// SetRestartOnActivation controls whether the app restarts after license activation.
// Should be set to true for GUI apps that need a full restart, false for CLI apps.
func SetRestartOnActivation(restart bool) {
	restartOnActivation = restart
}

// Run handles license validation and runs the application handler
func Run(cfg Config, handler LicensedAppFunc) {
	originalArgs = append([]string(nil), os.Args...)
	// Parse only known license flags, ignore unknown flags for the app to handle
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.Parse(filterLicenseFlags(os.Args[1:]))

	// Strip license flags from os.Args so they don't conflict with CLI framework
	os.Args = stripLicenseFlags(os.Args)

	clientCfg := ResolveClientConfig(cfg)
	// Create licensing client
	client, err := NewClient(clientCfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create licensing client")
	}
	ctx := context.Background()
	var licenseData *LicenseData
	var email, clientID, licenseKey string
	var hasFileCredentials bool
	if cfg.LicenseFile != "" {
		creds, err := LoadCredentialsFile(cfg.LicenseFile)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to load license file")
		}
		hasFileCredentials = true
		email = creds.Email
		clientID = creds.ClientID
		licenseKey = creds.LicenseKey
	}
	creds := &Credentials{
		Email:      email,
		ClientID:   clientID,
		LicenseKey: licenseKey,
	}
	// Check if already activated
	if client.IsActivated() {
		// Verify existing license
		licenseData, err = client.Verify()
		if err != nil {
			// Check if server is unavailable - if so, don't force reactivation
			if errors.Is(err, ErrServerUnavailable) {
				log.Warn().Err(err).Msg("license server unavailable, cannot verify license")
				log.Fatal().Msg("please check your network connection and try again")
			}
			log.Warn().Err(err).Msg("license verification failed, attempting reactivation")

			// Try to reactivate
			licenseData, err = attemptActivation(client)
			if err != nil {
				log.Fatal().Err(err).Msg("license activation failed")
			}
		}
	} else {
		if hasFileCredentials {
			// Not activated, try to activate
			licenseData, err = attemptActivation(client, creds)
			if err != nil {
				log.Fatal().Err(err).Msg("license activation failed")
			}
		} else {
			licenseData, err = attemptActivation(client)
			if err != nil {
				log.Fatal().Err(err).Msg("license activation failed")
			}
		}

	}
	// Check trial status and warn if expiring soon
	if licenseData.IsTrial {
		trialInfo := licenseData.GetTrialInfo()
		if trialInfo.IsExpired {
			fmt.Println()
			fmt.Println("═══════════════════════════════════════════════════════════════")
			fmt.Println("⚠️  Your trial has expired!")
			fmt.Println()
			fmt.Println("Please subscribe to continue using the application.")
			fmt.Println("Or enter your license credentials to activate.")
			fmt.Println("═══════════════════════════════════════════════════════════════")
			log.Fatal().Msg("trial license expired")
		} else if trialInfo.DaysRemaining <= 3 {
			fmt.Println()
			fmt.Printf("⚠️  Your trial expires in %d day(s)!\n", trialInfo.DaysRemaining)
			fmt.Println()
		}
	}

	// Run the application handler
	if activatedDuringRun && restartOnActivation {
		restartAfterActivation()
		return
	}
	if err := handler(ctx, licenseData); err != nil {
		log.Fatal().Err(err).Msg("application error")
	}
}

// attemptActivation tries to activate the license using available credentials
func attemptActivation(client *Client, credentials ...*Credentials) (*LicenseData, error) {
	// Show device fingerprint first
	fingerprint, err := client.GetDeviceFingerprint()
	if err != nil {
		return nil, fmt.Errorf("failed to get device fingerprint: %w", err)
	}
	fmt.Println()
	var creds *Credentials
	fmt.Println("🔐 License Activation Required")
	fmt.Printf("📱 Device Fingerprint: %s\n", fingerprint)
	fmt.Println()

	if len(credentials) > 0 {
		creds = credentials[0]
	} else {
		creds, err = ResolveCredentials()
		if err != nil {
			return nil, fmt.Errorf("failed to resolve credentials: %w", err)
		}
	}

	// If no credentials found, prompt the user with interactive form
	if creds == nil && credentialPrompter != nil {
		creds, err = credentialPrompter(client)
		if err != nil {
			return nil, fmt.Errorf("failed to get credentials: %w", err)
		}
	}

	if creds == nil {
		creds, err = promptForCredentialsInteractive(client)
		if err != nil {
			return nil, fmt.Errorf("failed to get credentials: %w", err)
		}
	}

	// Handle trial activation
	if creds.IsTrial {
		return activateTrial(client, creds.Email)
	}

	// Activate the license
	fmt.Println("🔑 Activating license...")
	if err := client.Activate(creds.Email, creds.ClientID, creds.LicenseKey); err != nil {
		// Print error explicitly for debugging
		fmt.Fprintf(os.Stderr, "❌ Activation error: %v\n", err)
		// Check for server unavailable error
		if errors.Is(err, ErrServerUnavailable) {
			return nil, fmt.Errorf("cannot reach license server - please check your network connection: %w", err)
		}
		return nil, fmt.Errorf("activation failed: %w", err)
	}

	fmt.Println("✅ License activated successfully!")
	activatedDuringRun = true

	// Verify after activation
	fmt.Println("🔍 Verifying license...")
	license, err := client.Verify()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Verification error: %v\n", err)
		return nil, fmt.Errorf("verification after activation failed: %w", err)
	}

	fmt.Println("✅ License verified!")
	return license, nil
}

func restartAfterActivation() {
	fmt.Println("🔁 Restarting Secretr to finish activation...")
	exe, err := os.Executable()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to locate executable for restart")
	}
	if len(originalArgs) == 0 {
		originalArgs = []string{exe}
	}
	cmd := exec.Command(exe, originalArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Start(); err != nil {
		log.Fatal().Err(err).Msg("failed to restart after activation")
	}
	os.Exit(0)
}

// activateTrial attempts to activate a trial license
func activateTrial(client *Client, email string) (*LicenseData, error) {
	fmt.Println("🎁 Checking trial eligibility...")

	// Check trial eligibility first
	eligibility, err := client.CheckTrialEligibility("")
	if err != nil {
		if errors.Is(err, ErrServerUnavailable) {
			return nil, fmt.Errorf("cannot reach license server - please check your network connection: %w", err)
		}
		return nil, fmt.Errorf("failed to check trial eligibility: %w", err)
	}

	if !eligibility.Eligible {
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Printf("❌ Trial not available: %s\n", eligibility.Message)
		if eligibility.HasUsedTrial {
			fmt.Println()
			fmt.Println("⚠️  This device has already used a trial.")
			fmt.Println()
			fmt.Println("Please enter your license credentials to activate:")
		}
		fmt.Println("═══════════════════════════════════════════════════════════════")
		return nil, fmt.Errorf("trial not available: %s", eligibility.Message)
	}

	// Request trial license (7 days default)
	license, err := client.RequestTrial(email, "", "", 7)
	if err != nil {
		if errors.Is(err, ErrServerUnavailable) {
			return nil, fmt.Errorf("cannot reach license server - please check your network connection: %w", err)
		}
		return nil, fmt.Errorf("trial activation failed: %w", err)
	}

	fmt.Println("✅ Trial license activated successfully!")
	fmt.Printf("📅 Trial expires: %s\n", license.TrialExpiresAt.Format("2006-01-02"))
	return license, nil
}

// PromptForCredentialsInteractiveExported is an exported wrapper for the interactive credential prompt.
// This is used by GUI when it needs to prompt for credentials without creating a separate Fyne app.
func PromptForCredentialsInteractiveExported(client *Client) (*Credentials, error) {
	return promptForCredentialsInteractive(client)
}

// promptForCredentialsInteractive prompts for license credentials using huh forms
func promptForCredentialsInteractive(client *Client) (*Credentials, error) {
	var inputMethod string

	// Check trial eligibility before showing options
	trialAvailable := false
	eligibility, err := client.CheckTrialEligibility("")
	if err == nil && eligibility.Eligible {
		trialAvailable = true
	}

	// Build options based on trial availability
	options := []huh.Option[string]{
		huh.NewOption("Enter license credentials individually", "individual"),
		huh.NewOption("Paste a JSON object with credentials", "json"),
	}
	if trialAvailable {
		// Prepend trial option if available
		options = append([]huh.Option[string]{huh.NewOption("Start a free trial", "trial")}, options...)
	}

	noteDescription := "No license found. Please provide your license credentials."
	if trialAvailable {
		noteDescription = "No license found. Please provide your license credentials or start a trial."
	}

	// First, ask how to input credentials
	methodForm := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("🔑 License Activation Required").
				Description(noteDescription),

			huh.NewSelect[string]().
				Title("How would you like to proceed?").
				Options(options...).
				Value(&inputMethod),
		),
	)

	if err := methodForm.Run(); err != nil {
		return nil, fmt.Errorf("method selection cancelled: %w", err)
	}

	if inputMethod == "trial" {
		return promptForTrialInteractive()
	}

	if inputMethod == "json" {
		return promptForJSONInteractive()
	}

	return promptForIndividualFieldsInteractive()
}

// promptForTrialInteractive prompts for email to start a trial
func promptForTrialInteractive() (*Credentials, error) {
	var email string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("🎁 Start Free Trial").
				Description("Enter your email to start a 7-day free trial."),

			huh.NewInput().
				Title("📧 Email").
				Description("Your email address for the trial").
				Placeholder("your@email.com").
				Value(&email).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("email is required")
					}
					if !strings.Contains(s, "@") {
						return fmt.Errorf("please enter a valid email address")
					}
					return nil
				}),
		),
	)

	if err := form.Run(); err != nil {
		return nil, fmt.Errorf("trial email input cancelled: %w", err)
	}

	return &Credentials{
		Email:   strings.TrimSpace(email),
		IsTrial: true,
	}, nil
}

// promptForJSONInteractive prompts for JSON credentials using huh
func promptForJSONInteractive() (*Credentials, error) {
	var jsonInput string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("📋 JSON Credentials").
				Description(`Paste your JSON credentials in this format:
{"email":"your@email.com","client_id":"xxx","license_key":"xxx"}`),

			huh.NewText().
				Title("JSON Credentials").
				Placeholder(`{"email":"...","client_id":"...","license_key":"..."}`).
				Value(&jsonInput).
				Validate(func(s string) error {
					s = strings.TrimSpace(s)
					if s == "" {
						return fmt.Errorf("JSON is required")
					}
					var creds Credentials
					if err := json.Unmarshal([]byte(s), &creds); err != nil {
						return fmt.Errorf("invalid JSON format: %w", err)
					}
					if creds.Email == "" {
						return fmt.Errorf("email is required in JSON")
					}
					if creds.ClientID == "" {
						return fmt.Errorf("client_id is required in JSON")
					}
					if creds.LicenseKey == "" {
						return fmt.Errorf("license_key is required in JSON")
					}
					return nil
				}),
		),
	)

	if err := form.Run(); err != nil {
		return nil, fmt.Errorf("JSON input cancelled: %w", err)
	}

	// Parse and return
	jsonInput = strings.TrimSpace(jsonInput)
	jsonInput = strings.Trim(jsonInput, "'\"")

	var creds Credentials
	if err := json.Unmarshal([]byte(jsonInput), &creds); err != nil {
		return nil, fmt.Errorf("invalid JSON format: %w", err)
	}

	fmt.Println()
	fmt.Printf("📧 Email: %s\n", creds.Email)
	fmt.Printf("🆔 Client ID: %s\n", creds.ClientID)
	fmt.Printf("🔑 License Key: %s...\n", truncateKey(creds.LicenseKey))
	fmt.Println()

	return &creds, nil
}

// promptForIndividualFieldsInteractive prompts for each credential field using huh
func promptForIndividualFieldsInteractive() (*Credentials, error) {
	var email, clientID, licenseKey string

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("🔑 Enter License Credentials").
				Description("Please provide your license information"),

			huh.NewInput().
				Title("📧 Email").
				Description("Your registered email address").
				Placeholder("your@email.com").
				Value(&email).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("email is required")
					}
					if !strings.Contains(s, "@") {
						return fmt.Errorf("please enter a valid email address")
					}
					return nil
				}),

			huh.NewInput().
				Title("🆔 Client ID").
				Description("Your unique client identifier").
				Placeholder("client-id-xxx").
				Value(&clientID).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("client ID is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("🔑 License Key").
				Description("Your license key").
				Placeholder("XXXX-XXXX-XXXX-XXXX").
				EchoMode(huh.EchoModePassword).
				Value(&licenseKey).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("license key is required")
					}
					return nil
				}),
		),
	)

	if err := form.Run(); err != nil {
		return nil, fmt.Errorf("credential input cancelled: %w", err)
	}

	return &Credentials{
		Email:      strings.TrimSpace(email),
		ClientID:   strings.TrimSpace(clientID),
		LicenseKey: strings.TrimSpace(licenseKey),
	}, nil
}

// truncateKey truncates a license key for display
func truncateKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8]
}

// filterLicenseFlags extracts only the license-related flags from args
// Note: License credentials cannot be passed via flags - only non-sensitive config flags are allowed
func filterLicenseFlags(args []string) []string {
	licenseFlags := map[string]bool{
		"http-timeout": true,
		"api-key":      true,
	}
	var filtered []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		// Check if it's a flag
		if len(arg) > 1 && arg[0] == '-' {
			name := arg[1:]
			if len(name) > 0 && name[0] == '-' {
				name = name[1:] // strip second dash for --flag
			}
			// Check for = syntax
			if idx := indexOf(name, '='); idx >= 0 {
				name = name[:idx]
			}
			if licenseFlags[name] {
				filtered = append(filtered, arg)
				// If no = and next arg exists and doesn't start with -, it's the value
				if indexOf(arg, '=') < 0 && i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
					i++
					filtered = append(filtered, args[i])
				}
			}
		}
	}
	return filtered
}

// stripLicenseFlags removes license-related flags from args so they don't conflict with CLI
// Note: License credentials cannot be passed via flags - only non-sensitive config flags are stripped
func stripLicenseFlags(args []string) []string {
	licenseFlags := map[string]bool{
		"http-timeout": true,
		"api-key":      true,
	}
	var filtered []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		// Check if it's a flag
		if len(arg) > 1 && arg[0] == '-' {
			name := arg[1:]
			if len(name) > 0 && name[0] == '-' {
				name = name[1:] // strip second dash for --flag
			}
			// Check for = syntax
			if idx := indexOf(name, '='); idx >= 0 {
				name = name[:idx]
			}
			if licenseFlags[name] {
				// Skip this flag
				// If no = and next arg exists and doesn't start with -, skip the value too
				if indexOf(arg, '=') < 0 && i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
					i++
				}
				continue
			}
		}
		filtered = append(filtered, arg)
	}
	return filtered
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// PromptForLicenseRenewal prompts for new license credentials when the current license has expired.
// This function does NOT offer trial option since one device can only have one trial.
// Returns the new license data if successful, or an error.
func PromptForLicenseRenewal(cfg Config) (*LicenseData, error) {
	clientCfg := ResolveClientConfig(cfg)
	client, err := NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create licensing client: %w", err)
	}

	fingerprint, err := client.GetDeviceFingerprint()
	if err != nil {
		return nil, fmt.Errorf("failed to get device fingerprint: %w", err)
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    🔄 LICENSE RENEWAL                          ")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("Your license has expired. Please enter your new license credentials.")
	fmt.Println()
	fmt.Printf("📱 Device Fingerprint: %s\n", fingerprint)
	fmt.Println()
	fmt.Println("💡 Get a new license at: https://secretr.app#pricing")
	fmt.Println()

	// Prompt for credentials (no trial option)
	creds, err := promptForRenewalCredentials()
	if err != nil {
		return nil, err
	}

	// Activate the new license
	fmt.Println()
	fmt.Println("🔑 Activating new license...")
	if err := client.Activate(creds.Email, creds.ClientID, creds.LicenseKey); err != nil {
		if errors.Is(err, ErrServerUnavailable) {
			return nil, fmt.Errorf("cannot reach license server - please check your network connection: %w", err)
		}
		return nil, fmt.Errorf("license activation failed: %w", err)
	}

	fmt.Println("✅ License activated successfully!")

	// Verify the new license
	fmt.Println("🔍 Verifying license...")
	license, err := client.Verify()
	if err != nil {
		return nil, fmt.Errorf("license verification failed: %w", err)
	}

	fmt.Println("✅ License verified!")
	fmt.Println()
	fmt.Printf("📋 Plan: %s\n", license.PlanSlug)
	if !license.ExpiresAt.IsZero() {
		fmt.Printf("📅 Expires: %s\n", license.ExpiresAt.Format("2006-01-02"))
	}
	fmt.Println()

	return license, nil
}

// promptForRenewalCredentials prompts for license credentials without trial option
func promptForRenewalCredentials() (*Credentials, error) {
	var inputMethod string

	// Build options - NO trial option for renewal
	options := []huh.Option[string]{
		huh.NewOption("Enter license credentials individually", "individual"),
		huh.NewOption("Paste a JSON object with credentials", "json"),
	}

	methodForm := huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("🔑 Enter New License").
				Description("Please provide your new license credentials.\n\nNote: Trial licenses cannot be reused on this device."),

			huh.NewSelect[string]().
				Title("How would you like to enter your credentials?").
				Options(options...).
				Value(&inputMethod),
		),
	)

	if err := methodForm.Run(); err != nil {
		return nil, fmt.Errorf("cancelled: %w", err)
	}

	if inputMethod == "json" {
		return promptForJSONInteractive()
	}

	return promptForIndividualFieldsInteractive()
}

// RenewLicenseWithCredentials activates a new license with the provided credentials.
// This is used by GUI which has its own credential input UI.
func RenewLicenseWithCredentials(cfg Config, email, clientID, licenseKey string) (*LicenseData, error) {
	clientCfg := ResolveClientConfig(cfg)
	client, err := NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create licensing client: %w", err)
	}

	// Activate the new license
	if err := client.Activate(email, clientID, licenseKey); err != nil {
		if errors.Is(err, ErrServerUnavailable) {
			return nil, fmt.Errorf("cannot reach license server - please check your network connection")
		}
		return nil, fmt.Errorf("license activation failed: %w", err)
	}

	// Verify the new license
	license, err := client.Verify()
	if err != nil {
		return nil, fmt.Errorf("license verification failed: %w", err)
	}

	return license, nil
}
