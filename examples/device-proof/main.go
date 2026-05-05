package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	licensing "github.com/oarkflow/licensing-go"
)

func main() {
	cfg := licensing.Config{
		ServerURL:         env("LICENSE_CLIENT_SERVER", licensing.DefaultServerURL),
		ConfigDir:         env("LICENSE_CLIENT_CONFIG_DIR", ""),
		LicenseFile:       env("LICENSE_CLIENT_LICENSE_FILE", licensing.DefaultLicenseFile),
		ProductID:         env("LICENSE_CLIENT_PRODUCT_ID", ""),
		AllowInsecureHTTP: envBool("LICENSE_CLIENT_ALLOW_INSECURE_HTTP"),
		DeviceKeyProvider: env("LICENSE_CLIENT_DEVICE_KEY_PROVIDER", "auto"),
		DeviceKeyFile:     env("LICENSE_CLIENT_DEVICE_KEY_FILE", ""),
		DeviceKeyName:     env("LICENSE_CLIENT_DEVICE_KEY_NAME", ""),
		TPMDevice:         env("LICENSE_CLIENT_TPM_DEVICE", ""),
	}

	client, err := licensing.NewClient(cfg)
	if err != nil {
		log.Fatal(err)
	}

	identity, err := client.CurrentDeviceIdentity()
	if err != nil {
		log.Fatal(err)
	}
	printJSON("device identity", identity)

	switch env("LICENSE_EXAMPLE_ACTION", "identity") {
	case "identity":
		return
	case "activate":
		email := mustEnv("LICENSE_CLIENT_EMAIL")
		clientID := mustEnv("LICENSE_CLIENT_ID")
		licenseKey := mustEnv("LICENSE_CLIENT_LICENSE_KEY")
		if err := client.Activate(email, clientID, licenseKey); err != nil {
			log.Fatal(err)
		}
		fmt.Println("activation succeeded")
	case "verify":
		license, err := client.Verify()
		if err != nil {
			log.Fatal(err)
		}
		printJSON("license", license)
	case "trial":
		email := mustEnv("LICENSE_CLIENT_EMAIL")
		license, err := client.RequestTrial(email, cfg.ProductID, env("LICENSE_CLIENT_PLAN_ID", ""), 0)
		if err != nil {
			log.Fatal(err)
		}
		printJSON("trial license", license)
	default:
		log.Fatalf("unsupported LICENSE_EXAMPLE_ACTION %q", env("LICENSE_EXAMPLE_ACTION", ""))
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func mustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s is required", key)
	}
	return value
}

func envBool(key string) bool {
	value := os.Getenv(key)
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	return err == nil && parsed
}

func printJSON(label string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s:\n%s\n", label, data)
}
