package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	licensing "github.com/oarkflow/licensing-go"
)

func main() {
	serverURL := flag.String("server", licensing.DefaultServerURL, "License server URL")
	configDir := flag.String("config-dir", "", "Directory for license/device key storage")
	licenseFile := flag.String("license-file", licensing.DefaultLicenseFile, "Local license filename")
	productID := flag.String("product-id", "", "Product ID or slug")
	insecure := flag.Bool("allow-insecure-http", false, "Allow insecure HTTP for local development")
	deviceKeyProvider := flag.String("device-key-provider", "auto", "Device key provider: auto, tpm, os, or software")
	deviceKeyFile := flag.String("device-key-file", "", "Software device key filename/path")
	deviceKeyName := flag.String("device-key-name", "", "OS keyring key label")
	tpmDevice := flag.String("tpm-device", "", "TPM device path when forcing TPM")
	action := flag.String("action", "identity", "Action: identity, activate, verify, or trial")
	email := flag.String("email", "", "Email for activation or trial")
	clientID := flag.String("client-id", "", "Client ID for activation")
	licenseKey := flag.String("license-key", "", "License key for activation")
	planID := flag.String("plan-id", "", "Plan ID for trial activation")
	flag.Parse()

	cfg := licensing.Config{
		ServerURL:         *serverURL,
		ConfigDir:         *configDir,
		LicenseFile:       *licenseFile,
		ProductID:         *productID,
		AllowInsecureHTTP: *insecure,
		DeviceKeyProvider: *deviceKeyProvider,
		DeviceKeyFile:     *deviceKeyFile,
		DeviceKeyName:     *deviceKeyName,
		TPMDevice:         *tpmDevice,
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

	switch *action {
	case "identity":
		return
	case "activate":
		requireFlag("email", *email)
		requireFlag("client-id", *clientID)
		requireFlag("license-key", *licenseKey)
		if err := client.Activate(*email, *clientID, *licenseKey); err != nil {
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
		requireFlag("email", *email)
		license, err := client.RequestTrial(*email, cfg.ProductID, *planID, 0)
		if err != nil {
			log.Fatal(err)
		}
		printJSON("trial license", license)
	default:
		log.Fatalf("unsupported action %q", *action)
	}
}

func requireFlag(name, value string) {
	if value == "" {
		log.Fatalf("--%s is required", name)
	}
}

func printJSON(label string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s:\n%s\n", label, data)
}
