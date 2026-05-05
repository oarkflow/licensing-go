# Device Proof Example

This example shows the v2 device identity used by the Go SDK. The displayed
`fingerprint` is derived from the device proof public key, not from mutable host
metadata, so it stays the same across restarts and time as long as the device key
is preserved.

Provider order for `LICENSE_CLIENT_DEVICE_KEY_PROVIDER=auto`:

1. TPM 2.0 hardware key when available.
2. OS keyring/keychain when available.
3. Software Ed25519 key file with `0600` permissions.

Print the current device identity:

```bash
LICENSE_CLIENT_ALLOW_INSECURE_HTTP=true \
LICENSE_CLIENT_SERVER=http://localhost:6601 \
go run ./examples/device-proof
```

Activate:

```bash
LICENSE_EXAMPLE_ACTION=activate \
LICENSE_CLIENT_ALLOW_INSECURE_HTTP=true \
LICENSE_CLIENT_SERVER=http://localhost:6601 \
LICENSE_CLIENT_EMAIL=user@example.com \
LICENSE_CLIENT_ID=client_123 \
LICENSE_CLIENT_LICENSE_KEY=XXXX-XXXX-XXXX-XXXX \
go run ./examples/device-proof
```

Verify an existing local license:

```bash
LICENSE_EXAMPLE_ACTION=verify go run ./examples/device-proof
```

Force a provider:

```bash
LICENSE_CLIENT_DEVICE_KEY_PROVIDER=tpm go run ./examples/device-proof
LICENSE_CLIENT_DEVICE_KEY_PROVIDER=os go run ./examples/device-proof
LICENSE_CLIENT_DEVICE_KEY_PROVIDER=software go run ./examples/device-proof
```
