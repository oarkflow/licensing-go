# Device Proof Example

This example shows the v2 device identity used by the Go SDK. The displayed
`fingerprint` is derived from the device proof public key, not from mutable host
metadata, so it stays the same across restarts and time as long as the device key
is preserved.

Provider order for `--device-key-provider=auto`:

1. TPM 2.0 hardware key when available.
2. OS keyring/keychain when available.
3. Software Ed25519 key file with `0600` permissions.

Print the current device identity:

```bash
go run ./examples/device-proof --server http://localhost:6601 --allow-insecure-http
```

Activate:

```bash
go run ./examples/device-proof \
  --server http://localhost:6601 \
  --allow-insecure-http \
  --action activate \
  --email user@example.com \
  --client-id client_123 \
  --license-key XXXX-XXXX-XXXX-XXXX
```

Verify an existing local license:

```bash
go run ./examples/device-proof --action verify
```

Force a provider:

```bash
go run ./examples/device-proof --device-key-provider tpm
go run ./examples/device-proof --device-key-provider os
go run ./examples/device-proof --device-key-provider software
```
