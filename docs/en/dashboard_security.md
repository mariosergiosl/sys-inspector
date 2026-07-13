# Dashboard Security (Authentication & HTTPS)

Since v0.90.16, the Fleet/Inspector web dashboard supports optional HTTP Basic
Authentication and HTTPS. Both are **disabled by default**, so upgrading does
not change the behavior of existing deployments. You opt in through the
`network` section of `conf/config.yaml` (or `/etc/sys-inspector/config.yaml`).

## HTTP Basic Authentication

Credentials are stored as a PBKDF2 hash (never in plain text) and verified with
`werkzeug`. Authentication works identically over HTTP and HTTPS.

### 1. Generate the password hash

Run the helper **on the host that will serve the dashboard**, so the hash is
compatible with that host's `werkzeug` version:

```bash
    python3 tools/gen_password.py
```

It prompts for the password twice and prints a `pbkdf2:sha256:...` hash.

### 2. Enable it in config.yaml

```yaml
    network:
      auth:
        enabled: true
        username: "admin"
        password_hash: "pbkdf2:sha256:600000$...$..."
```

Notes:

- The username defaults to `admin` if omitted.
- If `enabled: true` but no `password_hash` is set, the server **fails closed**:
  it rejects every request until a hash is provided. This prevents accidentally
  exposing an unauthenticated dashboard.
- The bind address stays configurable (`network.bind_address`); authentication
  does not force `127.0.0.1`, so you can keep the dashboard reachable on the LAN
  while requiring login.

## HTTPS (TLS)

```yaml
    network:
      tls_enabled: true
      ssl_cert: "/etc/sys-inspector/server_cert.pem"
      ssl_key: "/etc/sys-inspector/server_key.pem"
```

Behavior:

- If both files exist, they are used as-is (bring your own PKI / corporate CA).
- If either is missing and `tls_enabled: true`, a self-signed RSA-2048
  certificate/key pair is generated automatically on first start. Browsers will
  warn about the unknown issuer, which is expected for a self-signed
  certificate on a trusted network.
- If TLS setup fails (for example, a non-writable path), the server logs the
  error and falls back to plain HTTP instead of crashing.

## Recommendation

For a dashboard exposed beyond `localhost`, enable **both** Basic Auth and TLS.
Basic Auth over plain HTTP sends the credential base64-encoded, which is trivial
to decode on the wire; HTTPS protects it in transit.
