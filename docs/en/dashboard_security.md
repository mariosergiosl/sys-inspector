# Dashboard Security (Authentication & HTTPS)

> **Updated 2026-08-20.** Two things changed and are worth reading first:
> **HTTPS is no longer optional** (decision D-033), and the authentication that
> used to live in the `local-live` panel was **reimplemented in the server**
> when that mode was removed.

The server dashboard supports **optional** HTTP Basic authentication and always
serves over **HTTPS**. Configure it under the `network` section of
`conf/config.yaml` (or `/etc/sys-inspector/config.yaml`).

## HTTP Basic Authentication

Credentials are stored as a PBKDF2 hash (never in plain text) and verified with
`werkzeug`.

The guard sits **before routing**, not inside each route, so a new route is born
protected instead of born open until someone remembers to protect it. The
username is compared in constant time (`hmac.compare_digest`), because `==`
returns on the first differing character and leaks, through response timing, how
many leading characters match.

Two cases fail **closed**, deliberately: auth enabled with no `password_hash`,
and a missing `werkzeug` library. In both the operator asked for protection, and
staying open would leave them believing they are protected - worse than
refusing.

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

## HTTPS: the only transport, with no switch to turn it off

**`tls_enabled` no longer exists.** The plaintext transport was removed from the
code, not merely disabled by default (D-033).

```yaml
    network:
      ssl_cert: "/etc/sys-inspector/server_cert.pem"
      ssl_key: "/etc/sys-inspector/server_key.pem"
```

Behaviour:

- If both files exist they are used as they are (your own PKI / corporate CA).
- If either is missing, a self-signed RSA-2048 pair is generated automatically on
  first start. The browser warns about the unknown issuer, which is expected.
  **This is why defaulting TLS on does not break the first run.**
- If TLS cannot be enabled, the server **refuses to start**. It does not fall
  back to plaintext: a server that does not start is a visible problem in thirty
  seconds, while one serving in the clear believing itself encrypted can last for
  months.

### Why the option was removed rather than inverted

The previous default was worse than it looked. In the agent, the transport was
decided by the **port number** (`use_tls = server_port == 443`): any other port
- 8080, the common case in a lab or on an internal network - made the agent
speak plaintext without telling anyone, carrying the capture and the
`Authorization: Bearer <token>` header with it.

While a switch exists there are three ways back, none of them hypothetical: the
misconfiguration, the example copied from an old document, and the "just this
network, just for today" that becomes permanent.

### What remains a choice

Certificate **verification** (`daemon.verify_tls`, on the agent), because it
depends on infrastructure not every environment has: a CA that signs the
server's certificate. Turning it off protects against passive eavesdropping and
**not** against an active interceptor, and that difference changes how much that
agent's report is worth - so it is written to the **log**, every time, not just
to a config file.

## Recommendation

For a dashboard reachable beyond `localhost`, enable Basic Auth **as well**.
HTTPS already protects the credential in transit; Basic Auth is what stops
anyone who reaches the port from reading the whole fleet's collection.
