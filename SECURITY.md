# Security Policy

Sys-Inspector runs as root on the hosts it inspects and handles captured
system data end-to-end (collection, transport, storage). A vulnerability
here is not a normal bug: it can undermine the forensic evidence the tool
produces, or turn the tool itself into an attack surface on every host that
runs it. Reports are taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Use GitHub's private vulnerability reporting instead:

1. Go to the [Security tab](../../security) of this repository.
2. Click **"Report a vulnerability"**.
3. Describe the issue: affected version, run mode (`snapshot` / `daemon` /
   `server` / `live`), reproduction steps, and impact.

This opens a private conversation with the maintainer only; nothing is
public until a fix is available and the report is disclosed.

If you cannot use GitHub's private reporting for some reason, open an issue
that only says a private report is needed, with no technical detail, and
the maintainer will follow up for a private channel.

## What counts as a security issue here

- Anything that lets an inspected host feed the tool data that leads to
  code execution, path traversal, or privilege escalation on the
  agent/server.
- A way to tamper with a capture, its custody chain, or its encryption
  without detection.
- A way to make a detection probe silently fail or be evaded, when the
  tool's report would otherwise claim coverage.
- Credential or key handling issues (the private/public keypair, the
  ingestion token, TLS material).
- Denial of service against the agent or server from data supplied by the
  host being inspected, or from the network.

Bugs that only affect the *quality* of a detection (a false positive, a
missing severity, a UI issue) are normal bug reports, not security reports;
use the [bug report template](../../issues/new/choose) for those.

## Supported versions

This project ships a single active line; security fixes land on the latest
release.

| Version | Supported |
|---|---|
| Latest release | :white_check_mark: |
| Older releases | :x: |

## Response

This is a personal, independently maintained open-source project (not a
funded product with an SLA). Reports are handled on a best-effort basis;
expect an initial response within a few days, not hours.
