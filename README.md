# sys-inspector - eBPF-based System Inspector and Audit Tool

**Language / Idioma:** English | [Português](README.pt-BR.md)

[![OBS Build Status](https://build.opensuse.org/projects/home:mariosergiosl:sys-inspector/packages/sys-inspector/badge.svg)](https://build.opensuse.org/package/show/home:mariosergiosl:sys-inspector/sys-inspector)
[![PyPI version](https://img.shields.io/pypi/v/sys-inspector.svg)](https://pypi.org/project/sys-inspector/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-green.svg?logo=linux&logoColor=white)](https://www.kernel.org/)
[![GitHub Stars](https://img.shields.io/github/stars/mariosergiosl/sys-inspector?style=social)](https://github.com/mariosergiosl/sys-inspector/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/mariosergiosl/sys-inspector?style=social)](https://github.com/mariosergiosl/sys-inspector/network/members)
[![GitHub Release](https://img.shields.io/github/v/release/mariosergiosl/sys-inspector)](https://github.com/mariosergiosl/sys-inspector/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/mariosergiosl/sys-inspector/ci.yml?branch=main)](https://github.com/mariosergiosl/sys-inspector/actions)
[![Issues](https://img.shields.io/github/issues/mariosergiosl/sys-inspector)](https://github.com/mariosergiosl/sys-inspector/issues)
[![Code Size](https://img.shields.io/github/languages/code-size/mariosergiosl/sys-inspector)](https://github.com/mariosergiosl/sys-inspector)
[![Last Commit](https://img.shields.io/github/last-commit/mariosergiosl/sys-inspector)](https://github.com/mariosergiosl/sys-inspector/commits/main)
![Code Quality](https://github.com/mariosergiosl/sys-inspector/actions/workflows/ci.yml/badge.svg)

**Sys-Inspector** is an advanced observability and forensic tool powered by **eBPF** (Extended Berkeley Packet Filter).

Unlike traditional tools that poll `/proc` periodically, Sys-Inspector hooks directly into the Linux Kernel to capture events (process execution, file I/O, network connections) in real-time.

## Features (v0.90.16)

* **Fleet View Dashboard:** Monitor multiple infrastructure nodes from a single centralized web interface.
* **Forensic Time Machine:** Pause live execution and travel back in time to inspect historical snapshots stored in SQLite.
* **Kernel-Level Visibility:** Uses eBPF kprobes/tracepoints for zero-blindspot monitoring.
* **Deep Forensics:**
  * **Real-time MD5 Hashes:** Calculates hashes of executed binaries instantly.
  * **Context Awareness:** Detects SSH origin IPs, Sudo users, and Tmux sessions.
  * **Recursive Alert Bubbling:** Child process anomalies (e.g., Unsafe Libs, Net Errors) propagate warnings up to the parent process in the tree view.
* **Topology & Infrastructure:**
  * **Storage Topology:** Hierarchical view of Disks -> Partitions -> LVM -> Mount Points with HCTL info.
  * **Network Topology:** Auto-detection of Gateway, DNS servers, and Interfaces.
* **Enterprise Reporting:**
  * Generates self-contained, interactive **HTML Dashboards**.
  * **Custom Logo Support:** Embeds your organization's logo automatically.
  * **Visual Badges:** Instant identification of `[SSH]`, `[SUDO]`, `[UNSAFE]`, `[NET ERR]`.
  * **Active-state Toolbar:** The report toolbar highlights the sort and filter currently applied.
* **Dashboard Security (optional):**
  * **HTTP Basic Authentication:** PBKDF2-hashed credentials, working over HTTP and HTTPS.
  * **HTTPS with auto self-signed certificate:** Zero manual PKI; operator-provided certificates are honored.
  * Both disabled by default (see the "Dashboard Security" section below).

## Requirements

* Linux Kernel 4.15+ (5.x+ recommended for BTF support).
* Root privileges (`sudo`).
* Python 3.6+.
* BCC Tools (`python3-bcc`).
* `iproute2` (for `tc` command, required only for Chaos Maker).
* Additional Python libs: `flask`, `cryptography`, `pyyaml`.

## Installation (PyPI)

Works on any Linux distribution with Python 3.6+.

```bash
    pip install sys-inspector
```

## Installation (RPM / openSUSE)

You can install **Sys-Inspector** directly via `zypper` using the openSUSE Build Service repository.

1. **Add the Repository:**

```bash
    zypper addrepo https://download.opensuse.org/repositories/home:mariosergiosl:sys-inspector/15.6/home:mariosergiosl:sys-inspector.repo
```

1. **Refresh and Accept GPG Key:**
During the refresh, you will be asked to trust the repository GPG key.

**Fingerprint:** 7CF0 5795 053C F397 8E00 948E 9F8D 1AC9 E2BE EABC

```bash
    zypper refresh
    # Type 'a' to trust always when prompted.
```

1. **Install the Package:**

```bash
    zypper install sys-inspector
```

1. **Run:**
Once installed, the command is available globally:

```bash
    sys-inspector
```

## Usage

Sys-Inspector is orchestrated via the `main.py` entry point (or globally as `sys-inspector`). It supports multiple execution modes.

### 1. Local Live Mode (Recommended)

Starts the background collector daemon and the Fleet Web Dashboard simultaneously.

```bash
    sudo sys-inspector --mode local-live
    # Access the dashboard at http://localhost:8080
```

### 2. Snapshot Mode (Static Report)

Captures activity for a specific duration and generates a standalone HTML report.

```bash
    sudo sys-inspector --mode snapshot --interval 20
    # Output Example: report/sys-inspector_hostname_20260316_100000.html
```

### 3. Custom Logo

To include your company logo in the report header, simply place a PNG file at the following path:

```bash
    /etc/sys-inspector/logo.png
```

The application will automatically detect, resize (max-height: 40px), encode it to Base64, and embed it in the HTML.

## Dashboard Security (Authentication & HTTPS)

Both are **optional and disabled by default**, so existing deployments are unaffected. Configure them in `conf/config.yaml` (or `/etc/sys-inspector/config.yaml`) under the `network` section.

### HTTP Basic Authentication

1. Generate a password hash (run it on the host that serves the dashboard, so the hash matches its `werkzeug` version):

```bash
    python3 tools/gen_password.py
```

2. Paste the result into `config.yaml` and enable it:

```yaml
    network:
      auth:
        enabled: true
        username: "admin"
        password_hash: "pbkdf2:sha256:..."
```

Authentication works over both HTTP and HTTPS. If enabled without a hash, the server fails closed and rejects all requests.

### HTTPS (TLS)

Enable TLS in `config.yaml`. If the certificate/key below are missing, a self-signed pair is generated automatically on first start (browsers will warn about the unknown issuer, which is expected):

```yaml
    network:
      tls_enabled: true
      ssl_cert: "/etc/sys-inspector/server_cert.pem"
      ssl_key: "/etc/sys-inspector/server_key.pem"
```

To use your own PKI, place your certificate and key at the configured paths and they will be used instead of generating one.

See [docs/en/dashboard_security.md](docs/en/dashboard_security.md) for details.

## Chaos Engineering (Testing Tool)

Included in `tools/chaos_maker.sh` is a stress testing tool designed to validate the inspector's detection capabilities.

**⚠️ WARNING: DO NOT RUN ON PRODUCTION SYSTEMS.**
This script uses `tc` (Traffic Control) to purposefully degrade network quality (packet loss/latency) and consumes CPU/Disk resources.

### Capabilities

* **Network Degradation:** Injects 100ms latency and 20% packet loss to trigger `[NET ERR]` alerts in the report.
* **Process Anomalies:** Hides processes in `/dev/shm` to trigger `[WARN]` alerts.
* **Unsafe Library Loading:** Forces loading of dynamic libraries from `/tmp` via a Python script to trigger `[UNSAFE]` alerts.
* **Disk Stress:** Generates high I/O throughput to test IO accounting.

### How to Run

```bash
    sudo ./tools/chaos_maker.sh
```

To Stop: Press Ctrl+C. The script traps the signal and automatically cleans up the network rules (tc qdisc del) and temporary files.

### Project Structure

```bash
    ├── conf/                  # Configuration and Cryptographic Keys
    ├── data/                  # SQLite Persistence and Agent IDs
    ├── docs/                  # Narrative documentation (docs/en, docs/pt-BR)
    ├── report/                # Standalone HTML Reports Output
    ├── scripts/               # Development helpers (formatting, venv, test runner)
    ├── src/
    │   ├── collectors/        # eBPF Engine and Process Tree Builders
    │   ├── controllers/       # Execution Modes (Daemon, Web, Snapshot)
    │   ├── core/              # Database and Crypto Logic
    │   ├── exporters/         # HTML and Web Assets
    │   ├── probes/            # C eBPF source code
    │   ├── storage/           # Storage interface and handlers
    │   └── utils/             # Configuration loaders
    ├── tools/                 # Operational tools (chaos_maker, setup_env, key/password generation)
    └── main.py                # Unified Entry Point
```
