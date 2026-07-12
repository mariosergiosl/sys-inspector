# Changelog

All notable changes to the **Sys-Inspector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Dashboard Authentication (opt-in):** Added optional HTTP Basic Auth to the Fleet/Inspector dashboard, working over both HTTP and HTTPS. Disabled by default (`network.auth.enabled: false`) so existing deployments are unaffected. Credentials are stored as a PBKDF2 hash in `config.yaml`; generate it with `tools/gen_password.py` (run it on the host that serves the dashboard). When enabled without a hash, the server fails closed and rejects all requests.
- **Dashboard XSS Prevention:** Agent-supplied fields (`hostname`, `ip_address`, `os_info`) and the URL agent id are now validated against an allowlist and escaped before being rendered in the Fleet and Inspector views. A compromised agent can no longer inject script into the analyst's browser.
- **Setup Script Hardening:** `ensure_environment()` now resolves `setup_env.sh` only from fixed trusted locations (the packaged `tools/` directory and `/usr/bin/setup_env.sh`) instead of searching `$PATH`. This prevents execution of a malicious `setup_env.sh` when the agent runs as root.

### Fixed

- **Packaging Conflict:** Removed the divergent `[project]` table from `pyproject.toml` (stale version and an invalid `inspector:main` entry point) that could break the `sys-inspector` console script depending on the build backend. `setup.py` is now the single source of truth for package metadata.
- **Log Level:** The application now honors `general.log_level` from `config.yaml`. Previously the level was hardcoded to `INFO` and the configured value was ignored.

## [0.90.00] - 2026-03-16

### Added

- **Multi-Agent Architecture:** Transitioned from a single-run script to a continuous Daemon architecture.
- **Fleet View Dashboard:** Centralized Web UI (`/`) to monitor multiple connected agents and their online/offline status via heartbeat.
- **Time Machine (Forensic History):** Integrated SQLite storage with retention policies to allow browsing historical snapshots via the Web UI.
- **Live Pause Control:** Added the ability to pause the live incoming data stream for detailed forensic analysis of a specific moment.
- **Flask Web Server:** Embedded lightweight web server to serve the dashboards dynamically.

### Changed

- **Entry Point:** Deprecated `inspector.py` in favor of a unified `main.py` orchestrator supporting multiple modes (`snapshot`, `live`, `daemon`, `server`, `local-live`).
- **Database Engine:** Enabled SQLite WAL (Write-Ahead Logging) mode by default to support high-concurrency between the collector daemon and the web server.

### Fixed

- Resolved `[Errno 24] Too many open files` caused by unclosed database connections during continuous polling.

## [0.30.9] - 2025-12-05

### Added

- **Recursive Badge Propagation:** Alerts (`WARN`, `UNSAFE`, `NET ERR`, `SSH`) now "bubble up" from child processes to their parents in the HTML tree view. This allows quick identification of problematic branches even if the root process seems healthy.
- **Hierarchical Storage Topology:** The storage inventory now correctly maps the dependency tree: `Physical Disk -> Partition -> LVM/FS -> Mount Point`.
- **Network Topology:** Added automatic detection of Default Gateway and DNS Servers in the inventory header.
- **Logo Support:** The report generator now looks for `/etc/sys-inspector/logo.png`. If found, it converts the image to Base64 and embeds it in the report header.
- **Chaos Maker (English):** Fully translated `chaos_maker.sh` to English and improved cleanup routines. Added specific simulation for "Unsafe Library Loading".

### Changed

- **Default Arguments:** `inspector.py` can now be run without arguments.
  - Default Duration: `20` seconds.
  - Default Output: `/var/log/sys-inspector/sys-inspector_v{VER}_{HOST}_{DATE}.html`.
- **HTML Report Layout:**
  - Added "Storage Topology" print button.
  - Added `[UNSAFE]` filter button to the controls bar.
  - Improved readability of Disk I/O details.
- **Code Quality:**
  - Complete refactoring of `inspector.py` and `report_generator.py` to achieve **10/10 Pylint** score.
  - Resolved global variable warnings and reduced function complexity (Cyclomatic Complexity).
  - Strictly formatted with `flake8`.

### Fixed

- Fixed layout breakage when a disk had multiple partitions.
- Fixed `flake8` warnings regarding whitespace around operators and multiple statements on one line.
- Fixed `pylint` warnings about global variable usage in BPF callback handlers.

## [0.20.0] - 2025-11-28

### Added

- **Core eBPF Architecture:** Replaced legacy `psutil` polling with event-driven Kernel probes (kprobes/kretprobes) for `execve`, `openat`, `vfs_read`, `vfs_write`, and `tcp_v4_connect`.
- **Enterprise HTML Reporting:**
  - Interactive "Accordion" style process tree.
  - Sticky Header for easy navigation in large reports.
  - Visual Badges for CPU Load, Priority (Nice), and Anomaly Scores.
  - Embedded CSS/JS (Single-file portability).
- **Deep Forensics:**
  - Real-time MD5 hash calculation of executed binaries.
  - Context capture: SSH Origin IP, Sudo User, and Multiplexer (Tmux) detection.
  - Anomaly Detection: Heuristics for execution from `/tmp`, `/dev/shm`, deleted binaries, and suspicious environment variables (`LD_PRELOAD`).
- **Storage Topology Mapping:**
  - Correlation of open files to physical devices.
  - Explicit **HCTL (Host:Channel:Target:LUN)** display for SAN/Mainframe zoning analysis.
  - Persistent path resolution (`/dev/disk/by-path`).
- **Accurate Metrics:**
  - Distinction between Virtual Memory (VSZ) and Physical Memory (RSS).
  - CPU Usage % calculation based on tick deltas during capture window.
  - Lifetime I/O stats vs Window I/O stats.

### Changed

- **Project Structure:** Modularized into `src/sys_inspector` package layout (PEP 8 compliant).
- **Quality Assurance:** Strict adherence to Pylint (10/10) and Flake8 standards.
- **License:** Project released under GPL-3.0-only.

### Fixed

- Solved "Feedback Loop" where the inspector traced its own I/O operations.
- Fixed library enumeration to capture dynamic libs at process spawn time.
- Fixed visual layout issues in HTML header preventing overlap of values.

---

## [0.1.0] - 2025-11-28

### Initial

- Proof of Concept (PoC) for eBPF integration.
- Basic `execve` snooping.
