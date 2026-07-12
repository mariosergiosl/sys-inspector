# Changelog

All notable changes to the **Sys-Inspector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.90.16] - 2026-07-12

### Security

- **Dashboard Authentication (opt-in):** Added optional HTTP Basic Auth to the Fleet/Inspector dashboard, working over both HTTP and HTTPS. Disabled by default (`network.auth.enabled: false`) so existing deployments are unaffected. Credentials are stored as a PBKDF2 hash in `config.yaml`; generate it with `tools/gen_password.py` (run it on the host that serves the dashboard). When enabled without a hash, the server fails closed and rejects all requests.
- **Dashboard HTTPS (opt-in):** Added optional TLS for the dashboard (`network.tls_enabled: false` by default). When enabled, if the configured certificate/key are missing, a self-signed pair is generated automatically on first start (`src/core/tls.py`), so HTTPS works with zero manual PKI. Operator-provided certificates in the configured paths are honored instead. If TLS setup fails, the server falls back to HTTP rather than crashing.
- **Dashboard XSS Prevention:** Agent-supplied fields (`hostname`, `ip_address`, `os_info`) and the URL agent id are now validated against an allowlist and escaped before being rendered in the Fleet and Inspector views. A compromised agent can no longer inject script into the analyst's browser.
- **Setup Script Hardening:** `ensure_environment()` now resolves `setup_env.sh` only from fixed trusted locations (the packaged `tools/` directory and `/usr/bin/setup_env.sh`) instead of searching `$PATH`. This prevents execution of a malicious `setup_env.sh` when the agent runs as root.

### Changed

- **Toolbar active-state indicator:** The report toolbar now visually marks which sort (Process By) and which filter (Filters) are currently applied, using a reddish outline on the active badge. Sort and filter are independent, so both can be highlighted at once. The indicator uses `outline` (not `border`) to avoid any layout shift of neighboring icons. Clearing the filter keeps the active sort highlighted.
- **Symmetric toolbar:** The Process By sort buttons are now rendered as bare icons, matching the Filters block (the previous gray button boxes were an incidental style difference, not a semantic distinction).

### Fixed

- **Packaging Conflict:** Removed the divergent `[project]` table from `pyproject.toml` (stale version and an invalid `inspector:main` entry point) that could break the `sys-inspector` console script depending on the build backend. `setup.py` is now the single source of truth for package metadata.
- **Log Level:** The application now honors `general.log_level` from `config.yaml`. Previously the level was hardcoded to `INFO` and the configured value was ignored.
- **Leaf-node expander:** Leaf rows in the process tree emitted a literal `toggleBranch({node.pid})` because the string was not an f-string; the expander now uses the real PID.
- **Duplicate EDR-WAIT badge:** The frozen-process (EDR-WAIT) badge was emitted twice (once by the tag loop, once by a dedicated block); the redundant block was removed so it renders once.
- **WARN score tooltip:** The anomaly-score badge showed a placeholder ("Check Details"); it now lists the actual score reasons, noting when a higher score was bubbled up from a child process.
- **False-positive NET ERR on kernel threads:** TCP drop/retransmit events fired in softirq context were attributed to the running kernel thread (`ksoftirqd`, `kthreadd`) instead of the socket owner, flagging kernel threads with NET ERR. Kernel threads (PID 2 and its subtree) are now excluded from NET ERR badges, scores and tree aggregation; the socket-owning processes remain flagged correctly.

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
