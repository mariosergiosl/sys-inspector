# Changelog

All notable changes to the **Sys-Inspector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.30.3] - 2025-12-04
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