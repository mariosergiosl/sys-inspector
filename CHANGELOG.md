# Changelog

All notable changes to the **Sys-Inspector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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