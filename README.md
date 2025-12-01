# sys-inspector - eBPF-based System Inspector and Audit Tool



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
[![Code Quality](https://github.com/mariosergiosl/sys-inspector/actions/workflows/ci.yml/badge.svg)]


**Sys-Inspector** is an advanced system observability and forensic tool powered by **eBPF** (Extended Berkeley Packet Filter).

Unlike traditional tools that poll `/proc` periodically, Sys-Inspector hooks directly into the Linux Kernel to capture events (process execution, file I/O, network connections) in real-time, ensuring that short-lived processes and fleeting connections are never missed.

## Features

* **Kernel-Level Visibility:** Uses eBPF kprobes/tracepoints for zero-blindspot monitoring.
* **Deep Forensics:**
    * Calculates **MD5 hashes** of executed binaries on the fly.
    * Identifies **Storage Topology** (HCTL, WWN, SCSI Paths) for SAN zoning analysis.
    * Detects execution context (**SSH** origin, **Sudo** user, Tmux sessions).
* **Enterprise Reporting:** Generates self-contained, interactive **HTML Dashboards** with:
    * Searchable Process Tree.
    * Inventory Summary (Hardware, LVM, Network).
    * Visual Anomaly Badges (High Priority, Suspicious Paths).
* **Accurate Metrics:** Distinguishes between Virtual Memory (VSZ) and Physical Memory (RSS).

## Requirements

* Linux Kernel 4.15+ (5.x+ recommended for BTF support).
* Root privileges (`sudo`).
* Python 3.6+.
* BCC Tools (`python3-bcc`).

## Usage

### 1. Live Stream Mode (Development)
Monitor events in the terminal as they happen:
```bash
sudo sys-inspector
```

### 2. Snapshot Report (Production)
Capture 30 seconds of activity and generate an HTML forensic report:

```bash
sudo sys-inspector --html report_server01.html --duration 30
```