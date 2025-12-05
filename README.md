# sys-inspector - eBPF-based System Inspector and Audit Tool



[![OBS Build Status](https://build.opensuse.org/projects/home:mariosergiosl:sys-inspector/packages/sys-inspector/badge.svg)](https://build.opensuse.org/package/show/home:mariosergiosl:sys-inspector/sys-inspector)
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

## Features (v0.30.8)

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

## Requirements

* Linux Kernel 4.15+ (5.x+ recommended for BTF support).
* Root privileges (`sudo`).
* Python 3.6+.
* BCC Tools (`python3-bcc`).
* `iproute2` (for `tc` command, required only for Chaos Maker).

## Installation (RPM / openSUSE)

You can install **Sys-Inspector** directly via `zypper` using the openSUSE Build Service repository.

1. **Add the Repository:**
```bash
zypper addrepo [https://download.opensuse.org/repositories/home:mariosergiosl:sys-inspector/15.6/home:mariosergiosl:sys-inspector.repo](https://download.opensuse.org/repositories/home:mariosergiosl:sys-inspector/15.6/home:mariosergiosl:sys-inspector.repo)
```

2. **Refresh and Accept GPG Key:**
During the refresh, you will be asked to trust the repository GPG key.

**Fingerprint:** 7CF0 5795 053C F397 8E00 948E 9F8D 1AC9 E2BE EABC
```Bash
zypper refresh
# Type 'a' to trust always when prompted.
```

3. **Install the Package:**

```Bash
zypper install sys-inspector
```

4. **Run:**
Once installed, the command is available globally:

```Bash
sys-inspector
```


## Usage

Sys-Inspector can now be run with or without arguments. It handles directory creation automatically.

### 1. Default Mode (Recommended)
Captures **20 seconds** of activity and saves the report to `/var/log/sys-inspector/` with an auto-generated name containing the hostname and timestamp.

```bash
sudo python3 src/inspector.py
# Output Example: /var/log/sys-inspector/sys-inspector_v0.30.3_hostname_20251201_100000.html
```

### 2. Custom Parameters
You can specify the duration and the output file path manually.

```bash
# Capture for 60 seconds and save to a specific file
sudo python3 src/inspector.py --duration 60 --html /tmp/my_investigation.html

Argument	Short	Default	Description
--duration	-d	20	Capture duration in seconds.
--html		(Auto)	Path to output HTML file. If omitted, defaults to /var/log/sys-inspector/.
```

### 3. Custom Logo
To include your company logo in the report header, simply place a PNG file at the following path:
```Bash
/etc/sys-inspector/logo.png
```
The application will automatically detect, resize (max-height: 40px), encode it to Base64, and embed it in the HTML.

## Chaos Engineering (Testing Tool)

Included in `scripts/chaos_maker.sh` is a stress testing tool designed to validate the inspector's detection capabilities.

**⚠️ WARNING: DO NOT RUN ON PRODUCTION SYSTEMS.**
This script uses `tc` (Traffic Control) to purposefully degrade network quality (packet loss/latency) and consumes CPU/Disk resources.

### Capabilities:
* **Network Degradation:** Injects 100ms latency and 20% packet loss to trigger `[NET ERR]` alerts in the report.
* **Process Anomalies:** Hides processes in `/dev/shm` to trigger `[WARN]` alerts.
* **Unsafe Library Loading:** Forces loading of dynamic libraries from `/tmp` via a Python script to trigger `[UNSAFE]` alerts.
* **Disk Stress:** Generates high I/O throughput to test IO accounting.

### How to Run:
```bash
sudo ./scripts/chaos_maker.sh
```
To Stop: Press Ctrl+C. The script traps the signal and automatically cleans up the network rules (tc qdisc del) and temporary files.



### Project Structure

```bash
├── src/
│   ├── inspector.py           # Main Entry Point
│   └── sys_inspector/
│       ├── bpf_programs.py    # C eBPF Code
│       ├── sys_info.py        # Inventory & Topology
│       └── report_generator.py # HTML Engine
├── scripts/
│   ├── chaos_maker.sh         # Chaos Engineering Tool
│   └── run_python_test.sh     # Linter (Pylint/Flake8)
├── logs/                      # Default output directory
└── README.md
```
