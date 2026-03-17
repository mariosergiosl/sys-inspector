# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/collectors/system_inventory.py
# DESCRIPTION: Collects static system information (OS, Hardware, Network, Disk).
#              Serves as the initial snapshot data for the report.
#
#              UPDATED v0.70.03:
#              - FIX: Restored 'generated' key for html_report compatibility (Critical).
#              - FEAT: Physical Network Drop detection (CRC/Frame errors).
#              - MAINTAINED: Full logic from v0.61/v0.79.00.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 0.70.03
# ==============================================================================

import os
import socket
import platform
import subprocess
import datetime
import time
import re
# import glob


# ------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------------------
def _run_cmd(cmd):
    """
    Executes a shell command and returns the output string.

    Args:
        cmd (list): List of command arguments.

    Returns:
        str: Stdout content or "N/A" on failure.
    """
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        ).strip()
    except Exception:
        return "N/A"


def _get_physical_net_errors():
    """
    [v0.70 NEW] Parses /proc/net/dev to find physical layer errors.
    Returns a dict mapping interface -> error_count (if > 0).
    """
    phy_issues = {}
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()

        # Skip header lines (first 2)
        for line in lines[2:]:
            parts = line.strip().split(':')
            if len(parts) < 2: continue

            iface = parts[0].strip()
            # Stats are in the second part, split by whitespace
            stats = parts[1].split()
            # RX fields: [0]bytes [1]packets [2]errs [3]drop [4]fifo [5]frame [6]compressed [7]multicast
            # We focus on CRC/Frame/Fifo which are definitely HW/Driver issues
            if len(stats) >= 8:
                try:
                    rx_errs = int(stats[2])
                    # rx_drop = int(stats[3]) # Ignored here (logical drops)
                    rx_fifo = int(stats[4])
                    rx_frame = int(stats[5])

                    hw_errors = rx_errs + rx_fifo + rx_frame

                    if hw_errors > 0:
                        phy_issues[iface] = hw_errors
                except ValueError:
                    pass
    except Exception:
        pass
    return phy_issues


# ------------------------------------------------------------------------------
# OS & HARDWARE COLLECTORS
# ------------------------------------------------------------------------------
def get_os_info():
    """Retrieves Operating System details."""
    d = {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "uptime": "N/A",
        "os_pretty_name": ""
    }

    # Try /etc/os-release
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        d["os_pretty_name"] = line.split("=", 1)[1].strip().strip('"')
                        break
    except Exception: pass

    # Fallback to /etc/issue
    if not d["os_pretty_name"] and os.path.exists("/etc/issue"):
        try:
            with open("/etc/issue", "r") as f:
                d["os_pretty_name"] = f.read().split('\\')[0].strip()
        except Exception: pass

    if not d["os_pretty_name"]:
        d["os_pretty_name"] = f"{platform.system()} {platform.release()}"

    # Uptime
    try:
        with open("/proc/uptime", "r") as f:
            up_seconds = float(f.read().split()[0])
            d["uptime"] = str(datetime.timedelta(seconds=int(up_seconds)))
    except Exception: pass

    return d


def get_hw_info():
    """Retrieves basic Hardware details (CPU/RAM)."""
    d = {"cpu": "Unknown CPU", "mem_mb": 0}

    # CPU Model
    try:
        with open("/proc/cpuinfo", "r") as f:
            for line in f:
                if "model name" in line:
                    d["cpu"] = line.split(":", 1)[1].strip()
                    break
    except Exception: pass

    # Memory
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if "MemTotal" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        d["mem_mb"] = int(int(parts[1]) / 1024)
                    break
    except Exception: pass

    return d


# ------------------------------------------------------------------------------
# NETWORK COLLECTOR
# ------------------------------------------------------------------------------
def get_net_info():
    """Retrieves Network Interfaces, IPs, Gateway, and DNS."""

    # [v0.70] Check Physical Errors
    phy_errors = _get_physical_net_errors()

    net_data = {
        "interfaces": [],
        "gateway": "N/A",
        "dns": [],
        "phy_errors": phy_errors,
        "has_phy_issues": len(phy_errors) > 0
    }

    # Interfaces & IPs
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]
            for line in lines:
                if ":" in line:
                    iface = line.split(":")[0].strip()
                    if iface == "lo": continue

                    ip_out = _run_cmd(["ip", "-4", "addr", "show", iface])
                    ip = "N/A"
                    match = re.search(r"inet\s+([0-9\.]+)", ip_out)
                    if match:
                        ip = match.group(1)

                    net_data["interfaces"].append({"name": iface, "ip": ip})
    except Exception: pass

    # Gateway
    try:
        route_out = _run_cmd(["ip", "route", "show", "default"])
        match = re.search(r"default via ([0-9\.]+)", route_out)
        if match:
            net_data["gateway"] = match.group(1)
    except Exception: pass

    # DNS
    try:
        if os.path.exists("/etc/resolv.conf"):
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) > 1:
                            net_data["dns"].append(parts[1])
    except Exception: pass

    return net_data


# ------------------------------------------------------------------------------
# STORAGE COLLECTOR (Enhanced)
# ------------------------------------------------------------------------------
def get_storage_info():
    """Retrieves Block Device topology using lsblk and /proc/mounts."""
    # Use -P for key="value" pairs, easier to parse correctly
    cmd = ["lsblk", "-P", "-o", "NAME,KNAME,PKNAME,MODEL,SERIAL,SIZE,TYPE,FSTYPE,UUID,MOUNTPOINT,HCTL"]
    out = _run_cmd(cmd)

    all_devices = {}
    mount_map = {}

    # 1. Parse lsblk output flat list
    for line in out.splitlines():
        d = {}
        for m in re.finditer(r'(\w+)="([^"]*)"', line):
            d[m.group(1).lower()] = m.group(2)

        kname = d.get('kname')
        if not kname: continue
        if not d.get('hctl'): d['hctl'] = ""

        d['children'] = []
        all_devices[kname] = d

        if d.get('mountpoint'):
            mount_map[d['mountpoint']] = d

    # 2. ENRICHMENT: Fallback to /proc/mounts
    try:
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3: continue

                dev_path = parts[0]
                mount_point = parts[1]

                if mount_point in mount_map: continue

                matched_dev = None
                base_name = os.path.basename(dev_path)

                if base_name in all_devices:
                    matched_dev = all_devices[base_name]
                elif dev_path.startswith("/dev/mapper/"):
                    try:
                        real_path = os.path.realpath(dev_path)
                        real_base = os.path.basename(real_path)
                        if real_base in all_devices:
                            matched_dev = all_devices[real_base]
                    except: pass

                if matched_dev:
                    if not matched_dev.get('mountpoint'):
                        matched_dev['mountpoint'] = mount_point
                    mount_map[mount_point] = matched_dev
    except Exception:
        pass

    # 3. Build Hierarchy
    roots = []
    for kname, dev in all_devices.items():
        pkname = dev.get('pkname')

        if not dev.get('hctl') and pkname and pkname in all_devices:
            dev['hctl'] = all_devices[pkname].get('hctl', '')

        if pkname and pkname in all_devices:
            all_devices[pkname]['children'].append(dev)
        else:
            roots.append(dev)

    return {"roots": roots, "mounts": mount_map}


# ------------------------------------------------------------------------------
# MAIN AGGREGATOR
# ------------------------------------------------------------------------------
def collect_full_inventory():
    """
    Aggregates all system info into a single dictionary.
    """
    return {
        "os": get_os_info(),
        "hw": get_hw_info(),
        "net": get_net_info(),
        "storage": get_storage_info(),

        # [FIX] Restored 'generated' key for html_report compatibility
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        # [v0.70] Also keep raw timestamp for internal logic if needed
        "timestamp": time.time()
    }
