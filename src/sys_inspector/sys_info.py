# -*- coding: utf-8 -*-
# FILE: src/sys_inspector/sys_info.py
# DESCRIPTION: Robust System Inventory.

"""
System Inventory Module.

Collects static and dynamic information about the host system, including
OS version, hardware specs, network interfaces, and storage topology.
Designed to be fault-tolerant when reading /proc files.
"""

import os
import socket
import platform
import subprocess
import datetime
import re
import glob


def _run_cmd(cmd):
    """
    Executes a shell command safely and returns stripped stdout.

    Args:
        cmd (list): List of command parts (e.g., ['ls', '-l']).

    Returns:
        str: Command output or 'N/A' on failure.
    """
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        ).strip()
    except Exception:
        return "N/A"


def get_os_info():
    """
    Retrieves Operating System details.

    Tries multiple sources (/etc/os-release, /etc/issue, platform) to
    identify the distribution. Also calculates system uptime.

    Returns:
        dict: Keys 'hostname', 'kernel', 'uptime', 'os_pretty_name'.
    """
    d = {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "uptime": "N/A",
        "os_pretty_name": ""
    }

    # Method 1: /etc/os-release
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        d["os_pretty_name"] = line.split("=", 1)[1].strip().strip('"')
                        break
    except Exception:
        pass

    # Method 2: /etc/issue
    if not d["os_pretty_name"] and os.path.exists("/etc/issue"):
        try:
            with open("/etc/issue", "r", encoding="utf-8") as f:
                d["os_pretty_name"] = f.read().split('\\')[0].strip()
        except Exception:
            pass

    # Method 3: Platform
    if not d["os_pretty_name"]:
        try:
            d["os_pretty_name"] = f"{platform.system()} {platform.release()}"
        except Exception:
            pass

    # Uptime
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            sec = float(f.read().split()[0])
            d["uptime"] = str(datetime.timedelta(seconds=int(sec)))
    except Exception:
        pass

    return d


def get_hw_info():
    """
    Retrieves CPU model and total memory.

    Parses /proc/cpuinfo and /proc/meminfo.

    Returns:
        dict: Keys 'cpu' (model name) and 'mem_mb' (total RAM in MB).
    """
    cpu = "Unknown"
    mem = 0
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if "model name" in line:
                    cpu = line.split(":")[1].strip()
                    break
    except Exception:
        pass
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            mem = int(int(f.readline().split()[1]) / 1024)
    except Exception:
        pass
    return {"cpu": cpu, "mem_mb": mem}


def get_network():
    """
    Retrieves active IPv4 network interfaces.

    Uses 'ip -4 -o addr show' to get compact interface list.

    Returns:
        list: Strings formatted as 'Interface: IP/CIDR'.
    """
    return _run_cmd(["ip", "-4", "-o", "addr", "show"]).splitlines()


def get_storage_map():
    """
    Maps block devices to their mount points and physical paths.

    Crucial for forensic analysis, identifying HCTL (SCSI address),
    WWN, and persistent paths (/dev/disk/by-path).

    Returns:
        dict: containing 'devices' (list) and 'mounts' (dict mapping mountpoint to device info).
    """
    cols = "NAME,KNAME,PKNAME,FSTYPE,MOUNTPOINT,UUID,PARTUUID,MODEL,VENDOR,SIZE,TYPE,HCTL,SERIAL,WWN"
    out = _run_cmd(["lsblk", "-P", "-o", cols])

    mount_map = {}
    devices = {}

    for line in out.splitlines():
        d = {}
        for m in re.finditer(r'(\w+)="([^"]*)"', line):
            d[m.group(1).lower()] = m.group(2)

        name = d.get('kname', '')
        if name:
            paths = []
            ids = []
            for p in glob.glob(f"/dev/disk/by-path/*{name}"):
                paths.append(os.path.basename(p))
            for i in glob.glob(f"/dev/disk/by-id/*{name}"):
                ids.append(os.path.basename(i))
            d['paths'] = paths
            d['ids'] = ids

        devices[d['name']] = d
        if d.get('mountpoint'):
            mount_map[d['mountpoint']] = d

    for name, d in devices.items():
        if not d.get('hctl') and d.get('pkname'):
            parent = devices.get(d['pkname'])
            if parent and parent.get('hctl'):
                d['hctl'] = parent['hctl']

    return {"devices": list(devices.values()), "mounts": mount_map}


def collect_full_inventory():
    """
    Aggregates all system information into a single dictionary.

    Returns:
        dict: Full inventory including OS, HW, Network, and Storage.
    """
    return {
        "os": get_os_info(),
        "hw": get_hw_info(),
        "net": get_network(),
        "storage": get_storage_map(),
        "generated": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
