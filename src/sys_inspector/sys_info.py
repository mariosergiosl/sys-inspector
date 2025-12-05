# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/sys_inspector/sys_info.py
# DESCRIPTION: Robust System Inventory with Hierarchical Storage & Network Topology.
# VERSION: 0.30.6
# ===============================================================================

import os
import socket
import platform
import subprocess
import datetime
import re
import glob


def _run_cmd(cmd):
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        ).strip()
    except Exception:
        return "N/A"


def get_os_info():
    d = {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "uptime": "N/A",
        "os_pretty_name": ""
    }
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        d["os_pretty_name"] = line.split("=", 1)[1].strip().strip('"')
                        break
    except Exception:
        pass

    if not d["os_pretty_name"] and os.path.exists("/etc/issue"):
        try:
            with open("/etc/issue", "r", encoding="utf-8") as f:
                d["os_pretty_name"] = f.read().split('\\')[0].strip()
        except Exception:
            pass

    if not d["os_pretty_name"]:
        d["os_pretty_name"] = f"{platform.system()} {platform.release()}"

    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            sec = float(f.read().split()[0])
            d["uptime"] = str(datetime.timedelta(seconds=int(sec)))
    except Exception:
        pass
    return d


def get_hw_info():
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


def get_network_details():
    """
    Retrieves comprehensive network topology: Interfaces, IPs, Gateway, DNS.
    """
    # 1. Interfaces and IPs
    interfaces = []
    try:
        ip_out = _run_cmd(["ip", "-4", "-o", "addr", "show"])
        for line in ip_out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 4:
                # Format: 2: eth0    inet 192.168.1.26/24 ...
                iface_name = parts[1]
                ip_cidr = parts[3]
                interfaces.append({"name": iface_name, "ip": ip_cidr})
    except Exception:
        pass

    # 2. Default Gateway
    gateway = "N/A"
    try:
        route_out = _run_cmd(["ip", "route"])
        for line in route_out.splitlines():
            if line.startswith("default via"):
                # default via 192.168.1.1 dev eth0 ...
                gateway = line.split()[2]
                break
    except Exception:
        pass

    # 3. DNS Servers
    dns = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("nameserver"):
                    dns.append(line.split()[1])
    except Exception:
        pass

    return {"interfaces": interfaces, "gateway": gateway, "dns": dns}


def get_storage_tree():
    """
    Builds a hierarchical tree of block devices (Disk -> Partitions -> LVM).
    """
    cols = "NAME,KNAME,PKNAME,TYPE,FSTYPE,MOUNTPOINT,SIZE,MODEL,HCTL,UUID,VENDOR"
    out = _run_cmd(["lsblk", "-P", "-o", cols])

    all_devices = {}
    mount_map = {}

    # 1. Parse flat list into dictionary keyed by KNAME (Kernel Name)
    for line in out.splitlines():
        d = {}
        for m in re.finditer(r'(\w+)="([^"]*)"', line):
            d[m.group(1).lower()] = m.group(2)

        d['children'] = []
        kname = d.get('kname')

        # Path discovery
        if kname:
            paths = []
            for p in glob.glob(f"/dev/disk/by-path/*{kname}"):
                paths.append(os.path.basename(p))
            d['paths'] = paths

        all_devices[kname] = d
        if d.get('mountpoint'):
            mount_map[d['mountpoint']] = d

    # 2. Build Hierarchy
    roots = []
    for kname, dev in all_devices.items():
        pkname = dev.get('pkname')
        # HCTL inheritance for partitions if missing
        if not dev.get('hctl') and pkname and pkname in all_devices:
            dev['hctl'] = all_devices[pkname].get('hctl', '')

        if pkname and pkname in all_devices:
            all_devices[pkname]['children'].append(dev)
        else:
            # Devices without parent are roots (physical disks, loop, rom)
            roots.append(dev)

    return {"roots": roots, "mounts": mount_map}


def collect_full_inventory():
    """Aggregates all system info."""
    return {
        "os": get_os_info(),
        "hw": get_hw_info(),
        "net": get_network_details(),
        "storage": get_storage_tree(),
        "generated": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
