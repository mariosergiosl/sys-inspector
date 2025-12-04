#!/usr/bin/python3
# -*- coding: utf-8 -*-
# FILE: src/inspector.py
# VERSION: 0.30.3 (Refactored for Pylint Compliance)

"""
Sys-Inspector Core Module.

Orchestrates the observability pipeline with added support for:
- Hierarchical Storage Topology in HTML report
- Enhanced Network Topology in HTML report
- Recursive badge propagation
"""

import sys
import os
import argparse
import time
import socket
import struct
import pwd
import hashlib
import glob
import traceback
import datetime
import base64
from bcc import BPF

# Add src directory to Python path to allow relative imports
sys.path.append('src')
try:
    from sys_inspector.bpf_programs import BPF_SOURCE
    import sys_inspector.sys_info as sys_info
    import sys_inspector.report_generator as report_generator
except ImportError as err:
    sys.exit(f"Error importing modules: {err}")

PROGRAM_VERSION = "0.30.3"
LOGO_PATH = "/etc/sys-inspector/logo.png"
DEFAULT_LOG_DIR = "/var/log/sys-inspector"
_USER_CACHE = {}
CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
b = None  # Global BPF object reference (kept for event handler callback)


# --- HELPER FUNCTIONS ---

def get_username(uid):
    """Resolves User ID to Username with caching."""
    if uid not in _USER_CACHE:
        try:
            _USER_CACHE[uid] = pwd.getpwuid(uid).pw_name
        except Exception:
            _USER_CACHE[uid] = str(uid)
    return _USER_CACHE[uid]


def calculate_md5(filepath):
    """Calculates MD5 hash safely."""
    if not os.path.exists(filepath):
        return "N/A"
    try:
        hasher = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return "ACCESS_DENIED"


def get_security_context(pid):
    """Reads security context."""
    try:
        with open(f"/proc/{pid}/attr/current", "r", encoding="utf-8") as f:
            return f.read().strip().replace('\0', ' ')
    except Exception:
        return "unconfined"


def get_suspicious_env(pid):
    """Scans environment variables for suspicious entries."""
    suspicious = []
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            env_data = f.read().decode('utf-8', 'replace').split('\0')

        for env_var in env_data:
            key = env_var.split('=')[0]
            if key in ["LD_PRELOAD", "LD_LIBRARY_PATH"]:
                suspicious.append(env_var)
            if key == "PATH" and "/tmp" in env_var:
                suspicious.append("PATH_IN_TMP")
    except Exception:
        pass
    return suspicious


def get_process_context(pid):
    """Retrieves execution context tags."""
    tags = []
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            env_items = f.read().decode('utf-8', 'replace').split('\0')
            env = {}
            for item in env_items:
                if "=" in item:
                    k, v = item.split("=", 1)
                    env[k] = v

        if 'SSH_CONNECTION' in env:
            tags.append(f"[SSH:{env['SSH_CONNECTION'].split()[0]}]")
        if 'SUDO_USER' in env:
            tags.append(f"[SUDO:{env['SUDO_USER']}]")
        if 'TMUX' in env:
            tags.append("[TMUX]")
    except Exception:
        pass
    return " ".join(tags)


def get_lifetime_io(pid):
    """Reads lifetime I/O stats."""
    r_bytes, w_bytes = 0, 0
    try:
        with open(f"/proc/{pid}/io", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("rchar:"):
                    r_bytes = int(line.split()[1])
                elif line.startswith("wchar:"):
                    w_bytes = int(line.split()[1])
    except Exception:
        pass
    return r_bytes, w_bytes


def get_cpu_ticks(pid):
    """Reads CPU ticks."""
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
            parts = f.read().split()
            return int(parts[13]) + int(parts[14])
    except Exception:
        return 0


def get_libraries(pid):
    """Scans loaded shared libraries."""
    libs = set()
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="utf-8") as f:
            for line in f:
                if ".so" in line and "/" in line:
                    path = line.split()[-1]
                    if path.startswith("/"):
                        libs.add(path)
                    if len(libs) >= 50:
                        break
    except Exception:
        pass
    return list(libs)


def is_suspicious_lib(libpath):
    """Checks if a library path is suspicious (Logic ported for aggregation)."""
    bad = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")
    if libpath.startswith(bad) or "(deleted)" in libpath:
        return True
    return False


def check_anomaly(node):
    """Performs heuristic anomaly detection."""
    score = 0
    if node.cmd.startswith(("/tmp", "/dev/shm")):
        score += 10
    if "(deleted)" in node.cmd:
        score += 5
    if any(x in node.cmd for x in ["nc ", "ncat", "socat"]):
        score += 5
    if node.suspicious_env:
        score += 5
    node.anomaly_score = score


# --- DATA STRUCTURE ---

class ProcessNode:
    """
    Represents a captured process.
    Updated to include tree_* flags for badge propagation.
    """
    def __init__(self, pid, ppid, cmd, uid, prio=120):
        self.pid = pid
        self.ppid = ppid
        self.cmd = cmd
        self.uid = uid
        self.prio = prio

        # Memory
        self.vsz = 0
        self.rss = 0

        # Disk I/O
        self.read_bytes_delta = 0
        self.write_bytes_delta = 0
        self.read_bytes_total = 0
        self.write_bytes_total = 0

        # Network Traffic
        self.net_tx_bytes = 0
        self.net_rx_bytes = 0

        # Tree Aggregation Stats (Sums)
        self.tree_read_delta = 0
        self.tree_write_delta = 0
        self.tree_net_tx = 0
        self.tree_net_rx = 0
        self.tree_anomaly_score = 0

        # Tree Aggregation Flags (Boolean Bubbling)
        self.tree_has_ssh = False
        self.tree_has_sudo = False
        self.tree_has_unsafe = False
        self.tree_has_warn = False
        self.tree_has_net_err = False

        # CPU Stats
        self.cpu_start_ticks = 0
        self.cpu_usage_pct = 0.0

        # Network Health
        self.tcp_retrans = 0
        self.tcp_drops = 0

        # Artifacts
        self.open_files = set()
        self.connections = set()
        self.is_new = False
        self.context = ""
        self.sec_ctx = "N/A"
        self.suspicious_env = []
        self.md5 = "Calculating..."
        self.anomaly_score = 0
        self.libs = []


process_tree = {}


def scan_proc(init_cpu=False):
    """Populates process tree from /proc."""
    print("Scanning /proc...", end="\r")
    my_pid = os.getpid()
    for path in glob.glob('/proc/[0-9]*'):
        try:
            pid = int(os.path.basename(path))
            if pid == my_pid:
                continue

            with open(os.path.join(path, 'status'), "r", encoding="utf-8") as f:
                s = f.read()
            info = {line.split(':')[0]: line.split(':', 1)[1].strip()
                    for line in s.splitlines() if ':' in line}

            if not init_cpu and pid in process_tree:
                process_tree[pid].rss = int(info.get('VmHWM', '0').replace('kB', '').strip()) * 1024
                continue

            try:
                with open(os.path.join(path, 'cmdline'), 'rb') as f:
                    cmd_bytes = f.read().replace(b'\0', b' ')
                    cmd = cmd_bytes.decode('utf-8', 'replace').strip() or info.get('Name', '?')
            except Exception:
                cmd = info.get('Name', '?')

            ppid = int(info.get('PPid', 0))
            uid_val = int(info.get('Uid', '0').split()[0])
            node = ProcessNode(pid, ppid, cmd, uid_val)

            if 'VmHWM' in info:
                node.rss = int(info.get('VmHWM', '0').replace('kB', '').strip()) * 1024

            node.cpu_start_ticks = get_cpu_ticks(pid)
            node.context = get_process_context(pid)
            node.sec_ctx = get_security_context(pid)
            node.suspicious_env = get_suspicious_env(pid)
            node.read_bytes_total, node.write_bytes_total = get_lifetime_io(pid)

            exe_link = os.path.realpath(os.path.join(path, 'exe'))
            if os.path.exists(exe_link):
                node.md5 = calculate_md5(exe_link)
            else:
                node.md5 = "N/A"

            node.libs = get_libraries(pid)
            check_anomaly(node)
            process_tree[pid] = node

        except Exception:
            continue
    print("Scanning /proc complete.              ")


def handle_event(_cpu, data, _size):
    """eBPF Event Handler."""
    global b
    event = b["events"].event(data)
    pid = event.pid

    if pid not in process_tree:
        comm = event.comm.decode('utf-8', 'replace')
        process_tree[pid] = ProcessNode(pid, event.ppid, comm, event.uid, event.prio)
        process_tree[pid].is_new = True
        process_tree[pid].sec_ctx = get_security_context(pid)
        process_tree[pid].read_bytes_total, process_tree[pid].write_bytes_total = get_lifetime_io(pid)
        process_tree[pid].libs = get_libraries(pid)

    node = process_tree[pid]
    node.rss = max(node.rss, event.mem_peak_rss)

    t = event.type_id.decode('utf-8', 'replace')
    f = event.filename.decode('utf-8', 'replace')

    if t == 'E':  # Execve
        node.cmd = f
        node.is_new = True
        node.md5 = calculate_md5(f)
        node.context = get_process_context(pid)
        check_anomaly(node)
    elif t == 'O':  # OpenAt
        if not f.startswith(("/proc", "/sys", "/dev")):
            node.open_files.add(f)
    elif t == 'N':  # Connect
        try:
            dst = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
            node.connections.add(f"IPv4 -> {dst}:{socket.ntohs(event.dport)}")
        except Exception:
            pass
    elif t == 'R':
        node.read_bytes_delta += event.io_bytes
    elif t == 'W':
        node.write_bytes_delta += event.io_bytes


def calculate_final_cpu(duration):
    """Calculates CPU usage."""
    print("Calculating CPU usage...")
    for pid, node in process_tree.items():
        end_ticks = get_cpu_ticks(pid)
        if end_ticks > 0 and node.cpu_start_ticks > 0:
            delta = end_ticks - node.cpu_start_ticks
            try:
                node.cpu_usage_pct = (delta / float(CLK_TCK)) / duration * 100.0
            except Exception:
                pass


def collect_network_stats(bpf_obj):
    """Reads BPF Maps. Accepts BPF object to avoid global."""
    print("Collecting Network Health & Traffic Stats...")
    try:
        retrans_map = bpf_obj["tcp_retrans_map"]
        for k, v in retrans_map.items():
            pid = k.value
            count = v.value
            if pid in process_tree:
                process_tree[pid].tcp_retrans = count
                if count > 10:
                    process_tree[pid].anomaly_score += 2

        drop_map = bpf_obj["tcp_drop_map"]
        for k, v in drop_map.items():
            pid = k.value
            count = v.value
            if pid in process_tree:
                process_tree[pid].tcp_drops = count
                process_tree[pid].anomaly_score += 5

        tx_map = bpf_obj["net_bytes_sent"]
        for k, v in tx_map.items():
            pid = k.value
            if pid in process_tree:
                process_tree[pid].net_tx_bytes = v.value

        rx_map = bpf_obj["net_bytes_recv"]
        for k, v in rx_map.items():
            pid = k.value
            if pid in process_tree:
                process_tree[pid].net_rx_bytes = v.value
    except Exception:
        pass


def aggregate_tree_stats():
    """
    Recursively sums stats and propagates Badges (Alerts) from children to parents.
    Updates tree_* fields in ProcessNode.
    """
    print("Aggregating Tree Stats (Disk, Net & Badges)...")

    def get_tree_stats(pid):
        if pid not in process_tree:
            return 0, 0, 0, 0, 0, False, False, False, False, False

        node = process_tree[pid]

        # 1. Determine Local Flags (Self)
        local_ssh = "[SSH:" in node.context
        local_sudo = "[SUDO:" in node.context
        local_unsafe = any(is_suspicious_lib(l) for l in node.libs)
        local_warn = node.anomaly_score > 0
        local_net_err = (node.tcp_retrans > 0 or node.tcp_drops > 0)

        # 2. Base Values (Self)
        r_sum = node.read_bytes_delta
        w_sum = node.write_bytes_delta
        tx_sum = node.net_tx_bytes
        rx_sum = node.net_rx_bytes
        anom_sum = node.anomaly_score

        # 3. Recursive aggregation from children
        children = [p for p in process_tree.values() if p.ppid == pid]

        tree_ssh = local_ssh
        tree_sudo = local_sudo
        tree_unsafe = local_unsafe
        tree_warn = local_warn
        tree_net_err = local_net_err

        for child in children:
            # Recursive call
            cr, cw, ctx, crx, ca, c_ssh, c_sudo, c_unsafe, c_warn, c_net = get_tree_stats(child.pid)

            # Sum numeric metrics
            r_sum += cr
            w_sum += cw
            tx_sum += ctx
            rx_sum += crx
            anom_sum += ca

            # OR Logic for Badges (Propagate up)
            tree_ssh = tree_ssh or c_ssh
            tree_sudo = tree_sudo or c_sudo
            tree_unsafe = tree_unsafe or c_unsafe
            tree_warn = tree_warn or c_warn
            tree_net_err = tree_net_err or c_net

        # Store Aggregated Values in Node
        node.tree_read_delta = r_sum
        node.tree_write_delta = w_sum
        node.tree_net_tx = tx_sum
        node.tree_net_rx = rx_sum
        node.tree_anomaly_score = anom_sum

        # Store Boolean Flags in Node
        node.tree_has_ssh = tree_ssh
        node.tree_has_sudo = tree_sudo
        node.tree_has_unsafe = tree_unsafe
        node.tree_has_warn = tree_warn
        node.tree_has_net_err = tree_net_err

        return r_sum, w_sum, tx_sum, rx_sum, anom_sum, tree_ssh, tree_sudo, tree_unsafe, tree_warn, tree_net_err

    # Trigger recursion from Root nodes
    roots = [p.pid for p in process_tree.values() if p.ppid not in process_tree]
    for r in roots:
        get_tree_stats(r)


def load_logo():
    """Reads /etc/sys-inspector/logo.png and converts to Base64."""
    if os.path.exists(LOGO_PATH):
        try:
            with open(LOGO_PATH, "rb") as img_file:
                encoded_string = base64.b64encode(img_file.read()).decode('utf-8')
                return encoded_string
        except Exception as e:
            print(f"Warning: Could not load logo: {e}")
    return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--html", help="Custom HTML report file path")
    parser.add_argument("-d", "--duration", type=int, default=20, help="Capture seconds (default: 20)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("Error: Root required.")

    # --- Path Logic ---
    output_file = args.html

    if not output_file:
        # Create default filename
        hostname = socket.gethostname()
        now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sys-inspector_{PROGRAM_VERSION}_{hostname}_{now_str}.html"

        # Ensure directory exists
        try:
            os.makedirs(DEFAULT_LOG_DIR, exist_ok=True)
        except Exception as e:
            sys.exit(f"Error creating default directory {DEFAULT_LOG_DIR}: {e}")

        output_file = os.path.join(DEFAULT_LOG_DIR, filename)
    else:
        # Ensure directory exists for custom path
        output_dir = os.path.dirname(os.path.abspath(output_file))
        if output_dir:
            try:
                os.makedirs(output_dir, exist_ok=True)
            except Exception as e:
                sys.exit(f"Error creating directory {output_dir}: {e}")

    print(f"Loading sys-inspector v{PROGRAM_VERSION}...")
    print("Collecting system inventory...")
    inv = sys_info.collect_full_inventory()

    # Inject current PID
    bpf_text = BPF_SOURCE.replace("00000", str(os.getpid()))

    global b
    try:
        b = BPF(text=bpf_text)
        b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
        b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="syscall__openat")
        b.attach_kprobe(event="tcp_v4_connect", fn_name="kprobe__tcp_v4_connect")
        b.attach_kretprobe(event="vfs_read", fn_name="kretprobe__vfs_read")
        b.attach_kretprobe(event="vfs_write", fn_name="kretprobe__vfs_write")
        b.attach_kprobe(event="tcp_sendmsg", fn_name="kprobe__tcp_sendmsg")
        b.attach_kprobe(event="tcp_cleanup_rbuf", fn_name="kprobe__tcp_cleanup_rbuf")
    except Exception as err:
        sys.exit(f"BPF Error: {err}")

    scan_proc(init_cpu=True)
    print(f"Capturing activity for {args.duration}s (Please wait)...")
    b["events"].open_perf_buffer(handle_event)
    s = time.time()
    try:
        while time.time() - s < args.duration:
            b.perf_buffer_poll(100)
    except KeyboardInterrupt:
        pass

    calculate_final_cpu(args.duration)

    # Passed 'b' instance explicitly to fix W0603
    collect_network_stats(b)

    aggregate_tree_stats()

    # Logo Logic
    logo_data = load_logo()

    print(f"Generating HTML Report at: {output_file}")
    try:
        out = report_generator.generate_html(inv, process_tree, output_file, PROGRAM_VERSION, logo_b64=logo_data)
        print(f"\nSUCCESS: Report generated at: {os.path.abspath(out)}")
    except Exception as err:
        traceback.print_exc()
        print(f"Error generating HTML: {err}")


if __name__ == "__main__":
    main()
