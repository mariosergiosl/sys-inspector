# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/exporters/html_report.py
# DESCRIPTION: Generates the HTML reports (Static & Dynamic).
#              Handles visual formatting, Cgroup interpretation, and AJAX fragments.
#
#              UPDATED:
#              - UX: Added "ACTIVE CONNECTIONS" label to distinguish from Drops.
#              - SAFETY: Limited Blocked Packets list to Top 50 to prevent
#                        HTML explosion during massive Port Scans.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.90.15
# ==============================================================================

# import os
import re
from src.exporters.web_assets import HTML_TEMPLATE, CSS_BASE, JS_BLOCK, LEGEND_HTML


# ------------------------------------------------------------------------------
# LOGIC HELPERS
# ------------------------------------------------------------------------------
def format_bytes(size):
    """Converts bytes to human readable string."""
    if size < 1024:
        return "0"
    for unit in ['K', 'M', 'G', 'T']:
        size /= 1024
        if size < 1024:
            return f"{size:.1f}{unit}"
    return f"{size:.1f}P"


def format_number(num):
    """Formats large numbers (e.g. 37000 -> 37k)."""
    if num >= 1000000:
        return f"{num/1000000:.1f}M"
    if num >= 1000:
        return f"{num/1000:.1f}k"
    return str(num)


def is_suspicious_lib(libpath):
    """Checks if a library path is suspicious."""
    bad_prefixes = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")
    if libpath.startswith(bad_prefixes) or "(deleted)" in libpath:
        return True
    return False


def _format_security_context(ctx):
    """Parses security context string to identify SELinux or AppArmor."""
    ctx = ctx.strip() if ctx else ""

    if not ctx or ctx == "N/A" or ctx == "unconfined":
        tooltip = "Process is running without mandatory access control enforcement."
        return f"<span style='color:#777; cursor:help' title='{tooltip}'>[None] No SELinux Context / No AppArmor Confinement</span> <span style='font-size:0.9em;color:#555'>({ctx if ctx else 'Empty'})</span>"

    if ":" in ctx and len(ctx.split(":")) >= 3:
        tooltip = "SELinux Context:\nUser : Role : Type : Level"
        return f"<span style='color:var(--acc);cursor:help' title='{tooltip}'>[SELinux]</span> {ctx}"

    if "/" in ctx or "(" in ctx:
        tooltip = "AppArmor Profile:\nName (Mode)"
        return f"<span style='color:var(--pur);cursor:help' title='{tooltip}'>[AppArmor]</span> {ctx}"

    return f"<span style='color:#ccc'>[Custom/Other]</span> {ctx}"


def build_disk_string(path, mount_map, is_container=False):
    """
    Matches a file path to its mount point metadata.
    Includes logic for Root Fallback, Tmpfs, and Container Overlay.
    """
    if path.startswith(("/proc/", "/sys/", "socket:", "pipe:", "anon_inode:")):
        return "<span class='disk-str'>(Pseudo/Virtual)</span>"

    best_match = ""
    info = None
    for mp, d in mount_map.items():
        if path == mp or path.startswith(mp + "/"):
            if len(mp) > len(best_match):
                best_match = mp
                info = d

    if not info and path.startswith("/") and '/' in mount_map:
        best_match = '/'
        info = mount_map['/']

    if info:
        meta = []
        if info.get('fstype'): meta.append(f"FS:{info['fstype']}")
        if info.get('name'): meta.append(f"DEV:/dev/{info['name']}")
        if info.get('uuid'): meta.append(f"UUID:{info['uuid']}")
        if info.get('hctl'): meta.append(f"<span class='hctl-tag'>HCTL:{info['hctl']}</span>")
        return f"<span class='disk-str'>({' '.join(meta)})</span>"

    if path.startswith(("/dev/shm", "/run", "/var/run", "/tmp")):
        return "<span class='disk-str'>(FS:tmpfs/Memory)</span>"

    if is_container:
        return "<span class='disk-str'>(FS:Overlay/Container)</span>"

    if path.startswith("/"):
        return "<span class='disk-str'>(FS: Host Filesystem | Mount info missing)</span>"

    return ""


def _get_anomaly_reasons(node):
    reasons = []
    if hasattr(node, 'detection_reasons') and node.detection_reasons:
        for r in node.detection_reasons:
            reasons.append(r)

    if node.is_inspector:
        reasons.append("PROCESS ROLE: Security Inspector. Holds FANOTIFY handle.")
        if node.inspector_data:
            mode = node.inspector_data.get("mode", "Unknown")
            flags = node.inspector_data.get("flags", "")
            reasons.append(f"INSPECTION TYPE: {mode} (Flags: {flags})")
            if "SYNC" in mode:
                reasons.append("IMPACT: Sync mode causes direct I/O latency on target processes.")

    if node.cmd.startswith(("/tmp", "/dev/shm")) and not any("executed from unsafe path" in r for r in reasons):
        reasons.append(f"LOCATION: Binary executed from temporary directory: {node.cmd}")

    if "(deleted)" in node.cmd:
        reasons.append("INTEGRITY: Binary file has been deleted from disk while running")

    return reasons


# ------------------------------------------------------------------------------
# CGROUP LOGIC
# ------------------------------------------------------------------------------
def _analyze_cgroup_path(path):
    html = ""
    category = "System"
    runtime_color = "#888"
    runtime_name = "Unknown/System"

    if "libpod" in path:
        runtime_name = "Podman (Libpod)"
        runtime_color = "#b180ff"
        category = "Container"
    elif "docker" in path:
        runtime_name = "Docker Engine"
        runtime_color = "#0078d4"
        category = "Container"
    elif "kubepods" in path:
        runtime_name = "Kubernetes (K8s)"
        runtime_color = "#4ec9b0"
        category = "Container"
    elif "machine.slice" in path:
        runtime_name = "Systemd VM/LXC"
        runtime_color = "#fcc419"
        category = "VM"
    elif ".slice" in path or ".service" in path:
        parts = path.split('/')
        svc = parts[-1] if parts else path
        if svc == "": svc = "Root Slice"
        runtime_name = svc
        category = "System"

    html = f"<span style='color:{runtime_color}; font-weight:bold'>{runtime_name}</span>"

    full_id = path
    match = re.search(r'([a-f0-9]{64})', path)
    if match:
        full_id = match.group(1)
        html += f" <span style='color:#666'>ID:</span> <span style='font-family:monospace; color:#ccc'>{full_id}</span>"
    else:
        if category == "System":
            clean = path.strip("/")
            if not clean: clean = "/"
            html += f" <span style='color:#777'>{clean}</span>"

    return category, html, full_id


def _process_cgroups_block(raw_cgroups):
    if not raw_cgroups: return ""

    grouped = {}

    for line in raw_cgroups:
        parts = line.split(':')
        if len(parts) < 3: continue

        controllers = parts[1] if parts[1] else "unified"
        path = parts[2]

        is_v2 = "unified" in controllers
        ver_label = "[v2]" if is_v2 else "[v1]"
        ver_style = "color:var(--cyn); font-size:9px; border:1px solid var(--cyn); padding:0 3px; border-radius:2px; margin-right:5px" if is_v2 else "color:#888; font-size:9px; border:1px solid #555; padding:0 3px; border-radius:2px; margin-right:5px"
        ver_html = f"<span style='{ver_style}'>{ver_label}</span>"

        if path not in grouped:
            cat, display_html, _ = _analyze_cgroup_path(path)
            grouped[path] = {
                "html": display_html,
                "ctrls": set(),
                "ver_html": ver_html
            }

        for c in controllers.split(','):
            if c: grouped[path]["ctrls"].add(c)

    final_html = ""
    for path, data in grouped.items():
        ctrl_tags = ""
        for c in sorted(data["ctrls"]):
            ctrl_tags += f"<span style='background:#333; color:#aaa; border:1px solid #555; padding:2px 4px; font-size:10px; border-radius:3px; margin-right:4px; display:inline-block;'>{c}</span>"

        final_html += f"<div style='margin-bottom:6px; border-bottom:1px dashed #333; padding-bottom:4px'>"
        final_html += f"<div>{data['html']}</div>"
        final_html += f"<div style='margin-top:4px'>{ctrl_tags} {data['ver_html']}</div>"
        final_html += f"<div style='font-size:9px; color:#555; margin-top:2px; word-break:break-all'>{path}</div>"
        final_html += "</div>"

    return final_html


# ------------------------------------------------------------------------------
# COMPONENT RENDERERS
# ------------------------------------------------------------------------------
def _render_badges(node, tree=None):
    badges = []
    tag_map = {
        "SSH": ("🔌", "t-ssh", "Active SSH Connection"),
        "SUDO": ("🛡️", "t-sudo", "Running via Sudo"),
        "MINER": ("⛏️", "t-miner", "Crypto Mining Signature"),
        "UNSAFE": ("☢️", "t-unsafe", "Unsafe Path (/tmp, /dev/shm)"),
        "EDR/AV": ("💊", "t-edr", "Security Inspectors - EDR/AV"),
        "INSPECTOR": ("💊", "t-edr", "Security Inspectors - EDR/AV"),
        "EDR-WAIT": ("🧊", "t-edr", "Process Frozen by EDR/AV (Wchan Wait)"),
        "GPU": ("🕹️", "t-gpu", "Accessing GPU Resources"),
        "CONTAINER": ("📦", "t-cont", "Containerized Process"),
        "ZOMBIE": ("🧟", "t-zombie", "Zombie Process"),
        "IMMUTABLE": ("🔒", "t-immutable", "Immutable File Attribute")
    }

    if node.is_new:
        badges.append('<span class="tag t-new" data-filter="NEW" title="New Process">✨<span class="visually-hidden">NEW</span></span>')

    seen = set()
    for tag in node.context_tags:
        if "INSPECTOR" in tag: tag = "EDR/AV"
        if tag in tag_map and tag not in seen:
            icon, cls, tooltip = tag_map[tag]
            if tag == "ZOMBIE" and tree:
                parent_node = tree.get(node.ppid)
                if parent_node:
                    tooltip += f"\nWaiting for Parent PID: {node.ppid}\nParent Cmd: {parent_node.cmd}\nParent User: {parent_node.username}"
                else:
                    tooltip += f"\nParent PID {node.ppid} not found in tree."
            badges.append(f'<span class="tag {cls}" data-filter="{tag}" title="{tooltip}">{icon}<span class="visually-hidden">{tag}</span></span>')
            seen.add(tag)

    tree_drops = getattr(node, 'tree_tcp_drops', 0)
    tree_retrans = getattr(node, 'tree_tcp_retrans', 0)
    net_issues = tree_drops + tree_retrans
    if net_issues > 0:
        tooltip = f"Network Issues: {tree_drops} Drops, {tree_retrans} Retransmits"
        badges.append(f'<span class="tag t-err" data-filter="NET ERR" title="{tooltip}">❌ {format_number(net_issues)}<span class="visually-hidden">NET ERR</span></span>')

    score_to_show = getattr(node, 'tree_max_score', node.anomaly_score)
    if score_to_show > 0:
        tooltip = "Score Breakdown:\nCheck Details."
        badges.append(f'<b class="tag t-warn" data-filter="WARN" title="{tooltip}">⚠️ {score_to_show}<span class="visually-hidden">WARN</span></b>')

    if "EDR-WAIT" in getattr(node, 'context_tags', []):
        icon, cls, tooltip = tag_map["EDR-WAIT"]
        badges.append(f'<span class="tag {cls}" data-filter="EDR-WAIT" title="{tooltip}">{icon}<span class="visually-hidden">EDR-WAIT</span></span>')

    return " ".join(badges)


def _get_details_html(node, mounts):
    """Builds the hidden detail row content."""
    html = "<div class='det-grid'><div><table class='ctx-tbl'>"
    html += f"<tr><td class='ctx-lbl'>Full Command:</td><td class='ctx-val'>{node.cmd}</td></tr>"
    html += f"<tr><td class='ctx-lbl'>MD5:</td><td class='ctx-val'>{node.md5}</td></tr>"

    user_display = f"{node.username} ({node.uid})"
    login_user = getattr(node, 'loginuser', None)
    if login_user and login_user != "unset" and login_user != node.username:
        user_display += f" <span style='color:var(--yel); font-weight:bold; margin-left:5px'>&larr; via {login_user}</span>"
    html += f"<tr><td class='ctx-lbl'>User/UID:</td><td class='ctx-val'>{user_display}</td></tr>"

    raw_sec = getattr(node, 'security_context', 'N/A')
    formatted_sec = _format_security_context(raw_sec)
    html += f"<tr><td class='ctx-lbl'>Security:</td><td class='ctx-val'>{formatted_sec}</td></tr>"
    # [v0.70 FEAT] Temporal Details
    html += f"<tr><td class='ctx-lbl'>Started ON:</td><td class='ctx-val' style='color:var(--yel)'>{getattr(node, 'start_ts_abs', 'N/A')}</td></tr>"
    html += f"<tr><td class='ctx-lbl'>Life Time:</td><td class='ctx-val' style='color:var(--grn)'>{getattr(node, 'duration_str', 'N/A')}</td></tr>"

    is_sudo = "Yes" if "sudo" in node.cmd else "No"
    is_ssh = "Yes" if "sshd" in node.cmd else "No"
    html += f"<tr><td class='ctx-lbl'>Sudo/SSH:</td><td class='ctx-val'>Sudo:{is_sudo} / SSH:{is_ssh}</td></tr>"

    role_val = "Standard Process"
    role_style = ""
    if node.is_inspector:
        role_val = "Security Inspector (EDR/AV)"
        role_style = "color:var(--acc); font-weight:bold"

    role_tooltip = "Standard: Normal application.\nInspector: Security tool monitoring other processes via Fanotify."
    html += f"<tr><td class='ctx-lbl' style='{role_style}' title='{role_tooltip}'>Process Role <span style='cursor:help;font-size:10px;border:1px solid #555;border-radius:50%;width:12px;height:12px;display:inline-flex;align-items:center;justify-content:center'>?</span>:</td><td class='ctx-val' style='{role_style}'>{role_val}</td></tr>"

    c_id = node.container_id or 'Host'
    html += f"<tr><td class='ctx-lbl'>Container:</td><td class='ctx-val'>{c_id}</td></tr>"

    if hasattr(node, 'cgroups') and node.cgroups:
        formatted_cgroups = _process_cgroups_block(node.cgroups)
        cg_tooltip = "Kernel Limits (v1/v2)"
        html += f"<tr><td class='ctx-lbl' title='{cg_tooltip}'>Resource Limits <span style='cursor:help;font-size:10px;border:1px solid #555;border-radius:50%;width:12px;height:12px;display:inline-flex;align-items:center;justify-content:center'>?</span> (Cgroups):</td><td class='ctx-val'><div class='list-box'>{formatted_cgroups}</div></td></tr>"

    r_val = format_bytes(node.read_bytes_delta)
    w_val = format_bytes(node.write_bytes_delta)
    html += f"<tr><td class='ctx-lbl'>Session I/O:</td><td class='ctx-val'>R: {r_val} | W: {w_val}</td></tr>"

    mem_rss = format_bytes(getattr(node, 'rss', 0))
    mem_vsz = format_bytes(getattr(node, 'vsz', 0))
    html += f"<tr><td class='ctx-lbl'>Memory Usage:</td><td class='ctx-val'>RSS: {mem_rss} | VSZ: {mem_vsz}</td></tr>"

    net_tx_tot = format_bytes(getattr(node, 'net_tx_bytes', 0))
    net_rx_tot = format_bytes(getattr(node, 'net_rx_bytes', 0))
    html += f"<tr><td class='ctx-lbl'>Session Network:</td><td class='ctx-val'>TX: {net_tx_tot} | RX: {net_rx_tot}</td></tr>"

    lat_ms = node.io_latency_tot / 1000000.0
    ops = node.io_ops_count
    avg_lat = (lat_ms / ops) if ops > 0 else 0
    html += f"<tr><td class='ctx-lbl'>Disk Latency:</td><td class='ctx-val'>Total: {lat_ms:.2f}ms | Avg: {avg_lat:.2f}ms | Ops: {ops}</td></tr>"

    html += "</table></div>"

    # [UPDATED] Network Section: Separated Active from Blocked
    html += "<div><span class='det-title'>Network Resilience</span>"
    retr_style = "color:var(--red);font-weight:bold" if node.tcp_retrans > 0 else "color:#888"
    drop_style = "color:var(--red);font-weight:bold" if node.tcp_drops > 0 else "color:#888"
    html += f"<div style='margin-bottom:8px'>Retransmits: <span style='{retr_style}'>{node.tcp_retrans}</span> | Drops: <span style='{drop_style}'>{node.tcp_drops}</span></div>"

    # [NEW] Active Connections Label
    html += "<div style='font-size:10px; font-weight:bold; color:#777; margin-bottom:2px; text-transform:uppercase'>Active Connections:</div>"
    if node.connections:
        for c in node.connections:
            html += f"<div class='mono' style='color:#bbb; font-size:11px'>{c}</div>"
    else:
        html += "<div class='d-na' style='margin-left:10px'>No active connections</div>"

    # [NEW] Blocked Packets (Limited to 50 items)
    if hasattr(node, 'network_drops_details') and node.network_drops_details:
        html += "<div style='margin-top:10px; border-top:1px dashed #444; padding-top:5px'>"
        html += "<span style='color:var(--red); font-weight:bold; font-size:11px'> BLOCKED PACKETS SUMMARY:</span>"

        counts = {}
        for drop in node.network_drops_details:
            counts[drop] = counts.get(drop, 0) + 1

        sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)

        # SAFETY LIMIT: 50 items
        limit = 50
        display_items = sorted_counts[:limit]
        remainder = len(sorted_counts) - limit

        html += "<div class='list-box' style='max-height:150px; margin-top:5px'>"
        for pair, count in display_items:
            html += f"<div class='mono' style='color:#ff6b6b; font-size:11px; margin-left:5px'>{pair} <span style='color:#fff;font-weight:bold'>[x{count}]</span></div>"

        if remainder > 0:
            html += f"<div style='color:#777; font-style:italic; margin-left:5px; margin-top:2px'>... and {remainder} more unique blocked targets.</div>"

        html += "</div></div>"

    html += "</div></div>"

    reasons = _get_anomaly_reasons(node)
    if reasons:
        html += "<div class='det-blk'><span class='det-title' style='color:var(--red)'>Security Forensics</span>"
        for r in reasons:
            html += f"<div style='color:#ff6b6b; margin-left:10px; font-weight:bold;'>&bull; {r}</div>"
        html += "</div>"

    html += "<div class='det-blk'><span class='det-title'>Loaded Libraries</span>"
    if node.libs:
        ls_html = []
        is_cont = (node.container_id is not None)
        for lib in sorted(node.libs):
            dstr = build_disk_string(lib, mounts, is_cont)
            safe_lib = lib
            if is_suspicious_lib(lib):
                safe_lib = f"<span style='color:var(--red);font-weight:bold'>{lib} <span class='tag t-unsafe'>[UNSAFE]</span></span>"
            ls_html.append(f"<div>{safe_lib} {dstr}</div>")

        libs_content = '\n'.join(ls_html)
        html += f"<div class='list-box'>{libs_content}</div>"
    else:
        html += "<span class='d-na'>N/A (No libs captured)</span>"
    html += "</div>"

    html += "<div class='det-blk'><span class='det-title'>Active Files</span>"
    if node.open_files:
        ls_files = []
        is_cont = (node.container_id is not None)
        for f in sorted(node.open_files):
            dstr = build_disk_string(f, mounts, is_cont)
            meta = ""
            if hasattr(node, 'file_metadata') and f in node.file_metadata:
                m_str = node.file_metadata[f]
                if m_str:
                    meta = f"<span style='color:#aaa;font-size:0.9em;margin-right:5px'>[{m_str}]</span>"

            ls_files.append(f"<div style='font-family:monospace; font-size:11px'>{f} {meta} {dstr}</div>")

        files_content = '\n'.join(ls_files)
        html += f"<div class='list-box'>{files_content}</div>"
    else:
        html += "<div class='d-na' style='margin-left:10px'>No file activity</div>"
    html += "</div>"
    return html


# ------------------------------------------------------------------------------
# HEADER RENDERERS
# ------------------------------------------------------------------------------
def render_os_block(os_data, hw_data):
    html = "<div class='kv-list'>"
    html += f"<div class='kv'><span class='kv-k'>Hostname</span><span class='kv-v'>{os_data.get('hostname')}</span></div>"
    html += f"<div class='kv'><span class='kv-k'>Kernel</span><span class='kv-v'>{os_data.get('kernel')}</span></div>"
    html += f"<div class='kv'><span class='kv-k'>Uptime</span><span class='kv-v'>{os_data.get('uptime')}</span></div>"
    html += f"<div class='kv'><span class='kv-k'>OS</span><span class='kv-v'>{os_data.get('os_pretty_name')}</span></div>"
    html += f"<div class='kv'><span class='kv-k'>CPU</span><span class='kv-v'>{hw_data.get('cpu')}</span></div>"
    html += f"<div class='kv'><span class='kv-k'>Memory</span><span class='kv-v'>{hw_data.get('mem_mb')} MB</span></div>"
    html += "</div>"
    return html


def render_net_block(net_data):
    # [v0.70 FEAT] Physical Hardware Alert
    phy_alert = ""
    if net_data.get('has_phy_issues'):
        errors = net_data.get('phy_errors', {})
        err_details = ", ".join([f"{k}:{v}" for k, v in errors.items()])
        phy_alert = f"<div class='phys-alert'>⚠️ HARDWARE NETWORK DROPS DETECTED: {err_details} (Check Cables/SFP)</div>"

    html = f"{phy_alert}<div class='kv-list'>"

    for iface in net_data.get('interfaces', []):
        html += f"<div class='kv'><span class='kv-k'>{iface['name']}</span><span class='kv-v'>{iface['ip']}</span></div>"
    gw = net_data.get('gateway', 'N/A')
    dns = ", ".join(net_data.get('dns', []))
    html += f"<div class='net-gw-dns'><div><b>GW:</b> {gw}</div><div><b>DNS:</b> {dns}</div></div>"
    html += "</div>"
    return html


def render_disk_block(storage_data):
    html = ""
    roots = storage_data.get('roots', [])

    def render_disk_recursive(children, level=0):
        block = ""
        for child in children:
            padding = level * 15
            name = child.get('name', 'disk')
            safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)

            if level == 0:
                size = child.get('size', '')
                model = child.get('model', 'HARDDISK')
                hctl = f"<span class='hctl-tag'>HCTL: {child.get('hctl')}</span>" if child.get('hctl') else ""
                block += f"<div class='disk-root'><div class='disk-header'><span id='db-{safe_name}' class='disk-icon' onclick='toggleDisk(\"{name}\")'>+</span><span>{name} ({size})</span><span style='font-weight:normal;color:#aaa'>{model}</span>{hctl}</div>"
                block += f"<div id='dd-{safe_name}' class='disk-details'>"
                if child.get('children'): block += render_disk_recursive(child['children'], level + 1)
                block += "</div></div>"
            else:
                fstype = child.get('fstype', 'part')
                size = child.get('size', '')
                mount = f"MNT:{child.get('mountpoint')}" if child.get('mountpoint') else ""
                uuid = f"UUID:{child.get('uuid')}" if child.get('uuid') else ""
                prefix = "&lfloor; " if level > 1 else ""
                block += f"<div class='disk-part' style='padding-left:{padding}px'>{prefix}<b>{name}</b> ({fstype}) <span class='disk-meta'>{mount} Size:{size} {uuid}</span></div>"
                if child.get('children'): block += render_disk_recursive(child['children'], level + 1)
        return block
    html = render_disk_recursive(roots)
    return html


# ------------------------------------------------------------------------------
# PROCESS ROW RENDERER
# ------------------------------------------------------------------------------
def render_process_rows(tree, mounts):
    rows_html = ""
    all_pids = set(tree.nodes.keys())

    roots = [n for pid, n in tree.nodes.items() if n.ppid not in all_pids]
    roots.sort(key=lambda x: x.pid)

    if not roots:
        return "<tr><td colspan='11' style='text-align:center; padding:20px; color:#777'>No process data captured. Check permissions or BPF status.</td></tr>"

    system_root = None
    kernel_root = None
    orphans = []

    for r in roots:
        if r.pid == 1: system_root = r
        elif r.pid == 2: kernel_root = r
        else: orphans.append(r)

    render_roots = []
    if system_root: render_roots.append(system_root)
    if kernel_root: render_roots.append(kernel_root)
    if not system_root: render_roots.extend(orphans)

    def walk(node, level, is_adopted=False):
        nonlocal rows_html

        children = [n for pid, n in tree.nodes.items() if n.ppid == node.pid]

        if node.pid == 1 and system_root:
            children.extend(orphans)

        children.sort(key=lambda x: x.pid)
        has_kids = len(children) > 0

        row_cls = "row proc-row"
        if level == 0: row_cls += " root"
        else:
            parent_id = 1 if is_adopted else node.ppid
            row_cls += f" hidden c-{parent_id}"

        if node.anomaly_score > 0: row_cls += " warn"

        indent = f"<span style='padding-left:{level*25}px;border-left:1px solid #444'></span>"
        exp_id = f"b-{node.pid}"

        if has_kids:
            expander = f"<span id='{exp_id}' class='exp' onclick='event.stopPropagation();toggleBranch({node.pid})'>+</span>"
        else:
            expander = ""
            if level > 0: expander = "|-- <span class='exp' onclick='event.stopPropagation();toggleBranch({node.pid})'>&bull;</span>"
            elif level == 0: expander = "<span class='exp' onclick='event.stopPropagation()'>&bull;</span>"

        pid_style = "color:#569cd6"
        cmd_style = ""
        if is_adopted:
            pid_style = "color:#88aaff; font-style:italic"
            cmd_style = "font-style:italic; color:#bbb"

        cpu_style = "cpu-hi" if node.cpu_usage_pct > 50 else ""

        io_hot_display = ""
        if node.tree_read_delta > 0 or node.tree_write_delta > 0:
            r_str = format_bytes(node.tree_read_delta)
            w_str = format_bytes(node.tree_write_delta)
            io_hot_display = f"<span class='io-r'>R:{r_str}</span><br><span class='io-w'>W:{w_str}</span>"
            if node.read_bytes_delta > 0:
                io_hot_display += f"<br><span style='font-size:9px;color:#777'>(Own:{format_bytes(node.read_bytes_delta)})</span>"
        else: io_hot_display = "<span class='d-na'>-</span>"

        tree_io = f"R:{format_bytes(node.tree_read)}<br>W:{format_bytes(node.tree_write)}"
        tree_io_html = f"<span style='color:#888;font-size:10px'>{tree_io}</span>"

        net_tx = format_bytes(node.net_tx_bytes)
        if node.tree_net_tx > 0: net_tx += f"<br><span class='net-agg'>&Sigma; {format_bytes(node.tree_net_tx)}</span>"

        net_rx = format_bytes(node.net_rx_bytes)
        if node.tree_net_rx > 0: net_rx += f"<br><span class='net-agg'>&Sigma; {format_bytes(node.tree_net_rx)}</span>"

        alerts_html = _render_badges(node, tree)

        total_io = node.tree_read + node.tree_write
        own_net_total = node.net_tx_bytes + node.net_rx_bytes
        nice_val = getattr(node, 'nice', 0)
        prio_color = "var(--red)" if nice_val < 0 else "var(--grn)"

        data_attrs = f'data-pid="{node.pid}" data-prio="{-nice_val}" data-cpu="{node.cpu_usage_pct}" data-mem="{node.rss}" data-io="{total_io}" data-net="{own_net_total}"'

        rows_html += f"""<tr class="{row_cls}" {data_attrs} onclick="toggleDet({node.pid})">
            <td width="20%" style="{cmd_style}">{indent}{expander} {node.cmd}</td>
            <td width="60" style="{pid_style}">{node.pid}</td>
            <td width="90">{getattr(node, 'duration_str', 'N/A')}</td>
            <td width="90">{node.username}</td>
            <td width="50" style="color:{prio_color}">{nice_val}</td>
            <td width="60" class="{cpu_style}">{node.cpu_usage_pct:.1f}%</td>
            <td width="80">{format_bytes(node.rss)}</td>
            <td width="100">{io_hot_display}</td>
            <td width="100">{tree_io_html}</td>
            <td width="90">{net_tx}</td>
            <td width="90">{net_rx}</td>
            <td>{alerts_html}</td>
        </tr>"""

        det_content = _get_details_html(node, mounts)
        rows_html += f"""<tr id="d-{node.pid}" class="det-row"><td colspan="12" class="det-cell">{det_content}</td></tr>"""

        for child in children:
            child_is_adopted = (node.pid == 1) and (child in orphans)
            walk(child, level + 1, is_adopted=child_is_adopted)

    for root in render_roots:
        walk(root, 0, is_adopted=False)

    return rows_html


# ------------------------------------------------------------------------------
# ENTRY POINTS
# ------------------------------------------------------------------------------
def generate_report(inventory, process_tree, output_file, version):
    """Full Static HTML Generator."""
    try:
        os_c = render_os_block(inventory['os'], inventory['hw'])
        net_c = render_net_block(inventory['net'])
        disk_c = render_disk_block(inventory['storage'])
        mounts = inventory['storage'].get('mounts', {})
        rows = render_process_rows(process_tree, mounts)

        html = HTML_TEMPLATE.format(
            VERSION=version,
            HOSTNAME=inventory['os']['hostname'],
            TIMESTAMP=inventory['generated'],
            CSS_BLOCK=CSS_BASE,
            JS_BLOCK=JS_BLOCK + "\n    // Auto-start check handled by main.py injection or manual call",
            LEGEND_HTML=LEGEND_HTML,
            OS_CONTENT=os_c,
            DISK_CONTENT=disk_c,
            NET_CONTENT=net_c,
            TABLE_ROWS=rows
        )
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        return False


def generate_table_fragment(inventory, process_tree):
    """Generates ONLY the <tbody> rows (For Live Mode AJAX)."""
    try:
        mounts = inventory['storage'].get('mounts', {})
        return render_process_rows(process_tree, mounts)
    except Exception:
        return ""
