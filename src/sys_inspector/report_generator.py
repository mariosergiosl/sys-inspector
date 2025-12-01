# -*- coding: utf-8 -*-
# FILE: src/sys_inspector/report_generator.py
# DESCRIPTION: Generates HTML reports. Fixed Layout.

import pwd

# pylint: disable=line-too-long
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
    :root { --bg:#121212; --fg:#e0e0e0; --acc:#0078d4; --red:#ff6b6b; --grn:#51cf66; --yel:#fcc419; --gry:#777; --drk:#1e1e1e; --border:#333; }
    body { font-family:'Segoe UI', 'Roboto', monospace; background:var(--bg); color:var(--fg); padding:20px; font-size:13px; margin:0; }

    /* --- STICKY HEADER --- */
    .sticky-wrapper {
        position: sticky; top: 0; z-index: 1000;
        background-color: var(--bg);
        padding: 10px 20px 0 20px;
        border-bottom: 1px solid var(--acc);
        box-shadow: 0 5px 15px rgba(0,0,0,0.5);
    }

    .hdr { display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; }
    .title h1 { margin:0; font-weight:300; font-size:26px; color:var(--acc); letter-spacing:-0.5px; }
    .subtitle { color:var(--gry); font-size:0.85em; text-transform:uppercase; letter-spacing:2px; margin-top:4px; font-weight:bold; }
    .meta { text-align:right; color:#888; font-size:0.9em; }

    /* INVENTORY GRID (Fixed Spacing) */
    .inv { display:grid; grid-template-columns:repeat(auto-fit,minmax(400px,1fr)); gap:20px; margin-bottom:15px; }
    .card { background:var(--drk); border:1px solid #444; padding:12px; border-radius:4px; }
    .card h3 { margin:0 0 10px 0; border-bottom:1px solid #444; color:var(--acc); font-size:11px; text-transform:uppercase; }

    /* KV PAIRS - GRID LAYOUT (Prevents glueing) */
    .kv-list { display:flex; flex-direction:column; gap:5px; }
    .kv {
        display: grid;
        grid-template-columns: 140px 1fr; /* Label fixed width */
        align-items: baseline;
        border-bottom: 1px solid #2a2a2a;
        padding-bottom: 2px;
    }
    .kv-k { color:var(--gry); font-weight:normal; }
    .kv-v { font-weight:600; color:#ddd; word-break:break-all; }

    /* CONTROLS */
    .controls { display:flex; gap:15px; align-items:center; margin-bottom:10px; flex-wrap:wrap; }
    .legend { display:flex; gap:15px; background:#222; padding:8px; border:1px solid #444; border-radius:3px; align-items:center; }
    .leg-item { display:flex; align-items:center; gap:5px; font-size:11px; color:#aaa; }
    .dot { width:8px; height:8px; border-radius:50%; }
    .bar { height:6px; width:60px; border-radius:2px; display:inline-block; margin-right:5px; }
    .grad-prio { background: linear-gradient(to right, var(--grn), var(--acc), var(--red)); }
    .grad-cpu { background: linear-gradient(to right, #333, var(--acc), var(--red)); }

    #search { flex-grow:1; padding:8px; background:#252526; border:1px solid #555; color:white; border-radius:3px; font-family:monospace; }

    /* TABLE HEADER (Inside Sticky) */
    .tbl-hdr { display:flex; border-bottom:2px solid #444; font-weight:bold; color:#aaa; text-transform:uppercase; padding:5px 0; font-size:11px; }

    /* MAIN TABLE */
    .table-container { padding: 0 20px 20px 20px; }
    table { width:100%; border-collapse:collapse; font-size:12px; table-layout:fixed; }
    td { padding:6px 5px; border-bottom:1px solid #2a2a2a; vertical-align:middle; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

    /* ROW STYLES */
    .row:hover { background:#2a2d2e; cursor:pointer; }
    .row.warn { background:rgba(244,135,113,0.08); border-left:3px solid var(--red); }
    .exp { color:var(--acc); font-weight:bold; display:inline-block; width:20px; text-align:center; }
    .hidden { display:none; }

    /* DETAILS ROW (The Critical Fix) */
    tr.det-row { display:none; }
    tr.det-row.show { display:table-row; } /* Must be table-row */

    .det-cell { background:#151515; border-left:3px solid var(--acc); padding:20px; white-space:normal; overflow:visible; }

    /* DETAILS CONTENT BLOCKS */
    .det-blk { margin-bottom:20px; border-bottom:1px solid #333; padding-bottom:10px; }
    .det-title { color:var(--acc); font-weight:bold; margin-bottom:8px; display:block; font-size:1.1em; border-bottom:1px solid #444; padding-bottom:2px; }

    /* CONTEXT TABLE */
    .ctx-tbl { width:100%; border-spacing:0; margin-bottom:15px; }
    .ctx-lbl { color:#666; width:160px; vertical-align:top; padding:2px 0; }
    .ctx-val { color:#ccc; padding:2px 0; font-family:'Consolas',monospace; }

    /* VISUALS */
    .hctl { color:var(--cyn); font-weight:bold; background:rgba(78, 201, 176, 0.1); padding:0 3px; border-radius:2px; }
    .disk-str { color:#888; font-size:0.9em; margin-left:8px; }
    .d-na { opacity:0.4; font-style:italic; }
    .t-ssh { border:1px solid var(--yel); color:var(--yel); padding:0 3px; border-radius:2px; font-size:0.8em; }
    .t-sudo { border:1px solid var(--red); color:var(--red); padding:0 3px; border-radius:2px; font-size:0.8em; }
    .t-new { background:var(--grn); color:#000; padding:0 3px; border-radius:2px; font-weight:bold; font-size:0.8em; margin-right:6px; }
    .t-bad-lib { background:var(--red); color:#000; padding:0 3px; border-radius:2px; font-weight:bold; font-size:0.7em; margin-left:5px; }
    .io-r { color:var(--grn); } .io-w { color:var(--red); }
    .cpu-hi { color:var(--red); font-weight:bold; }
    .mem-hi { color:var(--yel); } .mem-crit { color:var(--red); font-weight:bold; }

    /* LIST BOXES */
    .list-box { max-height:150px; overflow-y:auto; background:#1a1a1a; padding:5px; border:1px solid #333; font-family:'Consolas',monospace; color:#bbb; }
</style>
<script>
    function toggleBranch(pid) {
        var btn = document.getElementById('b-'+pid);
        var closed = btn.innerText === '+';
        btn.innerText = closed ? '-' : '+';
        document.querySelectorAll('.c-'+pid).forEach(r => {
            if(closed) r.classList.remove('hidden');
            else {
                r.classList.add('hidden');
                var sub = document.getElementById('b-'+r.dataset.pid);
                if(sub && sub.innerText==='-') toggleBranch(r.dataset.pid);
                // Hide details if open
                var d = document.getElementById('d-'+r.dataset.pid);
                if(d) d.classList.remove('show');
            }
        });
    }
    function toggleDet(pid) { document.getElementById('d-'+pid).classList.toggle('show'); }
    function filterTable() {
        var v = document.getElementById("search").value.toUpperCase();
        document.querySelectorAll(".proc-row").forEach(r => {
            r.style.display = r.innerText.toUpperCase().indexOf(v) > -1 ? "" : "none";
        });
    }
</script>
</head>
<body>
    <div class="sticky-wrapper">
        <div class="hdr">
            <div>
                <div class="title"><h1>Sys-Inspector<span>v{VERSION}</span></h1></div>
                <div class="subtitle">Enterprise Forensic Report</div>
            </div>
            <div class="meta">{DATE}<br>{HOST}</div>
        </div>

        <div class="inv">
            <div class="card"><h3>System</h3><div class="kv-list">{OS_INFO}</div></div>
            <div class="card"><h3>Storage Topology</h3><div class="kv-list">{DISK_INFO}</div></div>
            <div class="card"><h3>Network Interfaces</h3><div class="kv-list">{NET_INFO}</div></div>
        </div>

        <div class="controls">
            <div class="legend">
                <div class="leg-item"><span class="leg-lbl">Priority</span> <div class="bar grad-prio"></div></div>
                <div class="leg-item"><span class="leg-lbl">CPU %</span> <div class="bar grad-cpu"></div></div>
                <div class="leg-item"><div class="dot" style="background:var(--yel)"></div>Remote</div>
                <div class="leg-item"><span class="t-new">NEW</span> Created</div>
                <div class="leg-item"><span class="hctl">HCTL</span> Zoning</div>
                <div class="leg-item" style="color:var(--red);font-weight:bold">[UNSAFE]</div> Suspicious Library
            </div>
            <input type="text" id="search" placeholder="Filter processes, files, connections..." onkeyup="filterTable()">
        </div>

        <div class="tbl-hdr">
             <div style="width:45%">Command Tree</div>
             <div style="width:60px">PID</div>
             <div style="width:100px">User</div>
             <div style="width:60px">Nice</div>
             <div style="width:70px">CPU%</div>
             <div style="width:90px">RSS</div>
             <div style="width:150px">I/O (Window)</div>
             <div>Context</div>
        </div>
    </div>

    <div class="table-container">
        <table>
            <colgroup>
                <col width="45%">
                <col width="60px">
                <col width="100px">
                <col width="60px">
                <col width="70px">
                <col width="90px">
                <col width="150px">
                <col>
            </colgroup>
            <tbody style="margin-top:10px">{ROWS}</tbody>
        </table>
    </div>
</body>
</html>"""
# pylint: enable=line-too-long


def build_disk_string(path, mount_map):
    """
    Maps a file path to its underlying disk device info (UUID, HCTL).
    """
    best = ""
    info = None
    for mp, d in mount_map.items():
        if path.startswith(mp) and len(mp) > len(best):
            best = mp
            info = d

    if info:
        parts = []
        parts.append(f"FS:{info.get('fstype','N/A')}")
        parts.append(f"DEV:/dev/{info.get('name','N/A')}")
        parts.append(f"UUID:{info.get('uuid','N/A')}")

        hctl = info.get('hctl') or "N/A"
        parts.append(f"<span class='hctl'>HCTL:{hctl}</span>")

        base = " ".join(parts)
        path_str = ""
        if info.get('paths'):
            path_str = f"PATH:{info['paths'][0]}"

        return f"<span class='disk-str'>({base} {path_str})</span>"
    return "<span class='disk-str'>(Pseudo/Virtual/N/A)</span>"


def is_suspicious_lib(libpath):
    """Forensic check for library paths."""
    bad_prefixes = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")
    if libpath.startswith(bad_prefixes) or "(deleted)" in libpath:
        return True
    return False


def render_row(node, level, mounts):
    """Renders a single table row and its hidden detail pane."""
    indent = f"<span style='padding-left:{level*25}px;border-left:1px solid #444'></span>"
    if level > 0:
        indent += "|-- "

    badge = "<span class='t-new'>NEW</span> " if node.is_new else ""
    cmd = node.cmd if len(node.cmd) < 80 else node.cmd[:80] + "..."
    expander = f"<span id='b-{node.pid}' class='exp' onclick='event.stopPropagation();toggleBranch({node.pid})'>{'-' if node.has_kids else '&bull;'}</span>"

    alerts = []
    if "[SSH:" in node.context:
        alerts.append("<span class='t-ssh'>SSH</span>")
    if "[SUDO:" in node.context:
        alerts.append("<span class='t-sudo'>SUDO</span>")
    if node.anomaly_score > 0:
        alerts.append(f"<b style='color:var(--red)'>WARN:{node.anomaly_score}</b>")
    alert_html = " ".join(alerts)

    # --- DETAILS PANE ---
    det_html = ""

    # 1. METADATA (Grid)
    det_html += "<div class='det-blk'><span class='det-title'>Metadata & Context</span>"
    det_html += "<table class='ctx-tbl'>"
    det_html += f"<tr><td class='ctx-lbl'>Full Command:</td><td class='ctx-val'>{node.cmd}</td></tr>"
    det_html += f"<tr><td class='ctx-lbl'>Executable MD5:</td><td class='ctx-val'>{node.md5 or 'N/A'}</td></tr>"
    det_html += f"<tr><td class='ctx-lbl'>User/UID:</td><td class='ctx-val'>{get_username(node.uid)} ({node.uid})</td></tr>"

    sudo_v = node.context.split("[SUDO:")[1].split("]")[0] if "[SUDO:" in node.context else "<span class='d-na'>No (Direct)</span>"
    ssh_v = node.context.split("[SSH:")[1].split("]")[0] if "[SSH:" in node.context else "<span class='d-na'>N/A (Local)</span>"

    det_html += f"<tr><td class='ctx-lbl'>Sudo Origin:</td><td class='ctx-val'>{sudo_v}</td></tr>"
    det_html += f"<tr><td class='ctx-lbl'>SSH Origin:</td><td class='ctx-val'>{ssh_v}</td></tr>"
    det_html += f"<tr><td class='ctx-lbl'>Security Context:</td><td class='ctx-val'>{node.sec_ctx or 'unconfined'}</td></tr>"

    susp_val = f"<span style='color:var(--red);font-weight:bold'>{', '.join(node.suspicious_env)}</span>" if node.suspicious_env else "<span class='d-na'>N/A (Clean)</span>"
    det_html += f"<tr><td class='ctx-lbl'>Suspicious Env:</td><td class='ctx-val'>{susp_val}</td></tr>"

    io_life = f"R: {node.read_bytes_total/1024/1024:.2f} MB | W: {node.write_bytes_total/1024/1024:.2f} MB"
    det_html += f"<tr><td class='ctx-lbl'>Lifetime I/O:</td><td class='ctx-val'>{io_life}</td></tr></table></div>"

    # 2. LIBRARIES (Stacked, Full Width)
    det_html += "<div class='det-blk'><span class='det-title'>Loaded Libraries</span>"
    if node.libs:
        lib_lines = []
        for lib in sorted(node.libs):
            if is_suspicious_lib(lib):
                lib_lines.append(f"<span style='color:var(--red);font-weight:bold'>{lib} <span class='t-bad-lib'>[UNSAFE]</span></span>")
            else:
                lib_lines.append(lib)
        det_html += f"<div class='list-box'>{'<br>'.join(lib_lines)}</div>"
    else:
        det_html += "<span class='d-na'>N/A (Static Binary or Access Denied)</span>"
    det_html += "</div>"

    # 3. FILES (Stacked, Full Width)
    det_html += "<div class='det-blk'><span class='det-title'>Active Files (Capture Window)</span>"
    if node.open_files:
        for f in sorted(node.open_files):
            dstr = build_disk_string(f, mounts)
            det_html += f"<div style='font-family:monospace;margin-left:10px'>{f} {dstr}</div>"
    else:
        det_html += "<span class='d-na'>No file activity captured</span>"
    det_html += "</div>"

    # 4. NETWORK (Stacked, Full Width)
    det_html += "<div class='det-blk'><span class='det-title'>Network Connections</span>"
    if node.connections:
        for c in node.connections:
            det_html += f"<div style='font-family:monospace;margin-left:10px'>{c}</div>"
    else:
        det_html += "<span class='d-na'>No active connections detected</span>"
    det_html += "</div>"

    # ROW BUILDING
    row_cls = "row proc-row"
    if node.anomaly_score > 0:
        row_cls += " warn"
    rss = f"{node.rss/1024/1024:.1f} MB"
    cpu_v = node.cpu_usage_pct
    cpu_cls = "cpu-hi" if cpu_v > 50 else ""
    nice_cls = "color:var(--red)" if (node.prio - 120) < 0 else "color:var(--grn)"

    io_str = ""
    if node.write_bytes_delta > 0:
        io_str = f"<span class='io-w'>W: {node.write_bytes_delta}</span>"
    elif node.read_bytes_delta > 0:
        io_str = f"<span class='io-r'>R: {node.read_bytes_delta}</span>"

    # Return Main Row + Hidden Details Row
    return f"""
    <tr class="{row_cls}" data-pid="{node.pid}" onclick="toggleDet({node.pid})">
        <td width="45%">{indent}{expander} {badge}{cmd}</td>
        <td width="60" style="color:#569cd6">{node.pid}</td>
        <td width="100">{get_username(node.uid)}</td>
        <td width="60" style="{nice_cls}">{node.prio-120}</td>
        <td width="70" class="{cpu_cls}">{cpu_v:.1f}%</td>
        <td width="90">{rss}</td>
        <td width="150">{io_str}</td>
        <td>{alert_html}</td>
    </tr>
    <tr id="d-{node.pid}" class="det-row">
        <td colspan="8" class="det-cell">{det_html}</td>
    </tr>
    """


def get_username(uid):
    """Resolves UID to username safely."""
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def generate_html(inv, tree, outfile, version):
    """Orchestrates HTML generation."""
    # Prepare Inventory HTML (Fixed Grid)
    os_info = ""
    for k, v in inv['os'].items():
        os_info += f"<div class='kv'><span class='kv-k'>{k.title()}</span><span class='kv-v'>{v}</span></div>"
    os_info += f"<div class='kv'><span class='kv-k'>CPU</span><span class='kv-v'>{inv['hw']['cpu']}</span></div>"
    os_info += f"<div class='kv'><span class='kv-k'>Memory</span><span class='kv-v'>{inv['hw']['mem_mb']} MB</span></div>"

    disk_info = ""
    for d in inv['storage']['devices']:
        if d['type'] == 'disk':
            hctl = d.get('hctl') or "N/A"
            disk_info += f"<div class='kv'><span class='kv-k'>{d['name']} ({d['size']})</span><span class='kv-v'>{d.get('model','')} <span class='hctl'>{hctl}</span></span></div>"

    net_info = ""
    for n in inv['net']:
        if ":" in n:
            parts = n.split(":", 1)
            k, v = parts[0], parts[1]
        else:
            k, v = "Inf", n
        net_info += f"<div class='kv'><span class='kv-k'>{k}</span><span class='kv-v'>{v}</span></div>"

    rows = ""

    def walk(pid, lvl):
        nonlocal rows
        if pid not in tree:
            return
        node = tree[pid]
        kids = sorted([p for p in tree.values() if p.ppid == pid], key=lambda x: x.pid)
        node.has_kids = len(kids) > 0

        r = render_row(node, lvl, inv['storage']['mounts'])
        if node.ppid:
            r = r.replace('class="row', f'class="row c-{node.ppid}')
        else:
            r = r.replace('class="row', 'class="row root')

        rows += r
        for k in kids:
            walk(k.pid, lvl + 1)

    roots = [p.pid for p in tree.values() if p.ppid not in tree and p.pid > 0]
    for r in sorted(roots):
        walk(r, 0)

    html = HTML_TEMPLATE.replace("{DATE}", inv['generated']) \
        .replace("{HOST}", inv['os']['hostname']) \
        .replace("{OS_INFO}", os_info) \
        .replace("{DISK_INFO}", disk_info) \
        .replace("{NET_INFO}", net_info) \
        .replace("{ROWS}", rows) \
        .replace("{VERSION}", version)

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)
    return outfile
