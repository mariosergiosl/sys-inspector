# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/sys_inspector/report_generator.py
# DESCRIPTION: Generates HTML reports. v0.30.3
# VERSION: 0.30.5
# ===============================================================================

import pwd

# pylint: disable=line-too-long
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
    :root { --bg:#121212; --fg:#e0e0e0; --acc:#0078d4; --red:#ff6b6b; --grn:#51cf66; --yel:#fcc419; --gry:#777; --drk:#252526; --border:#333; }
    body { font-family:'Segoe UI', 'Roboto', monospace; background:var(--bg); color:var(--fg); padding:20px; font-size:13px; margin:0; }

    /* HEADER & STICKY */
    .sticky-wrapper {
        position: sticky; top: 0; z-index: 1000;
        background-color: var(--bg);
        padding: 10px 20px 0 20px;
        border-bottom: 1px solid var(--acc);
        box-shadow: 0 5px 15px rgba(0,0,0,0.5);
    }
    .hdr { display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; }
    .logo-area { display:flex; align-items:center; gap:15px; }
    .client-logo { max-height: 40px; width: auto; border-radius:4px; }

    .title h1 { margin:0; font-weight:300; font-size:26px; color:var(--acc); letter-spacing:-0.5px; }
    .title span { font-size:0.6em; color:#666; margin-left:10px; }
    .subtitle { color:var(--gry); font-size:0.85em; text-transform:uppercase; letter-spacing:2px; margin-top:4px; font-weight:bold; }
    .meta { text-align:right; color:#888; font-size:0.9em; }

    .inv { display:grid; grid-template-columns:repeat(auto-fit,minmax(380px,1fr)); gap:15px; margin-bottom:15px; }
    .card { background:var(--drk); border:1px solid #444; padding:12px; border-radius:4px; display:flex; flex-direction:column; }
    .card h3 { margin:0 0 10px 0; border-bottom:1px solid #444; color:var(--acc); font-size:11px; text-transform:uppercase; display:flex; justify-content:space-between; align-items:center; }
    .kv { display:grid; grid-template-columns: 140px 1fr; gap:10px; border-bottom:1px solid #2a2a2a; padding-bottom:2px; align-items:baseline; }
    .kv:last-child { border-bottom: none; }
    .kv-k { color:var(--gry); font-weight:normal; } .kv-v { font-weight:600; color:#ddd; word-break:break-all; }

    /* STORAGE SPECIFIC */
    .disk-root { margin-bottom: 5px; border-bottom: 1px solid #333; padding-bottom: 5px; }
    .disk-header { display: flex; align-items: center; gap: 10px; font-weight: bold; }
    .disk-icon { color: var(--acc); cursor: pointer; font-family: monospace; font-size: 14px; border: 1px solid #444; width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; border-radius: 3px; background: #333; }
    .disk-details { display: none; margin-left: 20px; margin-top: 5px; border-left: 1px solid #444; padding-left: 10px; font-size: 0.9em; color: #bbb; }
    .disk-details.show { display: block; }
    .disk-part { margin-top: 3px; }
    .disk-meta { font-size: 0.85em; color: #777; margin-left: 5px; }
    .hctl-tag { background: #333; color: var(--cyn); padding: 1px 4px; border-radius: 2px; font-size: 0.85em; border: 1px solid #444; }
    .btn-print-disk { cursor: pointer; font-size: 10px; padding: 1px 5px; border: 1px solid #555; border-radius: 3px; background: #222; color: #aaa; }
    .btn-print-disk:hover { background: var(--acc); color: white; border-color: var(--acc); }

    /* NETWORK SPECIFIC */
    .net-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 5px; font-size: 0.95em; margin-bottom: 5px; }
    .net-iface { font-weight: bold; color: var(--acc); }
    .net-gw-dns { margin-top: 8px; border-top: 1px dashed #444; padding-top: 4px; font-size: 0.9em; color: #888; }

    /* CONTROLS */
    .controls { display:flex; flex-direction: column; gap:10px; margin-bottom:15px; width: 100%; }

    .legend {
        display:flex; gap:15px; background:#222; padding:8px 12px;
        border:1px solid #444; border-radius:3px; align-items:center;
        flex-wrap:wrap; width: 100%; box-sizing: border-box;
    }
    .leg-grp { display:flex; align-items:center; gap:10px; padding-right:15px; border-right:1px solid #444; }
    .leg-grp:last-child { border:none; }
    .leg-lbl { font-weight:bold; color:#aaa; font-size:11px; text-transform:uppercase; }

    /* BADGES */
    .tag { display:inline-block; padding:2px 6px; border-radius:3px; font-weight:bold; margin-right:4px; cursor:pointer; font-size:10px; border:1px solid transparent; }
    .tag:hover { filter:brightness(1.2); }
    .t-new { background:var(--grn); color:#000; border-color:var(--grn); }
    .t-ssh { color:var(--yel); border-color:var(--yel); background:rgba(252, 196, 25, 0.1); }
    .t-sudo { color:var(--red); border-color:var(--red); background:rgba(255, 107, 107, 0.1); }
    .t-warn { color:var(--red); border-color:var(--red); background:rgba(255, 107, 107, 0.15); }
    .t-err, .t-unsafe { background:var(--red); color:#000; border-color:var(--red); }

    .btn-clear { cursor:pointer; padding:2px 6px; border-radius:3px; border:1px solid #555; font-size:10px; font-weight:bold; color:#aaa; background:#333; }

    /* ACTION BUTTONS */
    .btn-act { cursor:pointer; padding:3px 8px; border-radius:3px; border:1px solid #555; font-size:11px; font-weight:bold; color:#ddd; background:#2a2a2a; transition:0.2s; margin-right:5px; }
    .btn-act:hover { background:#444; border-color:var(--acc); }

    @keyframes blink { 50% { opacity: 0.5; } }
    .btn-alert { background:transparent; border:1px solid var(--red); color:var(--red); }
    .btn-alert.blinking { background:var(--red); color:#000; animation: blink 1s infinite; border:none; }

    /* VISUALS */
    .bar { height:6px; width:60px; border-radius:2px; display:inline-block; margin-right:5px; }
    .grad-prio { background: linear-gradient(to right, var(--grn), var(--acc), var(--red)); }
    .grad-cpu { background: linear-gradient(to right, #333, var(--acc), var(--red)); }

    #search { width:100%; padding:8px; background:#252526; border:1px solid #555; color:white; border-radius:3px; font-family:monospace; box-sizing:border-box; }

    /* TABLE */
    .table-container { padding: 0 20px 20px 20px; }
    table { width:100%; border-collapse:collapse; font-size:12px; table-layout:fixed; }
    th { text-align:left; background:#2d2d30; padding:10px 5px; border-bottom:2px solid #444; color:#aaa; text-transform:uppercase; font-size:11px; }
    td { padding:6px 5px; border-bottom:1px solid #2a2a2a; vertical-align:middle; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

    .row:hover { background:#2a2d2e; cursor:pointer; }
    .row.warn { background:rgba(244,135,113,0.08); border-left:3px solid var(--red); }
    .exp { color:var(--acc); font-weight:bold; display:inline-block; width:16px; height:16px; line-height:14px; text-align:center; background:#333; border:1px solid #555; border-radius:3px; cursor:pointer; }

    .hidden { display:none; }
    tr.det-row { display:none; } tr.det-row.show { display:table-row; }
    .det-cell { background:#151515; border-left:3px solid var(--acc); padding:20px; white-space:normal; }

    .det-blk { margin-bottom:15px; border-bottom:1px solid #333; padding-bottom:10px; }
    .det-title { color:var(--acc); font-weight:bold; margin-bottom:8px; display:block; font-size:1.1em; border-bottom:1px solid #444; padding-bottom:2px; }
    .ctx-tbl { width:100%; border-spacing:0; }
    .ctx-lbl { color:#666; width:150px; vertical-align:top; } .ctx-val { color:#ccc; font-family:'Consolas',monospace; }

    .hctl { color:var(--cyn); font-weight:bold; background:rgba(78, 201, 176, 0.1); padding:0 3px; border-radius:2px; }
    .disk-str { color:#888; font-size:0.9em; margin-left:10px; }
    .d-na { opacity:0.4; font-style:italic; }
    .io-r { color:var(--grn); } .io-w { color:var(--red); }
    .io-agg { color:#777; font-size:10px; display:block; margin-top:2px; }
    .net-agg { color:#777; font-size:9px; display:block; margin-top:2px; }
    .cpu-hi { color:var(--red); font-weight:bold; }
    .alert-icon { font-size:14px; color:var(--yel); font-weight:bold; margin-left:5px; cursor:help; }
    .lib-list { max-height:150px; overflow-y:auto; background:#1a1a1a; padding:5px; border:1px solid #333; color:#bbb; }

    @media print {
        body { background:#fff; color:#000; }
        .sticky-wrapper { position:static; border:none; box-shadow:none; }
        .controls, .exp { display:none !important; }
        .card, table, th, td { border:1px solid #ccc; color:#000; }
        .row, .hidden { display:table-row !important; }
        .tag { border:1px solid #000; color:#000 !important; background:none !important; }
        .disk-details { display: block !important; } /* Expand all disks on print */
        .btn-print-disk { display: none; }
    }
</style>
<script>
    function toggleBranch(pid) {
        var btn = document.getElementById('b-'+pid);
        if(btn.classList.contains('disabled')) return;
        var closed = btn.innerText === '+';
        btn.innerText = closed ? '-' : '+';
        document.querySelectorAll('.c-'+pid).forEach(r => {
            if(closed) r.classList.remove('hidden');
            else {
                r.classList.add('hidden');
                var sub = document.getElementById('b-'+r.dataset.pid);
                if(sub && sub.innerText==='-') toggleBranch(r.dataset.pid);
                document.getElementById('d-'+r.dataset.pid)?.classList.remove('show');
            }
        });
    }

    function toggleDet(pid) { document.getElementById('d-'+pid).classList.toggle('show'); }

    function toggleDisk(name) {
        var el = document.getElementById('dd-'+name);
        var btn = document.getElementById('db-'+name);
        if(el.classList.contains('show')) {
            el.classList.remove('show');
            btn.innerText = '+';
        } else {
            el.classList.add('show');
            btn.innerText = '-';
        }
    }

    function printStorage() {
        var content = document.getElementById('storage-card').innerHTML;
        var win = window.open('', '', 'height=600,width=800');
        win.document.write('<html><head><title>Storage Topology</title>');
        win.document.write('<style>body{font-family:monospace;color:black;} .disk-details{display:block !important; margin-left:20px;} .disk-header{font-weight:bold; margin-top:10px;} .disk-icon, .btn-print-disk{display:none;} .disk-part{margin-left:20px;}</style>');
        win.document.write('</head><body>');
        win.document.write('<h1>Storage Topology</h1>');
        win.document.write(content);
        win.document.write('</body></html>');
        win.document.close();
        win.print();
    }

    function filterTable() {
        var v = document.getElementById("search").value.toUpperCase();
        var isFiltering = v !== "";
        document.querySelectorAll(".proc-row").forEach(r => {
            var txt = r.innerText.toUpperCase();
            var match = txt.indexOf(v) > -1;
            var btn = document.getElementById('b-'+r.dataset.pid);
            if(isFiltering) {
                if(btn) btn.classList.add('disabled');
                if(match) { r.style.display=""; r.classList.remove('hidden'); }
                else r.style.display="none";
            } else {
                if(btn) btn.classList.remove('disabled');
                r.style.display="";
                if(r.classList.contains('root')) r.classList.remove('hidden');
                else r.classList.add('hidden');
                if(btn) btn.innerText='+';
            }
        });
        if(isFiltering) document.querySelectorAll('.det-row').forEach(d => d.classList.remove('show'));
    }
    function setFilter(val) { document.getElementById("search").value = val; filterTable(); }

    function filterSecurity() {
        setFilter("WARN");
    }

    function sortView(metric) {
        var tbody = document.querySelector("tbody");
        var rows = Array.from(document.querySelectorAll(".proc-row"));
        rows.sort((a, b) => {
            var va = parseFloat(a.dataset[metric] || 0);
            var vb = parseFloat(b.dataset[metric] || 0);
            return vb - va;
        });
        rows.forEach(r => {
            r.classList.remove('hidden'); r.style.display="";
            var btn=document.getElementById('b-'+r.dataset.pid);
            if(btn){btn.innerText='';btn.classList.add('disabled');}
            tbody.appendChild(r);
            tbody.appendChild(document.getElementById('d-'+r.dataset.pid));
        });
    }
</script>
</head>
<body>
    <div class="sticky-wrapper">
        <div class="hdr">
            <div class="logo-area">
                {LOGO_HTML}
                <div>
                    <div class="title"><h1>Sys-Inspector<span>v{VERSION}</span></h1></div>
                    <div class="subtitle">Enterprise Forensic Report</div>
                </div>
            </div>
            <div class="meta">{DATE}<br>{HOST}</div>
        </div>

        <div class="inv">
            <div class="card"><h3>System</h3><div class="kv-list">{OS_INFO}</div></div>
            <div class="card" id="storage-card">
                <h3>Storage Topology <span class="btn-print-disk" onclick="printStorage()">Print</span></h3>
                <div style="overflow-y:auto; max-height:200px;">{DISK_INFO}</div>
            </div>
            <div class="card"><h3>Network Topology</h3><div class="kv-list">{NET_INFO}</div></div>
        </div>

        <div class="controls">
            <div class="legend">
                <div class="leg-grp">
                    <span class="leg-lbl">Priority</span> <div class="bar grad-prio"></div>
                </div>
                <div class="leg-grp">
                    <span class="leg-lbl">CPU %</span> <div class="bar grad-cpu"></div>
                </div>

                <div class="leg-grp">
                    <span class="leg-lbl">Process By</span>
                    <span class="btn-act" onclick="location.reload()">🌳 Tree</span>
                    <span class="btn-act" onclick="sortView('cpu')">🔥 Top CPU</span>
                    <span class="btn-act" onclick="sortView('io')">💾 Top Disk</span>
                    <span class="btn-act" onclick="sortView('mem')">🧠 Top RAM</span>
                </div>

                <div class="leg-grp" style="border:none; margin-left:auto">
                    <span class="leg-lbl">Filters</span>
                    <span class="tag t-new" onclick="setFilter('NEW')">NEW</span>
                    <span class="tag t-ssh" onclick="setFilter('SSH')">REMOTE</span>
                    <span class="tag t-warn" onclick="setFilter('WARN')">WARN</span>
                    <span class="tag t-unsafe" onclick="setFilter('UNSAFE')">UNSAFE</span>
                    <span class="tag t-err" onclick="setFilter('NET ERR')">NET ERR</span>
                    <span class="btn-clear" onclick="setFilter('')">CLEAR</span>

                    <span class="btn-act btn-alert {BLINK_CLASS}" onclick="filterSecurity()" title="Show Security Alerts">⚠</span>
                    <span class="btn-act" onclick="window.print()" title="Save PDF">🖨️</span>
                </div>
            </div>
            <input type="text" id="search" placeholder="Filter processes (PID, User, Disk, Alert)..." onkeyup="filterTable()">
        </div>

        <div class="tbl-hdr" style="display:flex; border-bottom:2px solid #444; font-weight:bold; color:#aaa; text-transform:uppercase; padding:8px 5px; font-size:11px;">
             <div style="width:35%">Command Tree</div>
             <div style="width:60px">PID</div>
             <div style="width:90px">User</div>
             <div style="width:50px">Nice</div>
             <div style="width:60px">CPU%</div>
             <div style="width:80px">RSS</div>
             <div style="width:100px">Disk &Delta;<br>I/O Hot</div>
             <div style="width:100px">Disk &Sigma;<br>I/O Hist</div>
             <div style="width:90px">Net TX<br>&Delta; / &Sigma;</div>
             <div style="width:90px">Net RX<br>&Delta; / &Sigma;</div>
             <div>Alerts</div>
        </div>
    </div>

    <div class="table-container">
        <table>
            <colgroup>
                <col width="35%">
                <col width="60px"><col width="90px"><col width="50px"><col width="60px"><col width="80px">
                <col width="100px"><col width="100px"><col width="90px"><col width="90px"><col>
            </colgroup>
            <tbody style="margin-top:10px">{ROWS}</tbody>
        </table>
    </div>
</body>
</html>"""
# pylint: enable=line-too-long


def format_bytes(size):
    if size < 1024:
        return "0"
    for unit in ['K', 'M', 'G', 'T']:
        size /= 1024
        if size < 1024:
            return f"{size:.1f}{unit}"
    return f"{size:.1f}P"


def recursive_disk_html(children, level):
    html = ""
    for child in children:
        meta = []
        if child.get('fstype'):
            meta.append(f"FS:{child['fstype']}")
        if child.get('mountpoint'):
            meta.append(f"MNT:{child['mountpoint']}")
        if child.get('size'):
            meta.append(f"Size:{child['size']}")
        if child.get('uuid'):
            meta.append(f"UUID:{child['uuid']}")

        pad = level * 15
        icon = "&lfloor;" if level > 0 else ""

        html += f"<div class='disk-part' style='padding-left:{pad}px'>{icon} <b>{child['name']}</b> ({child['type']}) <span class='disk-meta'>{' '.join(meta)}</span></div>"

        if child.get('children'):
            html += recursive_disk_html(child['children'], level + 1)
    return html


def build_disk_info(storage_tree):
    html = ""
    for root in storage_tree['roots']:
        name = root['name']
        size = root.get('size', '?')
        model = root.get('model', '')
        hctl = root.get('hctl', 'N/A')

        details_html = recursive_disk_html(root.get('children', []), 0)

        paths = ""
        if root.get('paths'):
            paths = f"<div style='margin-top:5px;font-size:0.8em;color:#666'>Paths: {', '.join(root['paths'])}</div>"

        html += f"""
        <div class='disk-root'>
            <div class='disk-header'>
                <span id='db-{name}' class='disk-icon' onclick='toggleDisk("{name}")'>+</span>
                <span>{name} ({size})</span>
                <span style='font-weight:normal;color:#aaa'>{model}</span>
                <span class='hctl-tag'>HCTL: {hctl}</span>
            </div>
            <div id='dd-{name}' class='disk-details'>
                {details_html}
                {paths}
            </div>
        </div>
        """
    return html


def build_net_info(net_data):
    html = ""
    # Interfaces Table
    for iface in net_data.get('interfaces', []):
        html += f"<div class='kv'><span class='kv-k'>{iface['name']}</span><span class='kv-v'>{iface['ip']}</span></div>"

    # GW and DNS
    gw = net_data.get('gateway', 'N/A')
    dns = ", ".join(net_data.get('dns', [])) or "N/A"

    html += "<div class='net-gw-dns'>"
    html += f"<div><b>GW:</b> {gw}</div>"
    html += f"<div><b>DNS:</b> {dns}</div>"
    html += "</div>"
    return html


def build_disk_string(path, mount_map):
    best = ""
    info = None
    for mp, d in mount_map.items():
        if path.startswith(mp) and len(mp) > len(best):
            best = mp
            info = d
    if info:
        parts = []
        parts.append(f"FS:{info.get('fstype', 'N/A')}")
        parts.append(f"DEV:/dev/{info.get('name', 'N/A')}")
        parts.append(f"UUID:{info.get('uuid', 'N/A')}")
        hctl = info.get('hctl') or "N/A"
        parts.append(f"<span class='hctl'>HCTL:{hctl}</span>")
        base = " ".join(parts)
        path_str = f"PATH:{info['paths'][0]}" if info.get('paths') else ""
        return f"<span class='disk-str'>({base} {path_str})</span>"
    return "<span class='disk-str'>(Pseudo/Virtual/N/A)</span>"


def is_suspicious_lib(libpath):
    bad = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")
    if libpath.startswith(bad) or "(deleted)" in libpath:
        return True
    return False


def get_username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def _get_alert_html(node):
    """Generates the HTML string for badges/alerts."""
    alerts = []
    # Agregação de Badges (Bubbling)
    if node.tree_has_ssh:
        alerts.append("<span class='tag t-ssh'>SSH</span>")
    if node.tree_has_sudo:
        alerts.append("<span class='tag t-sudo'>SUDO</span>")

    if node.anomaly_score > 0:
        alerts.append(f"<b class='tag t-warn'>WARN:{node.anomaly_score}</b>")
    elif node.tree_has_warn:
        alerts.append("<span class='alert-icon' title='Child anomaly'>&#9888;</span>")

    if node.tree_has_net_err:
        alerts.append("<span class='tag t-err'>NET ERR</span>")
    if node.tree_has_unsafe:
        alerts.append("<span class='tag t-unsafe'>UNSAFE</span>")

    return " ".join(alerts)


def _get_details_html(node, mounts):
    """Generates the detailed HTML pane for a row."""
    det_html = "<div class='det-grid'>"
    det_html += "<div><table class='ctx-tbl'>"
    det_html += f"<tr><td class='ctx-lbl'>Full Command:</td><td class='ctx-val'>{node.cmd}</td></tr>"
    det_html += f"<tr><td class='ctx-lbl'>MD5:</td><td class='ctx-val'>{node.md5 or 'N/A'}</td></tr>"
    det_html += f"<tr><td class='ctx-lbl'>User/UID:</td><td class='ctx-val'>{get_username(node.uid)} ({node.uid})</td></tr>"

    sudo_v = node.context.split("[SUDO:")[1].split("]")[0] if "[SUDO:" in node.context else "<span class='d-na'>No</span>"
    ssh_v = node.context.split("[SSH:")[1].split("]")[0] if "[SSH:" in node.context else "<span class='d-na'>N/A</span>"
    det_html += f"<tr><td class='ctx-lbl'>Sudo/SSH:</td><td class='ctx-val'>{sudo_v} / {ssh_v}</td></tr>"
    det_html += f"<tr><td class='ctx-lbl'>Security:</td><td class='ctx-val'>{node.sec_ctx or 'unconfined'}</td></tr>"

    if node.suspicious_env:
        det_html += f"<tr><td class='ctx-lbl' style='color:red'>Suspicious Env:</td><td class='ctx-val'>{', '.join(node.suspicious_env)}</td></tr>"

    det_html += (
        f"<tr><td class='ctx-lbl'>Lifetime I/O:</td>"
        f"<td class='ctx-val'>R: {node.read_bytes_total / 1024 / 1024:.2f} MB | "
        f"W: {node.write_bytes_total / 1024 / 1024:.2f} MB</td></tr></table></div>"
    )

    det_html += "<div><span class='det-title'>Network Resilience</span>"
    retr_s = "color:var(--red);font-weight:bold" if node.tcp_retrans > 0 else "color:#888"
    drop_s = "color:var(--red);font-weight:bold" if node.tcp_drops > 0 else "color:#888"
    det_html += f"<div style='margin-bottom:8px'>Retransmits: <span style='{retr_s}'>{node.tcp_retrans}</span> | Drops: <span style='{drop_s}'>{node.tcp_drops}</span></div>"
    if node.connections:
        for c in node.connections:
            det_html += f"<div style='font-family:monospace;margin-left:10px;color:#bbb'>{c}</div>"
    else:
        det_html += "<div class='d-na' style='margin-left:10px'>No active connections</div>"
    det_html += "</div></div>"

    det_html += "<div class='det-blk'><span class='det-title'>Loaded Libraries</span>"
    if node.libs:
        ls = []
        for lib in sorted(node.libs):
            if is_suspicious_lib(lib):
                ls.append(f"<span style='color:var(--red);font-weight:bold'>{lib} <span class='tag t-unsafe'>[UNSAFE]</span></span>")
            else:
                ls.append(lib)
        det_html += f"<div class='lib-list'>{'<br>'.join(ls)}</div>"
    else:
        det_html += "<span class='d-na'>N/A</span>"
    det_html += "</div>"

    det_html += "<div class='det-blk'><span class='det-title'>Active Files</span>"
    if node.open_files:
        for f in sorted(node.open_files):
            dstr = build_disk_string(f, mounts)
            det_html += f"<div style='font-family:monospace;margin-left:10px'>{f} {dstr}</div>"
    else:
        det_html += "<div class='d-na' style='margin-left:10px'>No file activity</div>"
    det_html += "</div>"
    return det_html


def render_row(node, level, mounts):
    indent = f"<span style='padding-left:{level * 25}px;border-left:1px solid #444'></span>"
    if level > 0:
        indent += "|-- "

    sym = '+' if node.has_kids else '&bull;'
    expander = f"<span id='b-{node.pid}' class='exp' onclick='event.stopPropagation();toggleBranch({node.pid})'>{sym}</span>"
    badge = "<span class='tag t-new'>NEW</span> " if node.is_new else ""
    cmd = node.cmd if len(node.cmd) < 50 else node.cmd[:50] + "..."

    alert_html = _get_alert_html(node)
    det_html = _get_details_html(node, mounts)

    row_cls = "row proc-row"
    if node.anomaly_score > 0:
        row_cls += " warn"

    rss = f"{node.rss / 1024 / 1024:.1f} MB"
    cpu_cls = "cpu-hi" if node.cpu_usage_pct > 50 else ""
    nice_cls = "color:var(--red)" if (node.prio - 120) < 0 else "color:var(--grn)"

    win_io = ""
    if node.write_bytes_delta > 0:
        win_io = f"<span class='io-w'>W: {format_bytes(node.write_bytes_delta)}</span>"
    elif node.read_bytes_delta > 0:
        win_io = f"<span class='io-r'>R: {format_bytes(node.read_bytes_delta)}</span>"

    tree_io = ""
    if node.tree_write_delta > 0 or node.tree_read_delta > 0:
        tree_io = f"<span class='io-agg'>&Sigma; R:{format_bytes(node.tree_read_delta)} W:{format_bytes(node.tree_write_delta)}</span>"

    tot_io = f"<span style='color:#888;font-size:10px'>R:{format_bytes(node.read_bytes_total)}<br>W:{format_bytes(node.write_bytes_total)}</span>"

    net_tx = f"<span class='net-val'>{format_bytes(node.net_tx_bytes)}</span>"
    if node.tree_net_tx > 0:
        net_tx += f"<span class='net-agg'>&Sigma; {format_bytes(node.tree_net_tx)}</span>"

    net_rx = f"<span class='net-val'>{format_bytes(node.net_rx_bytes)}</span>"
    if node.tree_net_rx > 0:
        net_rx += f"<span class='net-agg'>&Sigma; {format_bytes(node.tree_net_rx)}</span>"

    # Split f-string to comply with line length limits
    row_html = (
        f'<tr class="{row_cls}" data-pid="{node.pid}" '
        f'data-cpu="{node.cpu_usage_pct}" data-mem="{node.rss}" '
        f'data-io="{node.write_bytes_delta + node.read_bytes_delta}" '
        f'onclick="toggleDet({node.pid})">'
        f'<td width="35%">{indent}{expander} {badge}{cmd}</td>'
        f'<td width="60" style="color:#569cd6">{node.pid}</td>'
        f'<td width="90">{get_username(node.uid)}</td>'
        f'<td width="50" style="{nice_cls}">{node.prio - 120}</td>'
        f'<td width="60" class="{cpu_cls}">{node.cpu_usage_pct:.1f}%</td>'
        f'<td width="80">{rss}</td>'
        f'<td width="100">{win_io} {tree_io}</td>'
        f'<td width="100">{tot_io}</td>'
        f'<td width="90">{net_tx}</td>'
        f'<td width="90">{net_rx}</td>'
        f'<td>{alert_html}</td>'
        f'</tr>'
        f'<tr id="d-{node.pid}" class="det-row">'
        f'<td colspan="11" class="det-cell">{det_html}</td>'
        f'</tr>'
    )
    return row_html


def generate_html(inv, tree, outfile, version, logo_b64=None, has_anomalies=False):
    os_info = ""
    for k, v in inv['os'].items():
        os_info += f"<div class='kv'><span class='kv-k'>{k.title()}</span><span class='kv-v'>{v}</span></div>"
    os_info += f"<div class='kv'><span class='kv-k'>CPU</span><span class='kv-v'>{inv['hw']['cpu']}</span></div>"

    # New Storage Renderer
    disk_info = build_disk_info(inv['storage'])

    # New Network Renderer
    net_info = build_net_info(inv['net'])

    rows = ""

    def walk(pid, lvl):
        nonlocal rows
        if pid not in tree:
            return
        node = tree[pid]
        kids = sorted([p for p in tree.values() if p.ppid == pid], key=lambda x: x.pid)
        node.has_kids = len(kids) > 0

        r = render_row(node, lvl, inv['storage']['mounts'])
        if lvl > 0:
            r = r.replace('class="row', f'class="row hidden c-{node.ppid}')
        else:
            r = r.replace('class="row', 'class="row root')

        rows += r
        for k in kids:
            walk(k.pid, lvl + 1)

    roots = [p.pid for p in tree.values() if p.ppid not in tree and p.pid > 0]
    for r in sorted(roots):
        walk(r, 0)

    logo_html = ""
    if logo_b64:
        logo_html = f'<img src="data:image/png;base64,{logo_b64}" class="client-logo">'

    blink_cls = "blinking" if has_anomalies else ""

    html = HTML_TEMPLATE.replace("{DATE}", inv['generated']) \
        .replace("{HOST}", inv['os']['hostname']) \
        .replace("{OS_INFO}", os_info) \
        .replace("{DISK_INFO}", disk_info) \
        .replace("{NET_INFO}", net_info) \
        .replace("{ROWS}", rows) \
        .replace("{VERSION}", version) \
        .replace("{LOGO_HTML}", logo_html) \
        .replace("{BLINK_CLASS}", blink_cls)

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)
    return outfile
