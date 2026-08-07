# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/exporters/web_assets.py
# DESCRIPTION: Contains the static HTML/CSS/JS assets for the report.
#              Serves as the Frontend Resource bundle.
#
#              UPDATED v0.70.02:
#              - FEAT: Added 'Duration' column to Table Structure (Header & Colgroup).
#              - FEAT: Added CSS class .phys-alert for Hardware Drop Alerts (CRC/Frame).
#              - FIX: Adjusted table widths to accommodate the new timing column.
#              - MAINTAINED: All features, logic, and documentation from v0.61.00.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. LEGEND COMPONENT (Updated Tooltip)
# ------------------------------------------------------------------------------
LEGEND_HTML = r"""
<div class="score-legend-wrapper">
    <span class="legend-icon" title="Anomaly Score Rules">?</span>
    <div class="score-tooltip">
        <h4>Anomaly Score Rules (Bitmask)</h4>
        <table>
            <tr><td>+01</td><td>Unsafe Lib (/tmp, /dev/shm)</td></tr>
            <tr><td>+02</td><td>Malware Pattern (Exec /tmp)</td></tr>
            <tr><td>+04</td><td>Network Tool (nc, socat)</td></tr>
            <tr><td>+08</td><td>Deleted Binary</td></tr>
            <tr><td>+16</td><td>EDR (Endpoint Detection and Response) / AV (Antivirus)</td></tr>
            <tr><td>+32</td><td>GPU Usage (Mining)</td></tr>
            <tr><td>+64</td><td>Network Issue (Drops/Retrans)</td></tr>
            <tr><td>+128</td><td>Zombie/Defunct Process</td></tr>
            <tr><td>+256</td><td>Immutable File Anomaly</td></tr>
            <tr><td>+512</td><td>EDR Latency (Process Frozen)</td></tr>
        </table>
        <div style="font-size:9px; color:#777; margin-top:5px; border-top:1px solid #333; padding-top:2px;">
            * Score is unique sum of triggers.
        </div>
    </div>
</div>
"""

# ------------------------------------------------------------------------------
# 2. CSS STYLES (Supports New Badges & Dark Theme)
# ------------------------------------------------------------------------------
CSS_BASE = r"""
:root { --bg:#121212; --fg:#e0e0e0; --acc:#0078d4; --red:#ff6b6b; --grn:#51cf66; --yel:#fcc419; --pur:#b180ff; --gry:#777; --drk:#252526; --border:#333; --cyn:#4ec9b0; }
body { font-family:'Segoe UI', 'Roboto', monospace; background:var(--bg); color:var(--fg); padding:20px; font-size:13px; margin:0; }

/* --- HEADER & LAYOUT --- */
.sticky-wrapper {
    position: sticky; top: 0; z-index: 1000;
    background-color: var(--bg);
    padding: 10px 20px 0 20px;
    border-bottom: 1px solid var(--acc);
    box-shadow: 0 5px 15px rgba(0,0,0,0.5);
}
.hdr { display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; }
.title h1 { margin:0; font-weight:300; font-size:26px; color:var(--acc); letter-spacing:-0.5px; }
.title span { font-size:0.6em; color:#666; margin-left:10px; }
.subtitle { color:var(--gry); font-size:0.85em; text-transform:uppercase; letter-spacing:2px; margin-top:4px; font-weight:bold; }
.meta { text-align:right; color:#888; font-size:0.9em; }

/* --- CARDS --- */
.inv { display:grid; grid-template-columns:repeat(auto-fit,minmax(380px,1fr)); gap:15px; margin-bottom:15px; }
.card { background:var(--drk); border:1px solid #444; padding:12px; border-radius:4px; display:flex; flex-direction:column; }
.card h3 { margin:0 0 10px 0; border-bottom:1px solid #444; color:var(--acc); font-size:11px; text-transform:uppercase; display:flex; justify-content:space-between; align-items:center; }
.kv { display:grid; grid-template-columns: 140px 1fr; gap:10px; border-bottom:1px solid #2a2a2a; padding-bottom:2px; align-items:baseline; }
.kv:last-child { border-bottom: none; }
.kv-k { color:var(--gry); font-weight:normal; } .kv-v { font-weight:600; color:#ddd; word-break:break-all; }

/* --- PHYSICAL DROP ALERT (v0.70) --- */
.phys-alert {
    border: 1px solid var(--red);
    background: rgba(255, 107, 107, 0.1);
    color: var(--red);
    padding: 8px;
    margin-bottom: 15px;
    border-radius: 4px;
    font-weight: bold;
    text-align: center;
    animation: pulse 2s infinite;
    font-family: 'Consolas', monospace;
    font-size: 12px;
}
@keyframes pulse { 0% { opacity: 0.8; } 50% { opacity: 1; } 100% { opacity: 0.8; } }

/* --- SCROLLABLE LIST BOX (Files/Libs) --- */
.list-box {
    max-height: 250px;
    overflow-y: auto;
    overflow-x: hidden;
    border: 1px solid #333;
    background: #1a1a1a;
    padding: 5px;
    border-radius: 3px;
}
.list-box::-webkit-scrollbar { width: 8px; }
.list-box::-webkit-scrollbar-track { background: #222; }
.list-box::-webkit-scrollbar-thumb { background: #444; border-radius: 4px; }
.list-box::-webkit-scrollbar-thumb:hover { background: var(--acc); }

/* --- PHYSICAL DROP ALERT (v0.70) --- */
.phys-alert {
    border: 1px solid var(--red);
    background: rgba(255, 107, 107, 0.1);
    color: var(--red);
    padding: 8px;
    margin-bottom: 15px;
    border-radius: 4px;
    font-weight: bold;
    text-align: center;
    animation: pulse 2s infinite;
    font-family: 'Consolas', monospace;
    font-size: 12px;
}
@keyframes pulse { 0% { opacity: 0.8; } 50% { opacity: 1; } 100% { opacity: 0.8; } }

/* --- DISK TOPOLOGY SPECIFIC SCROLL (FIXED HEIGHT WRAPPER) --- */
.disk-topology-wrapper {
    display: block;
    position: relative;
    height: 180px;  /* FIXED HEIGHT for container */
    /* overflow: hidden; */ /* Contain overflow */
    border: 1px solid #333;
    border-radius: 3px;
    background: #1a1a1a;
}

.disk-topology-box {
    height: 100%;
    width: 100%;
    overflow-y: scroll; /* Force Scrollbar */
    padding: 5px;
    box-sizing: border-box;
}

/* High Contrast Scrollbar */
.disk-topology-box::-webkit-scrollbar { width: 12px; }
.disk-topology-box::-webkit-scrollbar-track { background: #000; border-left: 1px solid #333; }
.disk-topology-box::-webkit-scrollbar-thumb { background: #888; border-radius: 6px; border: 2px solid #000; }
.disk-topology-box::-webkit-scrollbar-thumb:hover { background: var(--acc); }

/* --- TOPOLOGY STYLES --- */
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

.net-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 5px; font-size: 0.95em; margin-bottom: 5px; }
.net-iface { font-weight: bold; color: var(--acc); }
.net-gw-dns { margin-top: 8px; border-top: 1px dashed #444; padding-top: 4px; font-size: 0.9em; color: #888; }

/* --- BADGES & ICONS --- */
.controls { display:flex; flex-direction: column; gap:10px; margin-bottom:15px; width: 100%; }
.legend { display:flex; gap:15px; background:#222; padding:8px 12px; border:1px solid #444; border-radius:3px; align-items:center; flex-wrap:wrap; width: 100%; box-sizing: border-box; }
.leg-grp { display:flex; align-items:center; gap:10px; padding-right:15px; border-right:1px solid #444; }
.leg-grp:last-child { border:none; }
.leg-lbl { font-weight:bold; color:#aaa; font-size:11px; text-transform:uppercase; }

/* LEGEND BARS (Restored) */
.bar { width:60px; height:8px; border-radius:2px; display:inline-block; }
.grad-prio { background: linear-gradient(to right, var(--red), var(--grn)); }
.grad-cpu { background: linear-gradient(to right, var(--grn), var(--red)); }

/* Base Tag Style */
.tag {
    display:inline-flex; align-items:center; justify-content:center;
    padding:1px 4px; border-radius:3px;
    font-weight:bold; margin-right:4px; cursor:help;
    font-size:16px; /* Optimized for Emojis */
    border:1px solid transparent;
    vertical-align: middle;
}
.tag:hover { transform: scale(1.2); transition: 0.1s; background: rgba(255,255,255,0.1); }

/* Visually Hidden (But searchable/filterable) */
.visually-hidden {
    position: absolute;
    width: 1px; height: 1px; margin: -1px;
    padding: 0; overflow: hidden;
    clip: rect(0, 0, 0, 0); border: 0;
}

/* Badge Filters in Toolbar (Clickable) */
.filter-btn { cursor: pointer; opacity: 0.7; transition: 0.2s; font-size: 16px; margin: 0 4px; }
.filter-btn:hover { opacity: 1.0; transform: scale(1.2); }
/* [UI] Active indicator: outline (not border) so it never shifts neighbor icons */
.filter-btn.active { opacity: 1.0; outline: 2px solid var(--red); outline-offset: 2px; border-radius: 3px; }

/* Special Badges (Backgrounds can be minimal now, relying on Icon) */
.t-warn { border-color:var(--red); background:rgba(255, 107, 107, 0.1); }
.t-err  { background:var(--red); color:#000; }

.btn-clear { cursor:pointer; padding:2px 6px; border-radius:3px; border:1px solid #555; font-size:10px; font-weight:bold; color:#aaa; background:#333; }
/* [UI] Sort buttons styled as bare icons, symmetric with .filter-btn (no gray box) */
.btn-act { cursor:pointer; opacity:0.7; transition:0.2s; font-size:16px; margin:0 4px; display:inline-block; }
.btn-act:hover { opacity:1.0; transform: scale(1.2); }
/* [UI] Active sort indicator, identical to the active filter outline (no layout shift) */
.btn-act.sort-active { opacity:1.0; outline: 2px solid var(--red); outline-offset: 2px; border-radius: 3px; }
#search { width:100%; padding:8px; background:#252526; border:1px solid #555; color:white; border-radius:3px; font-family:monospace; box-sizing:border-box; }

/* --- TABLE STYLES --- */
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
.ctx-lbl { color:#666; width:150px; vertical-align:top; }
.ctx-val { color:#ccc; font-family:'Consolas',monospace; white-space: pre-wrap; word-break: break-all; }
.hctl { color:var(--cyn); font-weight:bold; background:rgba(78, 201, 176, 0.1); padding:0 3px; border-radius:2px; }
.disk-str { color:#888; font-size:0.9em; margin-left:10px; }
.d-na { opacity:0.4; font-style:italic; }
.io-r { color:var(--grn); } .io-w { color:var(--red); }
.io-agg { color:#777; font-size:10px; display:block; margin-top:2px; }
.net-agg { color:#777; font-size:9px; display:block; margin-top:2px; }
.cpu-hi { color:var(--red); font-weight:bold; }
.lib-list { max-height:150px; overflow-y:auto; background:#1a1a1a; padding:5px; border:1px solid #333; color:#bbb; }

/* Legend Tooltip */
.score-legend-wrapper { position: relative; display: inline-flex; align-items: center; justify-content: center; margin-left: 8px; cursor: help; vertical-align: middle; }
.legend-icon { background: var(--drk); border: 1px solid var(--acc); color: var(--acc); width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 12px; }
.score-tooltip {
    display: none; position: absolute; right: 0; top: 30px; z-index: 9999;
    background: #1e1e1e; border: 1px solid var(--acc); padding: 10px;
    width: 280px; box-shadow: 0 5px 15px rgba(0,0,0,0.9); border-radius: 4px;
    text-align: left;
}
.score-legend-wrapper:hover .score-tooltip { display: block; }
.score-tooltip h4 { margin: 0 0 8px 0; color: var(--acc); border-bottom: 1px solid #333; padding-bottom: 4px; font-size: 12px; text-transform: uppercase; }
.score-tooltip table { width: 100%; border-collapse: collapse; }
.score-tooltip td { padding: 3px 0; border-bottom: 1px solid #333; color: #ccc; font-size: 11px; }
.score-tooltip td:first-child { color: var(--red); font-weight: bold; text-align: right; padding-right: 10px; width: 40px; }

/* --- TABS (Findings / Processes) --- */
/* A troca de aba usa esta classe, nunca o estilo inline: o cabecalho da tabela
   declara display:flex inline, e zerar o inline o faria voltar para block,
   empilhando as colunas na vertical. */
.panel-hidden { display: none !important; }
.tabbar { display: flex; gap: 4px; padding: 0 10px; border-bottom: 2px solid #444; }
.tab {
    padding: 8px 18px; cursor: pointer; font-size: 12px; font-weight: bold;
    text-transform: uppercase; letter-spacing: 0.5px; color: #888;
    border: 1px solid transparent; border-bottom: none; border-radius: 4px 4px 0 0;
    user-select: none;
}
.tab:hover { color: #ddd; background: #2a2d2e; }
.tab-active { color: var(--acc); background: #252526; border-color: #444; margin-bottom: -2px; }
.tab-count {
    display: inline-block; min-width: 16px; padding: 1px 5px; margin-left: 5px;
    background: var(--red); color: #fff; border-radius: 8px; font-size: 10px;
}

/* --- FINDINGS PANEL --- */
.findings-container { padding: 12px 16px 40px 16px; }
.fnd-empty { color: #777; font-style: italic; padding: 20px; }
.fnd-summary { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.fnd-chip {
    padding: 5px 12px; border: 1px solid #555; border-radius: 14px;
    font-size: 11px; color: #ccc; cursor: pointer; user-select: none;
}
.fnd-chip:hover { background: #2a2d2e; }
.fnd-chip b { margin-right: 4px; font-size: 13px; }
.fnd-chip-zero { opacity: 0.4; }
.fnd-chip-all { border-style: dashed; }
.fnd-list { display: flex; flex-direction: column; gap: 8px; }
.fnd-item { background: #252526; border-left: 4px solid #444; border-radius: 3px; padding: 8px 12px; }
.fnd-item:hover { background: #2a2d2e; }
.fnd-head { display: flex; align-items: center; gap: 10px; cursor: pointer; }
.fnd-sev {
    color: #1e1e1e; font-weight: bold; font-size: 10px; text-transform: uppercase;
    padding: 2px 8px; border-radius: 3px; min-width: 60px; text-align: center;
}
.fnd-title { font-weight: bold; color: #eee; flex: 1; }
.fnd-tech {
    font-family: monospace; font-size: 10px; color: var(--yel);
    border: 1px solid #555; padding: 1px 6px; border-radius: 3px;
}
.fnd-src {
    font-size: 10px; color: #888; text-transform: uppercase;
    border: 1px dashed #555; padding: 1px 6px; border-radius: 3px;
}
.fnd-target { font-family: monospace; font-size: 11px; color: #999; margin: 4px 0 0 70px; word-break: break-all; }
.fnd-det { display: none; margin: 8px 0 4px 70px; padding-top: 8px; border-top: 1px dashed #444; }
.fnd-desc { color: #bbb; font-size: 12px; margin-bottom: 6px; }
.fnd-rec { color: var(--grn); font-size: 12px; margin-bottom: 6px; }
.fnd-refs { color: #999; font-size: 11px; margin-bottom: 6px; }
.fnd-ev-title { color: var(--acc); font-size: 10px; text-transform: uppercase; font-weight: bold; margin: 8px 0 4px 0; }
.fnd-ev-row { display: flex; gap: 8px; margin-bottom: 3px; align-items: flex-start; }
.fnd-ev-k { color: #888; font-size: 11px; min-width: 90px; font-family: monospace; }
.fnd-ev-v {
    margin: 0; color: #ccc; font-size: 11px; font-family: monospace;
    white-space: pre-wrap; word-break: break-all; flex: 1;
    background: #1e1e1e; padding: 4px 6px; border-radius: 3px; max-height: 220px; overflow: auto;
}
/* Pivo para o processo em execucao (so aparece quando ha correspondencia). */
.fnd-pivot {
    font-size: 10px; color: var(--grn); border: 1px solid var(--grn);
    padding: 2px 8px; border-radius: 3px; cursor: pointer; white-space: nowrap;
}
.fnd-pivot:hover { background: var(--grn); color: #1e1e1e; }

/* Destaque temporario da linha alvo apos o pivo. */
@keyframes pivotPulse {
    0%   { background: rgba(78,201,176,0.55); }
    100% { background: transparent; }
}
.pivot-target { animation: pivotPulse 2.5s ease-out; }

/* --- ATT&CK REFERENCE --- */
.atk-intro { color: #aaa; font-size: 12px; margin-bottom: 14px; max-width: 900px; line-height: 1.5; }
.atk-list { display: flex; flex-direction: column; gap: 8px; }
.atk-item { background: #252526; border-left: 4px solid var(--yel); border-radius: 3px; padding: 10px 12px; }
.atk-head { display: flex; align-items: center; gap: 10px; }
.atk-id { font-family: monospace; font-weight: bold; color: var(--yel); font-size: 12px; }
.atk-name { color: #eee; font-weight: bold; flex: 1; }
.atk-qty {
    background: #333; color: #ccc; font-size: 10px; padding: 1px 8px;
    border-radius: 8px; border: 1px solid #555;
}
.atk-tactic { color: #999; font-size: 11px; margin-top: 4px; }
.atk-desc { color: #bbb; font-size: 12px; margin-top: 6px; line-height: 1.5; }
.atk-link { color: var(--acc); font-size: 10px; text-decoration: none; display: inline-block; margin-top: 6px; }
.atk-link:hover { text-decoration: underline; }
"""

# ------------------------------------------------------------------------------
# 3. JAVASCRIPT (State Preservation, AJAX, & Logic)
# ------------------------------------------------------------------------------
JS_BLOCK = r"""
    // --- STATE MANAGEMENT ---
    var state = {
        isLive: false,
        expandedPids: new Set(),
        detailsOpenPids: new Set(),
        currentFilter: "",
        // Ordem original da arvore, guardada antes da primeira reordenacao para
        // que o botao de reset devolva a hierarquia pai-filho sem recarregar.
        originalOrder: null
    };

    // --- TREE INTERACTION ---
    function toggleBranch(pid) {
        var btn = document.getElementById('b-'+pid);
        if(btn && btn.classList.contains('disabled')) return;

        var closed = btn && btn.innerText === '+';
        if(btn) btn.innerText = closed ? '-' : '+';

        // Track state
        if(closed) state.expandedPids.add(parseInt(pid));
        else state.expandedPids.delete(parseInt(pid));

        document.querySelectorAll('.c-'+pid).forEach(r => {
            if(closed) r.classList.remove('hidden');
            else {
                r.classList.add('hidden');
                var childPid = r.dataset.pid;
                // Recursive close logic
                var sub = document.getElementById('b-'+childPid);
                if(sub && sub.innerText==='-') toggleBranch(childPid);

                var det = document.getElementById('d-'+childPid);
                if(det) det.classList.remove('show');
            }
        });
    }

    function toggleDet(pid) {
        var el = document.getElementById('d-'+pid);
        if(el) {
            el.classList.toggle('show');
            if(el.classList.contains('show')) state.detailsOpenPids.add(parseInt(pid));
            else state.detailsOpenPids.delete(parseInt(pid));
        }
    }

    function restoreTreeState() {
        // Re-open branches
        state.expandedPids.forEach(pid => {
            var btn = document.getElementById('b-'+pid);
            if(btn && btn.innerText === '+') toggleBranch(pid);
        });
        // Re-apply Filter
        if(state.currentFilter) {
            document.getElementById("search").value = state.currentFilter;
            filterTable();
        }
    }

    // --- FILTERING ---
    function filterTable() {
        var v = document.getElementById("search").value.toUpperCase();
        state.currentFilter = v;

        var isFiltering = v !== "";
        document.querySelectorAll(".proc-row").forEach(r => {
            // Include hidden text (badge names) in search
            var txt = r.innerText.toUpperCase();
            // Also check data-filter attribute specifically
            var badges = r.querySelectorAll('.tag');
            badges.forEach(b => { if(b.dataset.filter) txt += b.dataset.filter.toUpperCase(); });

            var pid = r.dataset.pid;
            var btn = document.getElementById('b-'+pid);

            var match = txt.indexOf(v) > -1;

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
        else restoreTreeState();
    }

    function setFilter(val, el) {
        document.getElementById("search").value = val;
        filterTable();
        // [UI] Highlight the active filter badge (single active filter at a time)
        document.querySelectorAll(".filter-btn").forEach(function(b){ b.classList.remove("active"); });
        if (el) el.classList.add("active");
    }

    // --- LIVE MODE LOGIC ---
    function updateTableContent(newHtml) {
        var tbody = document.querySelector(".table-container tbody");
        if(tbody) {
            tbody.innerHTML = newHtml;
            restoreTreeState();
        }
        var banner = document.getElementById('live-banner-ts');
        if(banner) banner.innerText = new Date().toLocaleTimeString();
    }

    async function startLiveMode() {
        if(state.isLive) return;
        state.isLive = true;
        console.log("Starting Live Updates...");

        // Create Banner safely if not exists
        if(!document.getElementById('live-banner')) {
            var div = document.createElement('div');
            div.id = 'live-banner';
            div.style.cssText = 'background:#004400; color:#fff; padding:5px; text-align:center; font-weight:bold; border-bottom:1px solid #0f0; position:sticky; top:0; z-index:2000;';
            div.innerHTML = '🟢 LIVE MODE ACTIVE | Auto-Update (5s) | Last: <span id="live-banner-ts">Just now</span>';
            document.body.prepend(div);
        }

        setInterval(async () => {
            try {
                const response = await fetch('/live_update');
                if (response.ok) {
                    const newRows = await response.text();
                    updateTableContent(newRows);
                }
            } catch (e) {
                console.error("Live Update Failed:", e);
            }
        }, 5000);
    }

    // --- UTILS ---
    function toggleDisk(name) {
        // [UPDATED] Sanitize name for ID selector (match with Python logic)
        var safeName = name.replace(/[^a-zA-Z0-9_-]/g, '_');

        var el = document.getElementById('dd-'+safeName);
        var btn = document.getElementById('db-'+safeName);
        if(el && btn) {
            if(el.classList.contains('show')) { el.classList.remove('show'); btn.innerText = '+'; }
            else { el.classList.add('show'); btn.innerText = '-'; }
        }
    }

    function resetTree() {
        // Devolve a arvore ao estado inicial SEM recarregar a pagina.
        //
        // Antes isto era um location.reload(): alem de reprocessar um relatorio
        // que passa de 10MB, o recarregamento voltava para a aba padrao, de modo
        // que quem pedia "resetar a arvore" era jogado para fora dela.
        var tbody = document.querySelector(".table-container tbody");
        if (tbody && state.originalOrder) {
            state.originalOrder.forEach(function (n) { tbody.appendChild(n); });
        }

        state.expandedPids.clear();
        state.detailsOpenPids.clear();
        state.currentFilter = "";

        var busca = document.getElementById("search");
        if (busca) busca.value = "";

        document.querySelectorAll(".proc-row").forEach(function (r) {
            r.style.display = "";
            if (r.classList.contains("root")) r.classList.remove("hidden");
            else r.classList.add("hidden");
            var btn = document.getElementById("b-" + r.dataset.pid);
            if (btn) { btn.classList.remove("disabled"); btn.innerText = "+"; }
        });
        document.querySelectorAll(".det-row").forEach(function (d) {
            d.classList.remove("show");
        });

        document.querySelectorAll(".filter-btn").forEach(function (b) {
            b.classList.remove("active");
        });
        document.querySelectorAll(".btn-act").forEach(function (b) {
            b.classList.remove("sort-active");
        });
    }

    function sortView(metric, el) {
        var tbody = document.querySelector(".table-container tbody");
        if (!tbody) return;
        var rows = Array.from(tbody.querySelectorAll(".proc-row"));
        // A ordem hierarquica so existe no DOM inicial: se for perdida sem
        // copia, a unica forma de recupera-la seria recarregar a pagina.
        if (state.originalOrder === null) {
            state.originalOrder = Array.from(tbody.children);
        }
        rows.forEach(r => {
            r.classList.remove('hidden'); r.style.display="";
            var btn=document.getElementById('b-'+r.dataset.pid);
            if(btn){ btn.innerText='•'; btn.classList.add('disabled'); }
        });
        rows.sort((a, b) => {
            var va = parseFloat(a.dataset[metric] || 0);
            var vb = parseFloat(b.dataset[metric] || 0);
            return vb - va;
        });
        rows.forEach(r => { tbody.appendChild(r); var det = document.getElementById('d-'+r.dataset.pid); if(det) tbody.appendChild(det); });
        // [UI] Highlight the active sort badge (independent from the filter highlight)
        document.querySelectorAll(".btn-act").forEach(function(b){ b.classList.remove("sort-active"); });
        if (el) el.classList.add("sort-active");
    }

    // Function to Print Storage Card content (Handles 100+ disks by removing Scroll)
    function printStorage() {
        var content = document.getElementById('storage-card').innerHTML;
        var win = window.open('', '', 'height=600,width=800');
        win.document.write('<html><head><title>Storage Topology</title>');
        win.document.write('<style>');
        win.document.write('body{font-family:sans-serif; background:#fff; color:#000;}');
        // KEY FIX: Override .list-box to allow full expansion
        win.document.write('.list-box, .disk-topology-box { max-height: none !important; overflow: visible !important; border: none; }');
        win.document.write('.disk-details { display: block !important; margin-left: 20px; border-left: 1px solid #ccc; padding-left: 10px; }');
        win.document.write('.disk-icon, .btn-print-disk { display: none; }');
        win.document.write('.disk-header { font-weight: bold; margin-top: 10px; }');
        win.document.write('</style>');
        win.document.write('</head><body>');
        win.document.write(content);
        win.document.write('</body></html>');
        win.document.close();
        win.print();
    }

    // --- TABS ---
    // Alterna os paineis por data-panel. A arvore de processos e seus controles
    // sao preservados integralmente: apenas mudam de visibilidade.
    function showTab(name, el) {
        var panels = document.querySelectorAll('[data-panel]');
        for (var i = 0; i < panels.length; i++) {
            var p = panels[i];
            // Alterna pela classe: mexer em style.display apagaria o display
            // inline original (o cabecalho da tabela e flex) e quebraria o layout.
            if (p.getAttribute('data-panel') === name) {
                p.classList.remove('panel-hidden');
            } else {
                p.classList.add('panel-hidden');
            }
        }
        var tabs = document.querySelectorAll('.tab');
        for (var j = 0; j < tabs.length; j++) {
            tabs[j].classList.remove('tab-active');
        }
        if (el) { el.classList.add('tab-active'); }
    }

    // Expande/recolhe a evidencia de um achado.
    function toggleFinding(idx) {
        var d = document.getElementById('fnd-' + idx);
        if (!d) { return; }
        d.style.display = (d.style.display === 'block') ? 'none' : 'block';
    }

    // Pivo: leva da aba Findings ate o processo que executa o caminho
    // denunciado pelo achado, revelando toda a cadeia de ancestrais.
    function pivotToProcess(pidList) {
        var pids = String(pidList).split(',');
        var targetPid = pids[0];

        // 1. Vai para a aba Processes.
        showTab('processes', document.querySelector('.tab[data-tab="processes"]'));

        // 2. Limpa qualquer filtro ativo ANTES de expandir. Com filtro ligado a
        //    arvore desabilita os botoes de ramo e esconde o que nao casa, entao
        //    o alvo poderia ficar invisivel e os controles travados.
        setFilter('');

        var row = document.querySelector('tr[data-pid="' + targetPid + '"]');
        if (!row) { return; }

        // 3. Monta a cadeia de ancestrais subindo por data-ppid.
        var chain = [];
        var current = row;
        var guard = 0;
        while (current && guard < 64) {
            guard++;
            var ppid = current.getAttribute('data-ppid');
            if (!ppid || ppid === '0') { break; }
            var parent = document.querySelector('tr[data-pid="' + ppid + '"]');
            if (!parent || parent === current) { break; }
            chain.push(ppid);
            current = parent;
        }

        // 4. Expande da raiz para baixo usando a funcao da PROPRIA arvore, para
        //    o estado (botoes +/- e state.expandedPids) continuar coerente e a
        //    navegacao seguir funcionando depois do pivo.
        chain.reverse();
        for (var i = 0; i < chain.length; i++) {
            var btn = document.getElementById('b-' + chain[i]);
            if (btn && btn.innerText === '+' && !btn.classList.contains('disabled')) {
                toggleBranch(chain[i]);
            }
        }

        // 5. Rola descontando o cabecalho fixo; sem isso a linha para embaixo
        //    dele e parece que o pivo nao chegou a lugar nenhum.
        var sticky = document.querySelector('.sticky-wrapper');
        var offset = sticky ? sticky.getBoundingClientRect().height + 20 : 20;
        var y = row.getBoundingClientRect().top + window.pageYOffset - offset;
        window.scrollTo({top: y > 0 ? y : 0, behavior: 'smooth'});

        // 6. Destaca o alvo e os demais processos correlacionados.
        document.querySelectorAll('.pivot-target').forEach(function (e) {
            e.classList.remove('pivot-target');
        });
        void row.offsetWidth;  // reinicia a animacao
        row.classList.add('pivot-target');
        for (var k = 1; k < pids.length; k++) {
            var extra = document.querySelector('tr[data-pid="' + pids[k] + '"]');
            if (extra) { extra.classList.add('pivot-target'); }
        }
    }

    // Filtra a lista de achados por severidade ('' mostra todos).
    function filterFindings(sev) {
        var items = document.querySelectorAll('.fnd-item');
        for (var i = 0; i < items.length; i++) {
            var match = (!sev || items[i].getAttribute('data-sev') === sev);
            items[i].style.display = match ? '' : 'none';
        }
        var chips = document.querySelectorAll('.fnd-chip');
        for (var k = 0; k < chips.length; k++) {
            chips[k].style.background = (sev && chips[k].getAttribute('data-sev') === sev) ? '#333' : '';
        }
    }
"""

# ------------------------------------------------------------------------------
# 4. HTML SKELETON (Standardized)
# ------------------------------------------------------------------------------
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sys-Inspector v{VERSION}</title>
<style>
    {CSS_BLOCK}
</style>
<script>
    {JS_BLOCK}
</script>
</head>
<body>
    <div class="sticky-wrapper">
        <div class="hdr">
            <div class="logo-area">
                <div>
                    <div class="title"><h1>Sys-Inspector<span>v{VERSION}</span></h1></div>
                    <div class="subtitle">OBSERVABILITY SUITE - Enterprise Forensic Report</div>
                </div>
            </div>
            <div class="meta">{TIMESTAMP}<br>{HOSTNAME}</div>
        </div>

        <div class="inv">
            <div class="card">
                <h3>System</h3>
                <div id="os-info">{OS_CONTENT}</div>
            </div>

            <div class="card" id="storage-card">
                <h3>Storage Topology <span class="btn-print-disk" onclick="printStorage()">Print</span></h3>
                <div class="disk-topology-wrapper"> <div class="disk-topology-box">
                        {DISK_CONTENT}
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Network Topology</h3>
                <div id="net-info">{NET_CONTENT}</div>
            </div>
        </div>

        <div class="tabbar">
            <span class="tab tab-active" data-tab="findings" onclick="showTab('findings', this)">Findings {FINDINGS_BADGE}</span>
            <span class="tab" data-tab="processes" onclick="showTab('processes', this)">Processes</span>
            <span class="tab" data-tab="attack" onclick="showTab('attack', this)">ATT&amp;CK</span>
        </div>

        <div class="controls panel-hidden" data-panel="processes">
            <div class="legend">
                <div class="leg-grp">
                    <span class="leg-lbl">Priority</span> <div class="bar grad-prio"></div>
                </div>
                <div class="leg-grp">
                    <span class="leg-lbl">CPU %</span> <div class="bar grad-cpu"></div>
                </div>

                <div class="leg-grp">
                    <span class="leg-lbl">Process By</span>
                    <span class="btn-act" onclick="resetTree()" title="Reset Tree View">⟳</span>
                    <span class="btn-act" onclick="sortView('cpu', this)" title="Top CPU Usage">🔥</span>
                    <span class="btn-act" onclick="sortView('io', this)" title="Top Disk I/O">💾</span>
                    <span class="btn-act" onclick="sortView('mem', this)" title="Top Memory (RSS)">🧠</span>
                    <span class="btn-act" onclick="sortView('net', this)" title="Top Network Activity">🌐</span>
                    <span class="btn-act" onclick="sortView('prio', this)" title="Top Priority (Nice)">⚖️</span>
                </div>

                <div class="leg-grp" style="border:none; margin-left:auto; display:flex; align-items:center;">
                    <span class="leg-lbl">Filters</span>
                    <span class="filter-btn" onclick="setFilter('NEW', this)" title="New Processes">✨</span>
                    <span class="filter-btn" onclick="setFilter('SSH', this)" title="SSH Connections">🔌</span>
                    <span class="filter-btn" onclick="setFilter('SUDO', this)" title="Privileged (Sudo)">🛡️</span>
                    <span class="filter-btn" onclick="setFilter('CONTAINER', this)" title="Containerized">📦</span>
                    <span class="filter-btn" onclick="setFilter('EDR/AV', this)" title="Security Inspectors - EDR (Endpoint Detection and Response) / AV (Antivirus)">💊</span>
                    <span class="filter-btn" onclick="setFilter('EDR-WAIT', this)" title="Process Frozen by EDR/AV (Wchan Wait)">🧊</span>
                    <span class="filter-btn" onclick="setFilter('GPU', this)" title="GPU Activity">🕹️</span>
                    <span class="filter-btn" onclick="setFilter('MINER', this)" title="Mining Signature">⛏️</span>
                    <span class="filter-btn" onclick="setFilter('UNSAFE', this)" title="Unsafe Path">☢️</span>
                    <span class="filter-btn" onclick="setFilter('NET ERR', this)" title="Network Errors">❌</span>
                    <span class="filter-btn" onclick="setFilter('ZOMBIE', this)" title="Zombies">🧟</span>

                    <span class="btn-clear" onclick="setFilter('')">🧹 CLEAR</span>
                    <span class="btn-act" onclick="window.print()" title="Save PDF">🖨️</span>

                    {LEGEND_HTML}
                </div>
            </div>
            <input type="text" id="search" placeholder="Filter processes (PID, User, Disk, Alert)..." onkeyup="filterTable()">
        </div>

        <div class="tbl-hdr panel-hidden" data-panel="processes" style="display:flex; border-bottom:2px solid #444; font-weight:bold; color:#aaa; text-transform:uppercase; padding:8px 5px; font-size:11px;">
             <div style="width:20%">Command Tree</div>
             <div style="width:60px">PID</div>
             <div style="width:90px">Duration</div>
             <div style="width:90px">User</div>
             <div style="width:50px">Nice</div>
             <div style="width:60px">CPU%</div>
             <div style="width:80px">RSS</div>
             <div style="width:100px" title="Current Disk I/O (Bytes/sec) - Hot Activity">Disk &Delta;<br>I/O Hot</div>
             <div style="width:100px" title="Total Disk I/O during Session (Accumulated in Tree)">Disk &Sigma;<br>I/O Hist</div>
             <div style="width:90px" title="Network Transmit: Current Delta / Total Session">Net TX<br>&Delta; / &Sigma;</div>
             <div style="width:90px" title="Network Receive: Current Delta / Total Session">Net RX<br>&Delta; / &Sigma;</div>
             <div>Alerts</div>
        </div>
    </div>

    <div class="findings-container" data-panel="findings">
        {FINDINGS_CONTENT}
    </div>

    <div class="findings-container panel-hidden" data-panel="attack">
        {ATTACK_CONTENT}
    </div>

    <div class="table-container panel-hidden" data-panel="processes">
        <table>
            <colgroup>
                <col width="20%">
                <col width="60px">
                <col width="90px">
                <col width="90px">
                <col width="50px">
                <col width="60px">
                <col width="80px">
                <col width="100px">
                <col width="100px">
                <col width="90px">
                <col width="90px">
                <col>
            </colgroup>
            <tbody style="margin-top:10px">
                {TABLE_ROWS}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
