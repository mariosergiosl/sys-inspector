# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/controllers/web_controller.py
# DESCRIPTION: Web Interface for Sys-Inspector v0.90 (Multi-Agent Support).
#              Orchestrates the Fleet Dashboard (Macro) and Inspector (Micro).
#
# FEATURES:
#   - Route / : Fleet Dashboard (List of Agents).
#   - Route /inspector/<uuid> : Deep Dive (The original dashboard).
#   - REST API: Supports fetching specific agent data via UUID.
#   - [FIX v0.90.01] Added missing import 'render_template_string'.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.90.16
# ==============================================================================

import logging
import json
import os
import re
import sqlite3
import time
from contextlib import closing
# [FIX] Added render_template_string to imports
# from flask import Flask, jsonify, make_response, redirect, url_for, render_template_string
from flask import Flask, jsonify, make_response, render_template_string, request, Response
# [SEC] markupsafe ships with Flask; used to escape untrusted data in HTML
from markupsafe import escape
# [SEC] werkzeug ships with Flask; used to verify the hashed dashboard password
from werkzeug.security import check_password_hash

# [SEC] Agent IDs are UUIDs or the literal 'local'. Anything else is rejected
# before being interpolated into HTML/JS responses (XSS prevention).
SAFE_ID_PATTERN = re.compile(r'^[A-Za-z0-9\-]{1,64}$')

# Core & Exporter Imports
try:
    from src.core.crypto import load_private_key, decrypt_data
    # Reusing assets for visual consistency
    from src.exporters.web_assets import HTML_TEMPLATE, CSS_BASE, JS_BLOCK, LEGEND_HTML
    from src.exporters.html_report import (
        render_os_block,
        render_net_block,
        render_disk_block,
        render_process_rows,
        render_findings_panel
    )
except ImportError as e:
    print(f"[CRITICAL] Import Error in WebController: {e}")
    raise

# ==============================================================================
# 1. FLEET DASHBOARD TEMPLATE (The "Entrance" Hall)
# ==============================================================================
FLEET_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sys-Inspector Fleet</title>
    <style>
        :root { --bg:#121212; --card:#1e1e1e; --text:#e0e0e0; --acc:#0078d4; --red:#ff6b6b; --grn:#51cf66; }
        body { background:var(--bg); color:var(--text); font-family:'Segoe UI', monospace; padding:40px; margin:0; }

        .header { display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #333; padding-bottom:20px; margin-bottom:30px; }
        .brand h1 { margin:0; font-weight:300; font-size:32px; color:var(--acc); }
        .brand span { font-size:12px; color:#666; letter-spacing:1px; text-transform:uppercase; font-weight:bold; }

        .grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap:20px; }

        .agent-card {
            background:var(--card); border:1px solid #333; border-radius:4px; padding:20px;
            transition:0.2s; cursor:pointer; position:relative; overflow:hidden;
        }
        .agent-card:hover { transform:translateY(-3px); border-color:var(--acc); box-shadow:0 5px 15px rgba(0,0,0,0.3); }

        .status-bar { height:4px; width:100%; position:absolute; top:0; left:0; }
        .online { background:var(--grn); }
        .offline { background:var(--red); }

        .agent-name { font-size:18px; font-weight:bold; margin-bottom:5px; color:#fff; }
        .agent-ip { font-size:12px; color:#888; font-family:monospace; margin-bottom:15px; }

        .metrics { display:flex; justify-content:space-between; margin-top:15px; border-top:1px solid #333; padding-top:10px; }
        .m-item { text-align:center; }
        .m-val { font-size:16px; font-weight:bold; display:block; }
        .m-lbl { font-size:10px; color:#666; text-transform:uppercase; }

        .last-seen { font-size:10px; color:#555; margin-top:15px; text-align:right; font-style:italic; }
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">
            <h1>Sys-Inspector</h1>
            <span>Infrastructure Fleet View</span>
        </div>
        <div>
            <button onclick="location.reload()" style="background:#333; color:#fff; border:1px solid #555; padding:8px 15px; cursor:pointer; border-radius:3px;">⟳ Refresh</button>
        </div>
    </div>

    <div class="grid" id="agent-grid">
        <div style="color:#666; padding:20px;">Loading fleet status...</div>
    </div>

    <script>
        // [SEC] Escape agent-controlled fields (hostname, ip, os_info) before
        // inserting into innerHTML. A compromised agent must not inject HTML/JS.
        function esc(value) {
            const div = document.createElement('div');
            div.textContent = (value === null || value === undefined) ? '' : String(value);
            return div.innerHTML;
        }

        async function loadFleet() {
            try {
                const res = await fetch('/api/agents');
                const agents = await res.json();
                const grid = document.getElementById('agent-grid');
                grid.innerHTML = '';

                if (agents.length === 0) {
                    grid.innerHTML = '<div style="grid-column: 1/-1; text-align:center; padding:40px; color:#555; border:2px dashed #333; border-radius:8px;">No Agents Connected.<br><span style="font-size:12px">Start a Daemon to see it here.</span></div>';
                    return;
                }

                agents.forEach(a => {
                    // Simple status logic: Last seen < 60s = Online
                    const lastSeenDate = new Date(a.last_seen + "Z"); // UTC assumption
                    const now = new Date();
                    const diffSeconds = (now - lastSeenDate) / 1000;
                    const isOnline = diffSeconds < 90; // 90s tolerance

                    const statusClass = isOnline ? 'online' : 'offline';

                    const card = document.createElement('div');
                    card.className = 'agent-card';
                    card.onclick = () => window.location.href = '/inspector/' + encodeURIComponent(a.uuid);

                    card.innerHTML = `
                        <div class="status-bar ${statusClass}"></div>
                        <div class="agent-name">${esc(a.hostname) || 'Unknown Host'}</div>
                        <div class="agent-ip">${esc(a.ip_address) || esc(a.uuid.substring(0,8))+'...'}</div>

                        <div style="font-size:11px; color:#aaa; min-height:30px;">
                            ${esc(a.os_info) || 'Linux'}
                        </div>

                        <div class="last-seen">
                            ${isOnline ? '🟢 Online' : '🔴 Offline'} (${new Date(a.last_seen).toLocaleTimeString()})
                        </div>
                    `;
                    grid.appendChild(card);
                });
            } catch (e) {
                console.error(e);
            }
        }
        loadFleet();
        setInterval(loadFleet, 10000); // Auto-refresh list every 10s
    </script>
</body>
</html>
"""


# ------------------------------------------------------------------------------
# DATA ADAPTERS (Logic Bridge)
# ------------------------------------------------------------------------------
class ObjectAdapter:
    def __init__(self, data):
        self._data = data

    def __getattr__(self, name):
        return self._data.get(name)


class TreeAdapter:
    def __init__(self, nodes_dict):
        self.nodes = {int(pid): ObjectAdapter(data) for pid, data in nodes_dict.items()}

    def get(self, pid):
        return self.nodes.get(int(pid))


# ------------------------------------------------------------------------------
# CONTROLLER CLASS
# ------------------------------------------------------------------------------
class WebController:
    def __init__(self, config, db_manager):
        self.config = config
        self.db = db_manager
        self.logger = logging.getLogger("WebCtrl")

        # Load Security
        priv_path = config['security']['private_key_path']
        if not os.path.exists(priv_path):
            self.logger.critical(f"Private Key missing: {priv_path}")
            raise FileNotFoundError("Private Key missing.")
        try:
            self.priv_key = load_private_key(priv_path)
            self.logger.info("Private Key loaded.")
        except Exception as e:
            self.logger.critical(f"Invalid Private Key: {e}")
            raise

        # [SEC] Dashboard authentication (HTTP Basic Auth). Disabled by default
        # so existing deployments keep working unchanged (no regression).
        auth_cfg = config['network'].get('auth', {}) or {}
        self.auth_enabled = bool(auth_cfg.get('enabled', False))
        self.auth_user = auth_cfg.get('username', 'admin')
        self.auth_hash = auth_cfg.get('password_hash', '') or ''
        if self.auth_enabled and not self.auth_hash:
            # Fail closed: enabled without a hash means nobody can authenticate.
            self.logger.warning(
                "[AUTH] enabled but no password_hash set; all requests will be "
                "rejected. Run tools/gen_password.py and set network.auth.password_hash."
            )

        # Setup Flask
        self.app = Flask(__name__)
        self._register_routes()
        # [SEC] Register the auth gate AFTER routes; it short-circuits any request.
        self.app.before_request(self._before_request)
        self.host = config['network'].get('bind_address', '0.0.0.0')
        self.port = config['network'].get('bind_port', 8080)

        # [SEC] Optional HTTPS. Disabled by default (plain HTTP, no regression).
        net_cfg = config['network']
        self.tls_enabled = bool(net_cfg.get('tls_enabled', False))
        # Cert/key paths default to the 'server' section for consistency.
        srv_cfg = config.get('server', {}) or {}
        self.ssl_cert = net_cfg.get('ssl_cert') or srv_cfg.get('ssl_cert', '/etc/sys-inspector/server_cert.pem')
        self.ssl_key = net_cfg.get('ssl_key') or srv_cfg.get('ssl_key', '/etc/sys-inspector/server_key.pem')

    def _before_request(self):
        """Flask hook: enforce Basic Auth before serving any route.

        Returns None when the request is authorized (Flask proceeds to the
        route), or a 401 Response otherwise. When auth is disabled this always
        returns None, preserving the original open behavior.
        """
        if not self.auth_enabled:
            return None
        auth = request.authorization
        if (auth and self.auth_hash and auth.username == self.auth_user
                and check_password_hash(self.auth_hash, auth.password or "")):
            return None
        resp = Response("Authentication required.", 401)
        resp.headers['WWW-Authenticate'] = 'Basic realm="Sys-Inspector"'
        return resp

    def _get_snapshot_data(self, uuid):
        """Fetch and adapt the latest snapshot for a specific UUID."""
        try:
            db_path = self.config['storage']['sqlite_path']
            # [FIX] Context manager prevents leak
            with closing(sqlite3.connect(db_path, timeout=5.0)) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT timestamp, json_blob FROM snapshots WHERE agent_uuid = ? ORDER BY id DESC LIMIT 1",
                    (uuid,)
                )
                row = cursor.fetchone()

                if not row: return None, None, None, "No data for this agent."

                # Decrypt
                blob_dict = json.loads(row['json_blob'])
                decrypted = decrypt_data(blob_dict, self.priv_key)

                if not decrypted: return None, None, None, "Decryption Failed."

                # Adapt for Report Renderer
                inventory = decrypted.get('static', {})
                inventory['generated'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row['timestamp']))

                dyn = decrypted.get('dynamic', {})
                ptree_raw = dyn.get('process_tree', {})
                nodes_dict = ptree_raw.get('nodes', ptree_raw) if isinstance(ptree_raw, dict) else {}

                return inventory, TreeAdapter(nodes_dict), row['timestamp'], None

        except Exception as e:
            return None, None, None, str(e)

    def _register_routes(self):

        # --- 1. FLEET DASHBOARD (ROOT) ---
        @self.app.route('/')
        def fleet_view():
            return render_template_string(FLEET_TEMPLATE)

        @self.app.route('/api/agents')
        def api_list_agents():
            """Returns JSON list of all known agents."""
            agents = self.db.get_agents()  # Uses the robust DB method
            # Convert row objects to dicts if needed
            return jsonify([dict(a) for a in agents])

        # --- 2. DEEP INSPECTOR (MICRO VIEW) ---
        @self.app.route('/inspector/<uuid>')
        def inspector_view(uuid):
            # [SEC] Reject malformed IDs before any HTML/JS interpolation
            if not SAFE_ID_PATTERN.match(uuid):
                return make_response("Invalid agent id.", 400)

            inv, tree, ts, err = self._get_snapshot_data(uuid)

            if err:
                return f"""
                <body style='background:#121212; color:#ccc; font-family:sans-serif; text-align:center; padding:50px;'>
                    <h3>Agent: {escape(uuid)}</h3>
                    <p style='color:#ff6b6b'>Status: {escape(err)}</p>
                    <a href='/' style='color:#0078d4'>&larr; Back to Fleet</a>
                </body>
                """

            try:
                # Render Blocks using shared logic
                os_html = render_os_block(inv.get('os', {}), inv.get('hw', {}))
                net_html = render_net_block(inv.get('net', {}))
                disk_html = render_disk_block(inv.get('storage', {}))
                mounts = inv.get('storage', {}).get('mounts', {})
                rows_html = render_process_rows(tree, mounts)

                # Inject JS: Define Context UUID and Auto-Start
                # [CRITICAL] We inject the specific API endpoint for THIS agent
                context_js = f"""
                    const AGENT_UUID = "{uuid}";
                    const API_ENDPOINT = "/api/agent/{uuid}/latest";

                    // Override the fetch URL in standard JS logic
                    window.fetch_orig = window.fetch;
                    window.fetch = async (url) => {{
                        if(url === '/live_update') url = API_ENDPOINT + '_fragment';
                        return window.fetch_orig(url);
                    }};

                    {JS_BLOCK}

                    window.onload = function() {{
                        // Add "Back to Fleet" button
                        const hdr = document.querySelector('.hdr');
                        if(hdr) {{
                            const btn = document.createElement('a');
                            btn.href = '/';
                            btn.innerHTML = '&larr; Fleet';
                            btn.style.cssText = 'position:absolute; top:10px; right:10px; color:#888; text-decoration:none; font-size:11px; border:1px solid #444; padding:2px 8px; border-radius:3px;';
                            document.body.appendChild(btn);
                        }}
                        startLiveMode();
                    }};
                """

                # Achados normalizados da captura, na mesma aba Findings do
                # relatorio estatico (o template exige os dois placeholders).
                findings = inv.get('findings', []) or []
                findings_html = render_findings_panel(findings)
                actionable = sum(1 for f in findings if f.get('severity') != 'Info')

                return HTML_TEMPLATE.format(
                    VERSION="0.90 (Live)",
                    HOSTNAME=escape(inv.get('os', {}).get('hostname', 'Unknown')),
                    TIMESTAMP=inv['generated'],
                    CSS_BLOCK=CSS_BASE,
                    JS_BLOCK=context_js,  # Uses the context-aware JS
                    LEGEND_HTML=LEGEND_HTML,
                    OS_CONTENT=os_html,
                    DISK_CONTENT=disk_html,
                    NET_CONTENT=net_html,
                    FINDINGS_CONTENT=findings_html,
                    FINDINGS_BADGE=(f"<span class='tab-count'>{actionable}</span>" if actionable else ""),
                    TABLE_ROWS=rows_html
                )
            except Exception as e:
                self.logger.error(f"Render Error: {e}")
                return f"Render Error: {escape(e)}"

        # --- 3. AGENT SPECIFIC API ---
        @self.app.route('/api/agent/<uuid>/latest_fragment')
        def api_agent_fragment(uuid):
            """AJAX: Returns only the Table Rows for the live update."""
            # [SEC] Same allowlist validation as inspector_view
            if not SAFE_ID_PATTERN.match(uuid):
                return make_response("", 400)

            inv, tree, _, err = self._get_snapshot_data(uuid)
            if err or not tree: return make_response("", 204)
            try:
                mounts = inv.get('storage', {}).get('mounts', {})
                return render_process_rows(tree, mounts)
            except: return make_response("", 500)

    def _build_ssl_context(self):
        """Return an (cert, key) tuple for HTTPS, or None for plain HTTP.

        When TLS is enabled and the configured cert/key are missing, a
        self-signed pair is generated automatically. If generation fails
        (e.g. non-writable path), logs the error and falls back to HTTP so the
        dashboard still comes up rather than crashing.
        """
        if not self.tls_enabled:
            return None
        try:
            from src.core.tls import ensure_self_signed_cert
            hostname = self.config.get('general', {}).get('hostname') or 'sys-inspector'
            generated = ensure_self_signed_cert(self.ssl_cert, self.ssl_key, common_name=hostname)
            if generated:
                self.logger.info(f"[WEB] Generated self-signed certificate at {self.ssl_cert}")
            return (self.ssl_cert, self.ssl_key)
        except Exception as e:
            self.logger.error(f"[WEB] TLS setup failed ({e}); falling back to HTTP.")
            return None

    def run(self):
        ssl_context = self._build_ssl_context()
        scheme = "https" if ssl_context else "http"
        self.logger.info(f"[WEB] Fleet Server starting at {scheme}://{self.host}:{self.port}")
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        try:
            self.app.run(host=self.host, port=self.port, debug=False,
                         use_reloader=False, threaded=True, ssl_context=ssl_context)
        except Exception as e:
            self.logger.critical(f"[WEB] Server crashed: {e}")
