# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/controllers/server_controller.py
# DESCRIPTION: Controller logic for 'Server' mode.
#              Acts as the Central Manager for multiple agents.
#              - GET /: Dashboard of Agents
#              - POST /upload: Ingestion API for Agent Data
#              - GET /agent/<uuid>: View specific Agent Snapshot
#
# OPTIONS:
#
# PARAMETERS:
#   db_handler: Instance of DatabaseHandler
#   config: Configuration dictionary
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.90.16
# ==============================================================================

import os
import json
import time
import threading
import logging
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Internal Modules
from src.exporters.html_report import generate_report
from src.collectors.process_tree import ProcessTree, ProcessNode
from src.core.crypto import load_private_key, decrypt_data


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP Server."""
    daemon_threads = True


class ServerHTTPHandler(BaseHTTPRequestHandler):
    """
    Handles API and Dashboard requests for the Server Mode.
    """

    def _set_headers(self, content_type="text/html", status=200):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def _rehydrate_tree(self, json_data):
        """
        Converts JSON 'processes' dict back into a ProcessTree object.
        Needed to view Agent reports on the Server.
        """
        tree = ProcessTree()
        raw_procs = json_data.get('processes', {})

        for pid, pdata in raw_procs.items():
            node = ProcessNode(
                int(pid),
                int(pdata.get('ppid', 0)),
                pdata.get('cmd', '?'),
                int(pdata.get('uid', 0)),
                pdata.get('prio', 120),
                pdata.get('loginuid', None)
            )
            for k, v in pdata.items():
                if k == 'open_files': v = set(v)
                if k == 'connections': v = set(v)
                if hasattr(node, k):
                    setattr(node, k, v)
            tree.nodes[int(pid)] = node
        return tree

    def do_GET(self):
        controller = self.server.controller

        if self.path == '/':
            # --- DASHBOARD ---
            self._serve_dashboard(controller.db)

        elif self.path.startswith('/agent/'):
            # --- VIEW AGENT SNAPSHOT ---
            agent_uuid = self.path.split('/')[-1]
            # Get latest snapshot for this agent
            snaps = controller.db.get_history(0, time.time(), agent_filter=agent_uuid)

            if snaps:
                # get_snapshot_details devolve o bundle cifrado; descriptografa.
                data = controller.decrypt(controller.db.get_snapshot_details(snaps[0]['id']))
                if data:
                    tree = self._rehydrate_tree(data)

                    # Generate HTML
                    tmp_filename = f"/tmp/sys_server_{threading.get_ident()}.html"
                    # Use version to get new Icons/CSS
                    generate_report(data, tree, tmp_filename, "0.61.00")

                    with open(tmp_filename, 'r', encoding='utf-8') as f:
                        html_content = f.read()

                    self._set_headers()
                    self.wfile.write(html_content.encode('utf-8'))

                    try: os.remove(tmp_filename)
                    except: pass
                    return

            self._set_headers(status=404)
            self.wfile.write(b"Agent not found or no data received yet.")

        else:
            self._set_headers(status=404)
            self.wfile.write(b"Not Found")

    def do_POST(self):
        # --- API INGESTION ---
        controller = self.server.controller

        if self.path == '/upload':
            try:
                content_len = int(self.headers.get('Content-Length', 0))
                post_body = self.rfile.read(content_len)
                data = json.loads(post_body)

                # Ingestao (minima): o agente envia o bundle cifrado, seu
                # agent_uuid e as metricas quentes. O protocolo completo de
                # ingestao distribuida (fila, ack, lote) e da Fase 2 (W6).
                agent_uuid = data.get('agent_uuid', 'remote') if isinstance(data, dict) else 'remote'
                bundle = data.get('bundle', data) if isinstance(data, dict) else data
                metrics = data.get('metrics', {}) if isinstance(data, dict) else {}
                success = controller.db.insert_snapshot(bundle, agent_uuid=agent_uuid, metrics=metrics)

                if success:
                    controller.logger.info(f"[API] Received Snapshot from {data.get('agent_uuid', 'unknown')}")
                    self._set_headers(status=201, content_type="application/json")
                    self.wfile.write(b'{"status": "received"}')
                else:
                    self._set_headers(status=500, content_type="application/json")
                    self.wfile.write(b'{"status": "db_error"}')
            except Exception as e:
                controller.logger.error(f"[API] Error: {e}")
                self._set_headers(status=400)
                self.wfile.write(f'{{"status": "error", "msg": "{str(e)}"}}'.encode())
        else:
            self._set_headers(status=404)

    def _serve_dashboard(self, db):
        """Renders the Server Manager Dashboard HTML."""
        # Envia a status line e os headers antes do corpo. Sem isto a resposta
        # sai sem cabecalho HTTP (o cliente ve conexao malformada / HTTP 000).
        self._set_headers()
        # Usa a tabela 'agents' (colunas em claro) via get_agents, em vez de
        # extrair campos com json_extract do blob, que agora esta cifrado.
        agents = db.get_agents()

        rows = ""
        for a in agents:
            uuid = a.get('uuid', '')
            host = a.get('hostname') or "Unknown Host"
            ip = a.get('ip_address') or "Unknown IP"
            seen = a.get('last_seen', '')

            # Status a partir da coluna 'status' e do last_seen (timeout 90s).
            try:
                last_ts = datetime.datetime.strptime(seen, "%Y-%m-%d %H:%M:%S")
                is_online = (datetime.datetime.now() - last_ts).total_seconds() < 90
            except Exception:
                is_online = str(a.get('status', '')).upper() == 'ONLINE'

            status_style = "color:#51cf66" if is_online else "color:#ff6b6b"
            status_text = "ONLINE" if is_online else "OFFLINE"
            border_style = "border-left: 4px solid #51cf66;" if is_online else "border-left: 4px solid #ff6b6b;"

            rows += f"""
            <tr style='background:#252526; border-bottom:1px solid #333; {border_style}'>
                <td>
                    <a href='/agent/{uuid}' style='color:#4ec9b0; font-size:1.1em; font-weight:bold; text-decoration:none;'>{host}</a>
                    <br><small style='color:#666; font-family:monospace'>{uuid}</small>
                </td>
                <td style='color:#ccc'>{ip}</td>
                <td style='color:#aaa'>{seen}</td>
                <td><span style='{status_style}; font-weight:bold; font-size:11px; border:1px solid; padding:2px 6px; border-radius:3px'>{status_text}</span></td>
                <td><a href='/agent/{uuid}' class='btn-view'>VIEW REPORT</a></td>
            </tr>"""

        html = f"""
        <html><head><title>Sys-Inspector Manager</title>
        <meta http-equiv="refresh" content="30">
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #1e1e1e; color: #eee; padding: 0; margin: 0; }}
            .header {{ background: #2d2d30; padding: 15px 30px; border-bottom: 2px solid #0078d4; display: flex; align-items: center; justify-content: space-between; }}
            h1 {{ margin: 0; font-weight: 300; letter-spacing: 1px; }}
            table {{ width: 90%; margin: 40px auto; border-collapse: separate; border-spacing: 0 10px; }}
            th {{ text-align: left; color: #777; text-transform: uppercase; font-size: 0.85em; padding: 0 15px 10px 15px; letter-spacing: 1px; }}
            td {{ padding: 15px; }}
            tr {{ transition: transform 0.2s; }}
            tr:hover {{ transform: scale(1.01); background: #2a2d2e !important; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }}
            .btn-view {{ background: #333; color: #fff; text-decoration: none; padding: 6px 12px; font-size: 10px; border-radius: 3px; border: 1px solid #555; transition:0.2s; }}
            .btn-view:hover {{ background: #0078d4; border-color: #0078d4; }}
        </style>
        </head><body>
        <div class="header">
            <h1>Sys-Inspector <span style="color:#0078d4; font-weight:bold">Manager</span></h1>
            <div style="font-size:0.9em; color:#aaa; font-weight:bold">{len(agents)} AGENTS</div>
        </div>
        <table>
            <thead><tr><th>Hostname / UUID</th><th>IP Address</th><th>Last Seen</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        </body></html>
        """
        self.wfile.write(html.encode('utf-8'))


class ServerController:
    """
    Orchestrates the Server Mode.
    """
    def __init__(self, config, db_handler, shutdown_event):
        self.config = config
        self.db = db_handler
        self.shutdown_event = shutdown_event
        self.logger = logging.getLogger("ServerCtrl")

        # Modelo unico cifrado: para renderizar o snapshot de um agente, o
        # server descriptografa com a chave privada local, se presente. Num
        # cenario zero-knowledge a chave pode nao existir aqui (o analista
        # descriptografa noutro ponto); nesse caso o view avisa.
        self.priv_key = None
        priv_path = config.get('security', {}).get('private_key_path', 'conf/private_key.pem')
        if os.path.exists(priv_path):
            try:
                self.priv_key = load_private_key(priv_path)
            except Exception as e:
                self.logger.error(f"[SECURITY] Failed to load Private Key: {e}")
        else:
            self.logger.warning("[SECURITY] Private Key not found; agent snapshots cannot be rendered here.")

    def decrypt(self, bundle):
        """Descriptografa um bundle cifrado; retorna dict em claro ou None."""
        if not self.priv_key or not bundle:
            return None
        try:
            return decrypt_data(bundle, self.priv_key)
        except Exception as e:
            self.logger.error(f"[SECURITY] Decryption failed: {e}")
            return None

    def run(self):
        """Starts the Server HTTP Daemon."""
        port = self.config['network']['bind_port']

        server = ThreadingHTTPServer(('0.0.0.0', port), ServerHTTPHandler)
        server.controller = self

        t_server = threading.Thread(target=server.serve_forever)
        t_server.daemon = True
        t_server.start()

        self.logger.info(f"[HTTP] Server Manager listening on port {port}")
        self.logger.info("[INFO] Dashboard available at http://localhost:" + str(port))

        try:
            while not self.shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.logger.info("[MODE] Stopping Server...")
            server.shutdown()
