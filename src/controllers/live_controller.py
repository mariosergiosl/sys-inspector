# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/controllers/live_controller.py
# DESCRIPTION: Controller logic for 'Live' mode.
#              Runs a local Web Server and a background Collection Loop.
#              Serves AJAX fragments for real-time UI updates without page reload.
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
import time
import threading
import logging
# import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Internal Modules
from src.core.engine import SysInspectorEngine
from src.collectors.system_inventory import collect_full_inventory
from src.collectors.manager import summarize_metrics, collect_findings
from src.core.findings import summarize_by_severity
from src.exporters.html_report import generate_report, generate_table_fragment
from src.collectors.process_tree import ProcessTree, ProcessNode
from src.core.crypto import (load_public_key, load_private_key,
                             encrypt_data, decrypt_data)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP Server for non-blocking handling."""
    daemon_threads = True


class LiveHTTPHandler(BaseHTTPRequestHandler):
    """
    Specialized Handler for Live Mode.
    Only handles Dashboard (/) and AJAX Data (/live_update).
    """

    def _set_headers(self, content_type="text/html", status=200):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def _rehydrate_tree(self, json_data):
        """
        Converts JSON 'processes' dict back into a ProcessTree object.
        Required because html_report renders from Objects, not Dicts.
        """
        tree = ProcessTree()
        raw_procs = json_data.get('processes', {})

        for pid, pdata in raw_procs.items():
            # Create Node with mandatory fields
            node = ProcessNode(
                int(pid),
                int(pdata.get('ppid', 0)),
                pdata.get('cmd', '?'),
                int(pdata.get('uid', 0)),
                pdata.get('prio', 120),
                pdata.get('loginuid', None)
            )
            # Bulk update attributes
            for k, v in pdata.items():
                if k == 'open_files': v = set(v)
                if k == 'connections': v = set(v)
                if hasattr(node, k):
                    setattr(node, k, v)

            tree.nodes[int(pid)] = node
        return tree

    def do_GET(self):
        controller = self.server.controller

        # --- AJAX ENDPOINT (No Page Refresh) ---
        if self.path == '/live_update':
            # Get latest snapshot
            history = controller.db.get_history(0, time.time())
            if history:
                latest_id = history[0]['id']
                # get_snapshot_details devolve o bundle cifrado; descriptografa.
                full_data = controller.decrypt(controller.db.get_snapshot_details(latest_id))
                if full_data:
                    tree = self._rehydrate_tree(full_data)
                    html_fragment = generate_table_fragment(full_data, tree)

                    self._set_headers(content_type="text/plain")
                    self.wfile.write(html_fragment.encode('utf-8'))
                    return

            self._set_headers(status=204)  # No Content yet
            return

        # --- LANDING PAGE ---
        if self.path == '/':
            snap = controller.db.get_history(0, time.time())
            if snap:
                data = controller.decrypt(controller.db.get_snapshot_details(snap[0]['id']))
            if snap and data:
                tree = self._rehydrate_tree(data)

                # Generate Full HTML to Temp
                tmp_filename = f"/tmp/sys_live_{threading.get_ident()}.html"
                generate_report(data, tree, tmp_filename, "0.61.00")

                with open(tmp_filename, 'r', encoding='utf-8') as f:
                    html_content = f.read()

                # Inject JS Auto-Start for Live Mode
                injection = """
                <script>
                    document.addEventListener('DOMContentLoaded', function() {
                        startLiveMode();
                    });
                </script>
                """
                html_content = html_content.replace('<body>', f'<body>{injection}')

                self._set_headers()
                self.wfile.write(html_content.encode('utf-8'))
                try: os.remove(tmp_filename)
                except: pass
            else:
                self._set_headers()
                self.wfile.write(b"<h1>Sys-Inspector Initializing...</h1><script>setTimeout(()=>location.reload(), 3000)</script>")
        else:
            self._set_headers(status=404)
            self.wfile.write(b"Not Found")


class LiveController:
    """
    Orchestrates the Live Dashboard Mode.
    """
    def __init__(self, config, db_handler, shutdown_event):
        self.config = config
        self.db = db_handler
        self.shutdown_event = shutdown_event
        self.engine = SysInspectorEngine(config)
        self.logger = logging.getLogger("LiveCtrl")
        self.update_count = 0

        # Modelo unico: live tambem cifra (custo desprezivel, sigilo forense).
        # Carrega a chave publica para cifrar na coleta e a privada para
        # descriptografar ao renderizar o dashboard local.
        self.pub_key = None
        self.priv_key = None
        sec = config.get('security', {})
        try:
            self.pub_key = load_public_key(sec.get('public_key_path', 'conf/public_key.pem'))
        except Exception as e:
            self.logger.critical(f"[SECURITY] Failed to load Public Key: {e}")
            raise
        priv_path = sec.get('private_key_path', 'conf/private_key.pem')
        if os.path.exists(priv_path):
            try:
                self.priv_key = load_private_key(priv_path)
            except Exception as e:
                self.logger.error(f"[SECURITY] Failed to load Private Key: {e}")
        else:
            self.logger.warning("[SECURITY] Private Key not found; live dashboard cannot render until it exists.")

    def decrypt(self, bundle):
        """
        Descriptografa um bundle armazenado (get_snapshot_details retorna o dado
        cifrado). Retorna o dict em claro ou None se nao houver chave/falhar.
        """
        if not self.priv_key or not bundle:
            return None
        try:
            return decrypt_data(bundle, self.priv_key)
        except Exception as e:
            self.logger.error(f"[SECURITY] Decryption failed: {e}")
            return None

    def _collection_loop(self):
        """Background thread to capture data."""
        interval = self.config['collection']['interval']
        self.logger.info(f"[CORE] Starting Collection Loop (Interval: {interval}s)")

        while not self.shutdown_event.is_set():
            start_ts = time.time()
            try:
                # 1. Capture (Short duration for responsiveness, e.g., 5s fixed or dynamic)
                self.engine.run_snapshot(duration=5, output_file=None)

                # 2. Package (modelo unico: processos no topo em 'processes')
                full_inv = collect_full_inventory()
                full_inv['processes'] = self.engine.tree.to_json()
                full_inv['agent_uuid'] = self.db.agent_id
                full_inv['mode'] = 'live'

                # Achados estaticos (persistencia), mesmo conjunto dos demais modos.
                findings = collect_findings()
                full_inv['findings'] = [f.to_dict() for f in findings]
                full_inv['findings_summary'] = summarize_by_severity(findings)

                # 3. Encrypt + Save (cifrado como os demais modos, com as
                # colunas quentes preenchidas via helper compartilhado).
                metrics = summarize_metrics(full_inv['processes'])
                bundle = encrypt_data(full_inv, self.pub_key)
                if self.db.insert_snapshot(bundle, agent_uuid=self.db.agent_id, metrics=metrics):
                    self.update_count += 1
                    self.logger.info(f"[CORE] Snapshot {self.update_count} persisted.")
            except Exception as e:
                self.logger.error(f"[CORE] Collection Error: {e}")

            # Sleep remainder of interval
            elapsed = time.time() - start_ts
            sleep_time = max(1, interval - elapsed)

            # Check shutdown frequently during sleep
            for _ in range(int(sleep_time)):
                if self.shutdown_event.is_set(): break
                time.sleep(1)

    def run(self):
        """Starts Web Server and Collection Loop."""
        port = self.config['network']['bind_port']

        # 1. Start HTTP Server
        server = ThreadingHTTPServer(('0.0.0.0', port), LiveHTTPHandler)
        server.controller = self  # Inject reference to self

        t_server = threading.Thread(target=server.serve_forever)
        t_server.daemon = True
        t_server.start()
        self.logger.info(f"[HTTP] Live Dashboard started at http://0.0.0.0:{port}")

        # 2. Start Collector (Blocking or Threaded? Threaded allows clean exit via main)
        t_col = threading.Thread(target=self._collection_loop)
        t_col.daemon = True
        t_col.start()

        # 3. Block Main Thread until Shutdown
        try:
            while not self.shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.logger.info("[MODE] Stopping Live Server...")
            server.shutdown()
