# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/controllers/daemon_controller.py
# DESCRIPTION: Continuous Data Collector (Daemon Mode) for Sys-Inspector v0.80.
#              Operates in a Loop: Capture -> Encrypt -> Persist -> Sleep.
#              Acts as the Universal Local Collector.
#
# FEATURES:
#   - Persistent Engine Handling (Reuses eBPF probes).
#   - Secure Storage (Async Encryption).
#   - Configurable Duty Cycle.
#   - Network Aware (Captures IPs/Hostname for Agent ID).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.90.16
# ==============================================================================

import time
import logging
# import threading
# import json

# Imports from Core
from src.core.engine import SysInspectorEngine
# [FIXED] Importing the function directly, not a non-existent class
from src.collectors.system_inventory import collect_full_inventory
from src.collectors.manager import summarize_metrics, collect_findings
from src.core.findings import summarize_by_severity
# from src.core.database import DatabaseManager
from src.core.crypto import load_public_key, encrypt_data


class DaemonController:
    def __init__(self, config, db_manager, shutdown_event):
        """
        Initialize the Daemon Controller.

        Args:
            config (dict): Configuration dictionary.
            db_manager (DatabaseManager): Initialized DB handler.
            shutdown_event (threading.Event): Signal for graceful shutdown.
        """
        self.config = config
        self.db = db_manager
        self.shutdown_event = shutdown_event
        self.logger = logging.getLogger("DaemonCtrl")

        # Identity (unificada: o mesmo agent_id do DatabaseManager, usado por
        # todos os modos, persistido ao lado do banco).
        self.agent_uuid = db_manager.agent_id

        # Load Security Keys
        try:
            self.pub_key = load_public_key(config['security']['public_key_path'])
            self.logger.info("Public Key loaded successfully.")
        except Exception as e:
            self.logger.critical(f"Failed to load Public Key: {e}")
            raise

        # Configuration - Duty Cycle
        # Default: Capture for 15s, Sleep for 15s (50% Duty Cycle)
        self.interval = config['daemon'].get('interval', 15)
        self.capture_duration = config['daemon'].get('capture_duration', 15)

    def run(self):
        """
        Main Execution Loop.
        Initializes the Engine ONCE and toggles collection cyclically.
        """
        self.logger.info(f"[DAEMON] Starting Universal Collector (v0.80). Agent ID: {self.agent_uuid}")
        self.logger.info(f"[DAEMON] Cycle Config: Capture={self.capture_duration}s | Sleep={self.interval}s")

        # 1. Initialize Engine ONCE to avoid recompilation overhead
        try:
            # Instantiating the correct class name
            engine = SysInspectorEngine(self.config)
            self.logger.info("[CORE] eBPF Engine initialized/compiled.")
        except Exception as e:
            self.logger.critical(f"eBPF Engine Init Failed: {e}")
            return

        cycle_count = 0

        # 2. Main Loop
        while not self.shutdown_event.is_set():
            cycle_count += 1

            try:
                # Delegate collection logic, passing the persistent engine
                self.collect_and_store(engine, cycle_count)
            except Exception as e:
                self.logger.error(f"[CYCLE #{cycle_count}] Critical Failure: {e}", exc_info=True)
                time.sleep(5)  # Backoff on error

            # 3. Sleep Interval (Idle Time)
            if not self.shutdown_event.is_set():
                self.logger.info(f"[WAIT] Sleeping for {self.interval}s...")
                self.shutdown_event.wait(self.interval)

        # Cleanup on exit
        # engine.cleanup()  # on future
        self.logger.info("[DAEMON] Shutdown complete.")

    def collect_and_store(self, engine, cycle_id):
        """
        Performs a single capture cycle using the existing engine instance.
        """
        self.logger.info(f"[CYCLE #{cycle_id}] Starting Capture Phase ({self.capture_duration}s)...")

        # A. Start eBPF Polling
        engine.start()

        # Wait for capture duration (responsive sleep)
        elapsed = 0
        while elapsed < self.capture_duration:
            if self.shutdown_event.is_set():
                break
            time.sleep(1)
            elapsed += 1

        # B. Stop eBPF Polling
        engine.stop()

        if self.shutdown_event.is_set():
            return

        # C. Retrieve Data
        # Finaliza a agregacao da arvore (tags, scores).
        engine.tree.aggregate_stats()

        # Modelo unico de captura: mesmo shape do snapshot e do live, com os
        # processos no topo em 'processes', para o renderizador reidratar sem
        # precisar conhecer formatos diferentes por modo.
        full_data = collect_full_inventory()
        full_data['processes'] = engine.tree.to_json()
        full_data['capture_duration'] = self.capture_duration
        full_data['mode'] = 'daemon'
        full_data['agent_uuid'] = self.agent_uuid
        full_data['cycle'] = cycle_id

        # Achados estaticos (persistencia), mesmo conjunto dos demais modos.
        findings = collect_findings()
        full_data['findings'] = [f.to_dict() for f in findings]
        full_data['findings_summary'] = summarize_by_severity(findings)

        # D. Metricas quentes (mesmo helper compartilhado do snapshot).
        metrics = summarize_metrics(full_data['processes'])

        # E. Encrypt
        self.logger.debug(f"[CYCLE #{cycle_id}] Encrypting payload...")
        encrypted_bundle = encrypt_data(full_data, self.pub_key)

        # F. Persist (DatabaseManager): atualiza status do agente para ONLINE e
        # insere o snapshot com as colunas quentes.
        success = self.db.insert_snapshot(
            encrypted_bundle,
            agent_uuid=self.agent_uuid,
            metrics=metrics
        )

        if success:
            self.logger.info(f"[CYCLE #{cycle_id}] Snapshot persisted successfully (PIDs: {metrics['pids']}).")
        else:
            self.logger.error(f"[CYCLE #{cycle_id}] Database Insert Failed.")
