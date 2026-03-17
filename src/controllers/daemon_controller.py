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
# VERSION: 0.80.02 (Fix: Imports & Function Calls)
# ==============================================================================

import time
import logging
import threading
import json
import os
import uuid
import socket

# Imports from Core
from src.core.engine import SysInspectorEngine
# [FIXED] Importing the function directly, not a non-existent class
from src.collectors.system_inventory import collect_full_inventory
from src.core.database import DatabaseManager
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
        
        # Identity
        self.agent_uuid = self._get_uuid()
        
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
                time.sleep(5) # Backoff on error

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
        
        # 1. Dynamic Data (Process Tree)
        # Force aggregation in the process tree to finalize metrics
        engine.tree.aggregate_stats() 
        dynamic_data = {
            "process_tree": engine.tree.to_json(),
            "global_metrics": {
                "cpu_load": 0, 
                "threat_score": 0
            } 
        }
        
        # Calculate simplistic score from tree nodes
        total_score = 0
        pids_count = 0
        for pid, node in engine.tree.nodes.items():
            pids_count += 1
            if hasattr(node, 'anomaly_score'):
                total_score += node.anomaly_score
        
        dynamic_data['global_metrics']['threat_score'] = total_score
        
        # 2. Static Data
        # [FIXED] Calling the function directly
        static_data = collect_full_inventory()
        
        # Extract hostname from existing OS info
        hostname = static_data.get('os', {}).get('hostname', socket.gethostname())

        # D. Prepare Bundle
        timestamp = time.time()
        full_snapshot = {
            "meta": {
                "uuid": self.agent_uuid,
                "timestamp": timestamp,
                "type": "daemon_periodic",
                "cycle": cycle_id,
                "duration": self.capture_duration,
                "hostname": hostname
            },
            "static": static_data,
            "dynamic": dynamic_data
        }

        # Metrics for Hot Columns (SQL Searchable without decryption)
        metrics = {
            'cpu': 0, 
            'mem': static_data.get('memory', {}).get('used', 0),
            'pids': pids_count,
            'score': total_score
        }

        # E. Encrypt
        self.logger.debug(f"[CYCLE #{cycle_id}] Encrypting payload...")
        encrypted_bundle = encrypt_data(full_snapshot, self.pub_key)

        # F. Persist (Using v0.70 Database Manager)
        # Updates agent status to 'ONLINE' and inserts snapshot
        success = self.db.insert_snapshot(
            encrypted_bundle, 
            agent_uuid=self.agent_uuid, 
            metrics=metrics
        )

        if success:
            self.logger.info(f"[CYCLE #{cycle_id}] Snapshot persisted successfully (PIDs: {metrics['pids']}).")
        else:
            self.logger.error(f"[CYCLE #{cycle_id}] Database Insert Failed.")

    def _get_uuid(self):
        """
        Retrieves or generates a unique Agent ID. 
        Persists it to .agent_id file to maintain identity across restarts.
        """
        id_file = ".agent_id"
        if os.path.exists(id_file):
            try:
                with open(id_file, 'r') as f:
                    return f.read().strip()
            except:
                pass
        
        # Generate new if not found
        new_id = str(uuid.uuid4())
        try:
            with open(id_file, 'w') as f:
                f.write(new_id)
        except Exception as e:
            self.logger.warning(f"Could not save .agent_id: {e}")
            
        return new_id
