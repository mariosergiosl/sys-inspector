# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/storage/db_handler.py
# DESCRIPTION: Advanced SQLite Handler for Architecture.
#              Handles Hybrid Schema (JSON + Metrics), WAL Mode,
#              Store-and-Forward logic, and FIFO Retention Policy.
#
# FEATURES:
#   - Auto-Identity: Manages .agent_id persistence
#   - Hybrid Storage: Extracts metrics for fast querying, keeps JSON for details
#   - Concurrency: PRAGMA journal_mode=WAL enabled by default
#   - Retention: Deletes old records when DB exceeds size limit (MB)
#
# OPTIONS:
#
# PARAMETERS:
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 0.61.00
# ==============================================================================

import sqlite3
import json
import os
import time
import uuid
import logging
from contextlib import closing
from src.storage.interface import StorageProvider


class DatabaseHandler(StorageProvider):
    """
    Central Persistence Handler.
    Used by:
      - Snapshot Mode (Single Write)
      - Daemon Mode (Buffer Write + Mark Synced)
      - Server Mode (Read/Write from multiple agents)
    """

    def __init__(self, config):
        """
        Args:
            config (dict): Full configuration dictionary.
        """
        self.config = config
        self.db_path = config['storage']['sqlite_path']

        # Retention limit in Bytes (Default: 20MB for Client, 100MB for Server)
        # We read from config or fallback
        mode = config['general'].get('mode', 'snapshot')
        default_limit = 100 * 1024 * 1024 if mode == 'server' else 20 * 1024 * 1024
        self.size_limit = config['storage'].get('db_size_limit_bytes', default_limit)

        self.conn = None
        self.agent_id = self._get_or_create_agent_id()

    def _get_or_create_agent_id(self):
        """
        Retrieves the persistent Agent UUID.
        If '.agent_id' does not exist, generates a new UUID v4 and saves it.
        This ensures the Agent ID survives reboots/updates.
        """
        # Determine path (same dir as DB or /etc/sys-inspector/ if possible)
        # For simplicity/permissions, we store alongside the DB or local dir
        base_dir = os.path.dirname(os.path.abspath(self.db_path))
        id_file = os.path.join(base_dir, ".agent_id")

        if os.path.exists(id_file):
            try:
                with open(id_file, 'r') as f:
                    uid = f.read().strip()
                    if len(uid) > 10:  # Simple validation
                        return uid
            except Exception as e:
                logging.error(f"[DB] Failed to read agent_id: {e}")

        # Generate New
        new_uid = str(uuid.uuid4())
        try:
            if not os.path.exists(base_dir):
                os.makedirs(base_dir, exist_ok=True)
            with open(id_file, 'w') as f:
                f.write(new_uid)
            logging.info(f"[DB] Generated new Agent ID: {new_uid}")
        except Exception as e:
            logging.error(f"[DB] Could not save agent_id file: {e}")
            # Fallback to volatile UUID if filesystem is read-only
            return new_uid

        return new_uid

    def connect(self):
        """
        Establishes SQLite connection with WAL mode and Hybrid Schema.
        """
        try:
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)

            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

            # Performance & Concurrency Settings
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            self.conn.execute("PRAGMA foreign_keys=ON;")

            self._init_schema()
            return True
        except sqlite3.Error as e:
            logging.error(f"[DB] Connection Failed: {e}")
            return False

    def _init_schema(self):
        """
        Defines the Hybrid Schema:
        - agents: Registry of machines (Server view).
        - snapshots: Historical data with extracted columns for fast graphs.
        """
        agents_table = """
        CREATE TABLE IF NOT EXISTS agents (
            uuid TEXT PRIMARY KEY,
            hostname TEXT,
            ip_address TEXT,
            os_info TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """

        snapshots_table = """
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_uuid TEXT NOT NULL,
            timestamp REAL NOT NULL,

            -- Hot Columns (Extracted for Performance/Graphs)
            cpu_avg REAL DEFAULT 0,
            mem_used_mb INTEGER DEFAULT 0,
            pids_count INTEGER DEFAULT 0,
            alert_score INTEGER DEFAULT 0,
            is_alert BOOLEAN DEFAULT 0,

            -- Payload (Cold Storage)
            json_blob TEXT NOT NULL,

            -- Sync State (For Store-and-Forward)
            synced BOOLEAN DEFAULT 0,

            FOREIGN KEY(agent_uuid) REFERENCES agents(uuid)
        );
        """

        indexes = """
        CREATE INDEX IF NOT EXISTS idx_snap_agent_ts ON snapshots(agent_uuid, timestamp);
        CREATE INDEX IF NOT EXISTS idx_snap_synced ON snapshots(synced);
        """

        with closing(self.conn.cursor()) as cursor:
            cursor.execute(agents_table)
            cursor.execute(snapshots_table)
            cursor.executescript(indexes)
            self.conn.commit()

    def _extract_metrics(self, data):
        """
        Parses the JSON dictionary to extract 'Hot Columns' for the DB.
        """
        metrics = {
            'cpu_avg': 0.0,
            'mem_used_mb': 0,
            'pids_count': 0,
            'alert_score': 0,
            'is_alert': False
        }

        try:
            # 1. Hardware / OS Metrics
            if 'hw' in data:
                # Assuming hw.mem_mb is available, but usage usually comes from summing processes or 'free' command
                # Here we sum up RSS from processes if available, or just fallback
                pass

            # 2. Process Tree Metrics
            processes = data.get('processes', {})
            metrics['pids_count'] = len(processes)

            total_cpu = 0.0
            total_mem_kb = 0
            max_score = 0

            for pid, pdata in processes.items():
                total_cpu += pdata.get('cpu_usage_pct', 0)
                total_mem_kb += pdata.get('rss', 0)

                # Check Anomaly Score
                score = pdata.get('anomaly_score', 0)
                if score > max_score:
                    max_score = score

            metrics['cpu_avg'] = total_cpu  # Sum of all cores usage (can be > 100%)
            metrics['mem_used_mb'] = int(total_mem_kb / 1024)
            metrics['alert_score'] = max_score
            metrics['is_alert'] = True if max_score > 0 else False

        except Exception as e:
            logging.warning(f"[DB] Metric extraction partial failure: {e}")

        return metrics

    def save_snapshot(self, snapshot_data):
        """
        Saves a snapshot.
        If running as Client/Daemon, uses self.agent_id.
        If running as Server, expects agent_uuid inside snapshot_data (passed from API).
        """
        if not self.conn: return False

        try:
            # Determine Identity
            # If we are the generator, we put our ID. If we are server receiving, we trust the data.
            agent_uuid = snapshot_data.get('agent_uuid', self.agent_id)
            host = snapshot_data.get('os', {}).get('hostname', 'unknown')
            ip = "127.0.0.1"  # Placeholder, improved in 'net' section

            # Update Agent Registry (Upsert logic)
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("""
                    INSERT INTO agents (uuid, hostname, ip_address, last_seen)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(uuid) DO UPDATE SET
                        hostname=excluded.hostname,
                        last_seen=CURRENT_TIMESTAMP
                """, (agent_uuid, host, ip))

            # Prepare Snapshot Data
            ts = time.time()
            metrics = self._extract_metrics(snapshot_data)
            json_blob = json.dumps(snapshot_data)

            # Insert Snapshot
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("""
                    INSERT INTO snapshots
                    (agent_uuid, timestamp, cpu_avg, mem_used_mb, pids_count, alert_score, is_alert, json_blob, synced)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """, (
                    agent_uuid, ts,
                    metrics['cpu_avg'], metrics['mem_used_mb'], metrics['pids_count'],
                    metrics['alert_score'], metrics['is_alert'],
                    json_blob
                ))
                self.conn.commit()

            # Enforce Retention Policy
            self._enforce_retention()
            return True

        except sqlite3.Error as e:
            logging.error(f"[DB] Save Snapshot Failed: {e}")
            return False

    def _enforce_retention(self):
        """
        FIFO Retention based on DB File Size.
        Deletes oldest records if file exceeds size_limit.
        """
        try:
            if not os.path.exists(self.db_path): return

            current_size = os.path.getsize(self.db_path)
            if current_size > self.size_limit:
                logging.info(f"[DB] Size limit reached ({current_size/1024/1024:.2f}MB). Pruning...")

                # Pruning Strategy: Delete oldest 10% or fixed amount
                # We simply delete the oldest 50 records to be safe and fast
                with closing(self.conn.cursor()) as cursor:
                    cursor.execute("""
                        DELETE FROM snapshots
                        WHERE id IN (
                            SELECT id FROM snapshots ORDER BY timestamp ASC LIMIT 50
                        )
                    """)
                    self.conn.commit()

                    # Optional: Incremental Vacuum to release pages back to OS
                    # cursor.execute("PRAGMA incremental_vacuum(100);")
        except Exception as e:
            logging.error(f"[DB] Retention failed: {e}")

    # --- Methods for Daemon (Store-and-Forward) ---

    def get_pending_snapshots(self, limit=10):
        """Returns list of snapshots that haven't been synced to server."""
        if not self.conn: return []
        try:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("""
                    SELECT id, json_blob FROM snapshots
                    WHERE synced = 0
                    ORDER BY timestamp ASC LIMIT ?
                """, (limit,))
                return cursor.fetchall()  # Returns [(id, blob), ...]
        except Exception:
            return []

    def mark_as_synced(self, snapshot_ids):
        """Marks a list of IDs as synced."""
        if not self.conn or not snapshot_ids: return
        try:
            with closing(self.conn.cursor()) as cursor:
                placeholders = ','.join('?' for _ in snapshot_ids)
                sql = f"UPDATE snapshots SET synced = 1 WHERE id IN ({placeholders})"
                cursor.execute(sql, tuple(snapshot_ids))
                self.conn.commit()
        except Exception as e:
            logging.error(f"[DB] Mark Synced Failed: {e}")

    # --- Methods for Server/Viewer ---

    def get_history(self, start_ts, end_ts, agent_filter=None):
        """Retrieves lightweight history list (metrics only) for Timeline."""
        if not self.conn: return []
        try:
            sql = """
                SELECT id, timestamp, agent_uuid, cpu_avg, mem_used_mb, alert_score, is_alert
                FROM snapshots
                WHERE timestamp BETWEEN ? AND ?
            """
            params = [start_ts, end_ts]

            if agent_filter:
                sql += " AND agent_uuid = ?"
                params.append(agent_filter)

            sql += " ORDER BY timestamp DESC"

            with closing(self.conn.cursor()) as cursor:
                cursor.execute(sql, params)
                cols = ['id', 'timestamp', 'agent_uuid', 'cpu_avg', 'mem_used_mb', 'alert_score', 'is_alert']
                results = [dict(zip(cols, row)) for row in cursor.fetchall()]
                return results
        except Exception as e:
            logging.error(f"[DB] Get History Failed: {e}")
            return []

    def get_snapshot_details(self, snap_id):
        """Retrieves full JSON blob for a specific ID."""
        if not self.conn: return None
        try:
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("SELECT json_blob FROM snapshots WHERE id = ?", (snap_id,))
                row = cursor.fetchone()
                return json.loads(row[0]) if row else None
        except Exception:
            return None

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
