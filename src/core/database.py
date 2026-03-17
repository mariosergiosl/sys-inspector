# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/database.py
# DESCRIPTION: Core Database Manager for Sys-Inspector v0.80
#              Handles SQLite persistence, Queue logic, and Retention Policy.
#
# FEATURES:
#   - Automatic Schema Creation (Agents + Snapshots).
#   - Count-based Retention (Circular Buffer logic).
#   - Storage of Encrypted Blobs (Zero-Knowledge at rest).
#   - Queue Management for Agent Mode (PENDING/SENT status).
#   - Compatibility with Legacy Controllers (status column).
#   - [FIX v0.90.02] Moved PRAGMA WAL to init only to reduce locks.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 0.90.02
# ==============================================================================

import sqlite3
import time
import os
import json
import logging
from contextlib import closing

DEFAULT_DB_PATH = "data/sys_inspector.db"
DEFAULT_RETENTION_COUNT = 100


class DatabaseManager:
    def __init__(self, db_path=None, max_snapshots=DEFAULT_RETENTION_COUNT):
        self.db_path = db_path if db_path else DEFAULT_DB_PATH
        self.max_snapshots = max_snapshots
        self.logger = logging.getLogger("DBManager")

        # Ensure data directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)

        self._init_db()

    def _get_conn(self):
        """Creates a database connection with Row factory enabled."""
        # [FIX v0.90.02] Removed PRAGMA from here to avoid re-locking WAL mode
        # Timeout helps with concurrency
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Creates the schema if it does not exist."""
        try:
            with closing(self._get_conn()) as conn:
                # [FIX v0.90.02] Set WAL mode ONCE during initialization
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")

                # 1. Agents Table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS agents (
                        uuid TEXT PRIMARY KEY,
                        hostname TEXT,
                        ip_address TEXT,
                        os_info TEXT,
                        status TEXT DEFAULT 'OFFLINE',
                        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # 2. Snapshots Table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_uuid TEXT NOT NULL,
                        timestamp REAL NOT NULL,

                        -- Hot Columns
                        cpu_avg REAL DEFAULT 0,
                        mem_used_mb INTEGER DEFAULT 0,
                        pids_count INTEGER DEFAULT 0,
                        alert_score INTEGER DEFAULT 0,
                        is_alert BOOLEAN DEFAULT 0,

                        -- Payload
                        json_blob TEXT NOT NULL,
                        synced BOOLEAN DEFAULT 0,

                        FOREIGN KEY(agent_uuid) REFERENCES agents(uuid)
                    )
                """)

                # 3. Indexes
                conn.execute("CREATE INDEX IF NOT EXISTS idx_snap_synced ON snapshots(synced)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_snap_agent_ts ON snapshots(agent_uuid, timestamp)")

                conn.commit()
        except Exception as e:
            self.logger.critical(f"Schema Initialization Failed: {e}")
            raise

    # --------------------------------------------------------------------------
    # WRITE OPERATIONS
    # --------------------------------------------------------------------------
    def insert_snapshot(self, encrypted_bundle, agent_uuid="local", metrics=None):
        if metrics is None: metrics = {}

        # Prepare JSON before lock
        blob_json = json.dumps(encrypted_bundle)

        try:
            with closing(self._get_conn()) as conn:
                # 1. Upsert Agent
                conn.execute("""
                    INSERT INTO agents (uuid, hostname, last_seen, status)
                    VALUES (?, ?, CURRENT_TIMESTAMP, 'ONLINE')
                    ON CONFLICT(uuid) DO UPDATE SET
                        last_seen=CURRENT_TIMESTAMP,
                        status='ONLINE'
                """, (agent_uuid, "unknown"))

                # 2. Insert Snapshot
                conn.execute("""
                    INSERT INTO snapshots (
                        agent_uuid, timestamp,
                        cpu_avg, mem_used_mb, pids_count, alert_score, is_alert,
                        json_blob, synced
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """, (
                    agent_uuid,
                    time.time(),
                    metrics.get('cpu', 0),
                    metrics.get('mem', 0),
                    metrics.get('pids', 0),
                    metrics.get('score', 0),
                    1 if metrics.get('score', 0) > 0 else 0,
                    blob_json
                ))

                # 3. Enforce Retention
                conn.execute("""
                    DELETE FROM snapshots
                    WHERE id IN (
                        SELECT id FROM snapshots
                        WHERE agent_uuid = ?
                        ORDER BY id DESC
                        LIMIT -1 OFFSET ?
                    )
                """, (agent_uuid, self.max_snapshots))

                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Insert Failed: {e}")
            return False

    def mark_as_synced(self, snapshot_ids):
        if not snapshot_ids: return
        try:
            with closing(self._get_conn()) as conn:
                placeholders = ','.join('?' * len(snapshot_ids))
                sql = "UPDATE snapshots SET synced=1 WHERE id IN ({placeholders})"
                conn.execute(sql, snapshot_ids)
                conn.commit()
        except Exception as e:
            self.logger.error(f"Mark Synced Failed: {e}")

    def update_agent_status(self, uuid, status, hostname=None, ip=None, os_info=None):
        try:
            with closing(self._get_conn()) as conn:
                sql = "UPDATE agents SET status=?, last_seen=CURRENT_TIMESTAMP"
                params = [status]

                if hostname:
                    sql += ", hostname=?"
                    params.append(hostname)
                if ip:
                    sql += ", ip_address=?"
                    params.append(ip)
                if os_info:
                    sql += ", os_info=?"
                    params.append(os_info)

                sql += " WHERE uuid=?"
                params.append(uuid)

                conn.execute(sql, params)
                conn.commit()
        except Exception as e:
            self.logger.error(f"Agent Update Failed: {e}")

    # --------------------------------------------------------------------------
    # READ OPERATIONS
    # --------------------------------------------------------------------------
    def get_pending_snapshots(self, limit=50):
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute("""
                    SELECT id, json_blob FROM snapshots
                    WHERE synced=0
                    ORDER BY id ASC LIMIT ?
                """, (limit,))
                return [{'id': r['id'], 'data': json.loads(r['json_blob'])} for r in cursor]
        except Exception as e:
            self.logger.error(f"Get Pending Failed: {e}")
            return []

    def get_snapshot_details(self, snap_id):
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute("SELECT json_blob FROM snapshots WHERE id = ?", (snap_id,))
                row = cursor.fetchone()
                return json.loads(row[0]) if row else None
        except Exception:
            return None

    def get_agents(self):
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC")
                return [dict(row) for row in cursor]
        except Exception as e:
            # Log error strictly to help debug permissions issues
            self.logger.error(f"Get Agents Failed: {e}")
            return []
