# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/storage/sqlite_provider.py
# DESCRIPTION: SQLite implementation of the StorageProvider interface.
#              Stores system snapshots as JSON blobs for flexibility.
#
# OPTIONS:
#
# PARAMETERS:
#
# AUTHOR: Mario Luz (Refactoring Sys-Inspector Project)
# CHANGELOG:
# VERSION: 0.50.56
# ==============================================================================

import sqlite3
import json
import os
import time
from contextlib import closing
from src.storage.interface import StorageProvider

class SQLiteProvider(StorageProvider):
    """
    Implements persistence using a local SQLite database.
    Designed for the 'Agent' and 'Live' modes where local caching is required.
    """

    def __init__(self, db_path, retention_days=10):
        """
        Initialize the provider config.
        
        Args:
            db_path (str): Path to the .db file.
            retention_days (int): Max age of records in days.
        """
        self.db_path = db_path
        self.retention_days = retention_days
        self.conn = None

    def connect(self):
        """
        Connects to SQLite and ensures the schema exists.
        Enables WAL mode for better concurrency.
        """
        try:
            # Ensure directory exists
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)

            self.conn = sqlite3.connect(self.db_path)
            
            # Optimization: Enable Write-Ahead Logging (WAL)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            
            self._init_schema()
            return True
        except sqlite3.Error as e:
            print(f"[ERROR] SQLite Connection Failed: {e}")
            return False

    def _init_schema(self):
        """Creates the necessary tables if they don't exist."""
        schema = """
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            host TEXT NOT NULL,
            data JSON NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ts ON snapshots(timestamp);
        """
        with closing(self.conn.cursor()) as cursor:
            cursor.executescript(schema)
            self.conn.commit()

    def save_snapshot(self, snapshot_data):
        """
        Saves the snapshot dictionary as a JSON string.
        Triggers retention cleanup.
        """
        if not self.conn:
            print("[ERROR] Database not connected.")
            return False

        try:
            ts = time.time()
            host = snapshot_data.get('os', {}).get('hostname', 'unknown')
            json_data = json.dumps(snapshot_data)

            with closing(self.conn.cursor()) as cursor:
                cursor.execute(
                    "INSERT INTO snapshots (timestamp, host, data) VALUES (?, ?, ?)",
                    (ts, host, json_data)
                )
                self.conn.commit()
            
            # Trigger cleanup (could be async in future)
            self._cleanup_old_records()
            return True
        except sqlite3.Error as e:
            print(f"[ERROR] Failed to save snapshot: {e}")
            return False

    def get_history(self, start_ts, end_ts):
        """Retrieves snapshots between two timestamps."""
        if not self.conn:
            return []

        results = []
        try:
            query = "SELECT data FROM snapshots WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC"
            with closing(self.conn.cursor()) as cursor:
                cursor.execute(query, (start_ts, end_ts))
                rows = cursor.fetchall()
                for row in rows:
                    results.append(json.loads(row[0]))
        except sqlite3.Error as e:
            print(f"[ERROR] Failed to fetch history: {e}")
        
        return results

    def _cleanup_old_records(self):
        """Deletes records older than retention_days."""
        try:
            cutoff = time.time() - (self.retention_days * 86400)
            with closing(self.conn.cursor()) as cursor:
                cursor.execute("DELETE FROM snapshots WHERE timestamp < ?", (cutoff,))
                self.conn.commit()
        except sqlite3.Error:
            pass

    def close(self):
        """Closes the connection safely."""
        if self.conn:
            self.conn.close()
            self.conn = None