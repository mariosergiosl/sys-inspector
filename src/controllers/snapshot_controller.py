# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/controllers/snapshot_controller.py
# DESCRIPTION: Controller logic for 'Snapshot' mode (v0.70).
#              Orchestrates the secure capture workflow:
#              1. Collect (via Manager) -> Dict
#              2. Encrypt (via Crypto) -> Blob
#              3. Persist (via DB) -> SQLite
#              4. Decrypt (if Private Key exists) -> Rehydrate -> HTML Report
#
#              UPDATED v0.70.03:
#              - FIX: Added .get() method to PseudoTree to prevent crash
#                     during badge rendering in complex process trees.
#              - MAINTAINED: Full rehydration and crypto logic.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 0.70.03
# ==============================================================================

import os
# import time
import socket
import datetime
import logging
# import json

# Internal Modules
from src.collectors.manager import CollectionManager
from src.exporters.html_report import generate_report
from src.collectors.process_tree import ProcessNode  # Needed for rehydration

# v0.70 Security Modules
from src.core.crypto import load_public_key, load_private_key, encrypt_data, decrypt_data


class SnapshotController:
    """
    Manages the lifecycle of a single forensic snapshot capture (Secure Mode).
    """

    def __init__(self, config, db_handler):
        self.config = config
        self.db = db_handler  # Expects src.core.database.DatabaseManager interface
        self.logger = logging.getLogger("SnapshotCtrl")

        # Load Keys Paths from Config
        self.pub_key_path = config.get('security', {}).get('public_key_path', 'conf/public_key.pem')
        self.priv_key_path = config.get('security', {}).get('private_key_path', 'conf/private_key.pem')

    def _rehydrate_tree(self, processes_dict):
        """
        Converts the JSON Dictionary back into a Pseudo-ProcessTree object structure.
        Crucial for compatibility with the existing html_report.py.
        """
        class PseudoTree:
            def __init__(self):
                self.nodes = {}
                self.to_json = lambda: processes_dict  # Mock to_json if needed

            def get(self, pid):
                """[v0.70.03 FIX] Returns node from internal dict."""
                return self.nodes.get(pid)

        tree = PseudoTree()

        # 1. Create Nodes
        for pid, p_data in processes_dict.items():
            # Create a dummy node with attributes from dict
            node = ProcessNode(int(pid), 0, "", 0)  # Init with defaults
            node.__dict__.update(p_data)  # Inject all dict data into object

            # Fix Types (Sets/Lists) that JSON flattened
            if isinstance(node.open_files, list): node.open_files = set(node.open_files)
            if isinstance(node.connections, list): node.connections = set(node.connections)

            # Handle tags_accumulated safely
            # Since to_json removes it, we recreate it from context_tags (which is persisted)
            if hasattr(node, 'tags_accumulated') and isinstance(node.tags_accumulated, list):
                node.tags_accumulated = set(node.tags_accumulated)
            elif not hasattr(node, 'tags_accumulated'):
                # Fallback: Populate set from the list version
                node.tags_accumulated = set(getattr(node, 'context_tags', []))

            tree.nodes[int(pid)] = node

        # 2. Re-link Children (for tree traversal in report)
        for pid, node in tree.nodes.items():
            if node.ppid in tree.nodes:
                # We need to manually add children attribute if missing or append
                parent = tree.nodes[node.ppid]
                if not hasattr(parent, 'children'): parent.children = []
                parent.children.append(node)

        return tree

    def run(self, duration=30):
        """
        Executes the Secure Capture Workflow.
        """
        self.logger.info(f"[MODE] Snapshot started. Interval: {duration}s")

        try:
            # 1. UNIFIED COLLECTION
            # Uses the new Manager to get a clean Dictionary with all data
            mgr = CollectionManager(self.config)
            full_data = mgr.collect_snapshot(duration=duration)

            # 2. ENCRYPTION (Data-at-Rest Protection)
            # We MUST have a public key to save data.
            if not os.path.exists(self.pub_key_path):
                self.logger.critical(f"[SECURITY] Public Key not found at {self.pub_key_path}. Cannot encrypt/save.")
                return

            self.logger.info("[SECURITY] Encrypting data with Public Key...")
            pub_key = load_public_key(self.pub_key_path)
            encrypted_bundle = encrypt_data(full_data, pub_key)

            # 3. PERSISTENCE (Store-and-Forward)
            # Save the BLOB to SQLite
            row_id = self.db.insert_snapshot(encrypted_bundle)
            if row_id:
                self.logger.info(f"[CORE] Encrypted Snapshot saved to DB (ID: {row_id}).")
            else:
                self.logger.error("[ERROR] Failed to save snapshot to Database.")
                return  # If we didn't save, we shouldn't report

            # 4. REPORT GENERATION (Server-Side Decryption)
            # Only possible if we have the Private Key.
            if os.path.exists(self.priv_key_path):
                self.logger.info("[SECURITY] Private Key found. Decrypting for Report generation...")
                priv_key = load_private_key(self.priv_key_path)

                # Decrypt the bundle we just created (or fetched from DB)
                decrypted_data = decrypt_data(encrypted_bundle, priv_key)

                if decrypted_data:
                    # Rehydrate Tree Object for the Legacy Report Generator
                    tree_obj = self._rehydrate_tree(decrypted_data['processes'])

                    # Generate HTML
                    hostname = socket.gethostname()
                    ts_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    outfile = f"report/sys-inspector_{hostname}_{ts_str}.html"

                    # Ensure report dir exists
                    if not os.path.exists("report"): os.makedirs("report")

                    self.logger.info(f"[*] Generating HTML Report: {outfile}")
                    success = generate_report(decrypted_data, tree_obj, outfile, "0.90 (Snapshot)")

                    if success:
                        self.logger.info(f"[REPORT] HTML generated successfully.")
                    else:
                        self.logger.error("[REPORT] Failed to generate HTML file.")
                else:
                    self.logger.error("[SECURITY] Decryption failed. Corrupted data or wrong key.")
            else:
                # Zero-Knowledge Case: We collected and saved, but can't see it.
                self.logger.warning("[SECURITY] Private Key NOT found. Data saved encrypted, but HTML report skipped.")
                self.logger.warning(f" -> Use 'python3 main.py --decrypt-snapshot {row_id}' later with the key.")

        except KeyboardInterrupt:
            self.logger.warning("[!] Snapshot interrupted by user.")
        except Exception as e:
            self.logger.error(f"[CRITICAL] Snapshot execution failed: {e}")
            import traceback
            traceback.print_exc()
