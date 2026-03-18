# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: main.py
# USAGE: python3 main.py --mode [snapshot|live|daemon|server|local-live] [OPTIONS]
#        If no options provided, settings are loaded from conf/config.yaml
#
# DESCRIPTION: Master Entry Point for Sys-Inspector v0.90.
#              Orchestrates Snapshot, Daemon, Server, and Local-Live modes.
#              Includes auto-setup for critical dependencies.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.90.15
# ==============================================================================

import sys
import signal
import argparse
import threading
import logging
import time
import os
import subprocess

# Global Shutdown Event for Threaded Modes
SHUTDOWN_EVENT = threading.Event()


# ------------------------------------------------------------------------------
# BOOTSTRAP: DEPENDENCY CHECK
# ------------------------------------------------------------------------------
def ensure_environment():
    """
    Checks for critical dependencies (PyYAML, Cryptography, Flask).
    Triggers setup_env.sh if ANY dependency is missing.
    This ensures SLES environments are auto-configured on first run.
    """
    required_modules = ['yaml', 'cryptography', 'flask']
    missing_modules = []

    for mod in required_modules:
        try:
            __import__(mod)
        except ImportError:
            missing_modules.append(mod)

    if missing_modules:
        print(f"[!] Missing critical modules: {', '.join(missing_modules)}")
        print("[*] Triggering auto-setup...")

        import shutil
        # 1. Tenta localizar no $PATH global (/usr/bin/)
        script_path = shutil.which("setup_env.sh")

        # 2. Fallback para ambiente de desenvolvimento local
        if not script_path:
            # Determine script path relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(base_dir, "tools", "setup_env.sh")

        if not script_path or not os.path.exists(script_path):
            print("[ERROR] Setup script not found. Aborting.")
            sys.exit(1)

        # Call the shell script with --install flag
        print(f"[*] Executing: {script_path} --install")
        try:
            ret_code = subprocess.call(["/bin/bash", script_path, "--install"])
        except Exception as e:
            print(f"[CRITICAL] Failed to execute setup script: {e}")
            sys.exit(1)

        if ret_code != 0:
            print("[CRITICAL] Setup failed. Please install requirements manually.")
            sys.exit(1)

        print("[*] Environment fixed. Resuming execution...")

        # Invalidate import caches to find the newly installed modules
        import importlib
        importlib.invalidate_caches()


# ------------------------------------------------------------------------------
# SIGNAL HANDLING
# ------------------------------------------------------------------------------
def signal_handler(sig, frame):
    """Handles Ctrl+C (SIGINT) for graceful shutdown."""
    print("\n[!] Shutdown Signal Received. Stopping threads...")
    SHUTDOWN_EVENT.set()


# ------------------------------------------------------------------------------
# MAIN EXECUTION
# ------------------------------------------------------------------------------
def main():

    # 1. Pre-flight Check (Bootstrap)
    ensure_environment()

    # 2. Delayed Imports (To prevent ModuleNotFoundError before Setup)
    try:
        from src.utils.config_loader import load_config
        from src.core.database import DatabaseManager
        from src.core.crypto import load_private_key, decrypt_data

        # Controllers
        from src.controllers.snapshot_controller import SnapshotController
        from src.controllers.live_controller import LiveController
        from src.controllers.daemon_controller import DaemonController
        from src.controllers.server_controller import ServerController
        # [NEW v0.80] Integrated Web Controller
        from src.controllers.web_controller import WebController

    except ImportError as e:
        print(f"[CRITICAL] Failed to import modules after setup: {e}")
        # Hint for Flask which is required by WebController
        if "flask" in str(e).lower():
            print("HINT: 'flask' is missing. Run 'pip install flask' or './scripts/setup_env.sh --install'")
        sys.exit(1)

    # 3. Argument Parsing
    parser = argparse.ArgumentParser(description="Sys-Inspector v0.80 Agent")

    # NOTE: default=None ensures we don't override config.yaml if flag is missing
    parser.add_argument("--mode", choices=['snapshot', 'live', 'daemon', 'server', 'local-live'],
                        default=None, help="Execution mode (Overrules config.yaml)")

    parser.add_argument("--config", default="conf/config.yaml",
                        help="Path to configuration file")

    parser.add_argument("--interval", type=int, default=None,
                        help="Collection duration/interval override (seconds)")

    parser.add_argument("--decrypt-snapshot", type=int, metavar="ID",
                        help="Utility: Decrypt and view a specific snapshot ID")

    args = parser.parse_args()

    # 4. Initialization
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

    # Load Config: Handle FHS fallback if running globally
    config_path = args.config

    # Se o caminho for o default relativo e não existir no local, tenta o global
    if config_path == "conf/config.yaml" and not os.path.exists(config_path):
        if os.path.exists("/etc/sys-inspector/config.yaml"):
            config_path = "/etc/sys-inspector/config.yaml"

    if not os.path.exists(config_path):
        logging.critical(f"Config file not found. Tried local 'conf/config.yaml' and global '/etc/sys-inspector/config.yaml'")
        sys.exit(1)

    config = load_config(config_path)

    # --------------------------------------------------------------------------
    # AUTO-PROVISION CRYPTOGRAPHIC IDENTITY
    # --------------------------------------------------------------------------
    try:
        from src.core.crypto import ensure_crypto_environment
        ensure_crypto_environment(
            config['security']['public_key_path'],
            config['security']['private_key_path']
        )
    except Exception as e:
        logging.critical(f"Failed to provision cryptographic keys: {e}")
        sys.exit(1)

    # Override Mode logic: CLI Args > Config File
    if args.mode:
        config['general']['mode'] = args.mode

    # Override Interval if provided in CLI (applies to Snapshot duration or Daemon interval)
    if args.interval:
        config['snapshot']['duration'] = args.interval
        # Note: For daemon, CLI interval usually overrides the sleep interval,
        # but config.yaml is preferred for complex duty cycles.
        if 'daemon' not in config: config['daemon'] = {}
        config['daemon']['interval'] = args.interval

    # Initialize Database (SQLite + Retention + Encryption Support)
    try:
        db = DatabaseManager(
            db_path=config['storage']['sqlite_path'],
            max_snapshots=config['storage'].get('max_snapshots', 100)
        )
    except Exception as e:
        logging.critical(f"Failed to initialize Database: {e}")
        sys.exit(1)

    # Register Signal Handler
    signal.signal(signal.SIGINT, signal_handler)

    # --------------------------------------------------------------------------
    # UTILITY: DECRYPTION CLI
    # --------------------------------------------------------------------------
    if args.decrypt_snapshot:
        logging.info(f"[*] Attempting to decrypt Snapshot ID: {args.decrypt_snapshot}")

        # Load Private Key
        priv_path = config['security']['private_key_path']
        if not os.path.exists(priv_path):
            logging.error(f"Private Key not found at {priv_path}")
            sys.exit(1)

        priv_key = load_private_key(priv_path)

        # Fetch from DB logic
        try:
            import sqlite3
            from contextlib import closing
            conn = sqlite3.connect(config['storage']['sqlite_path'])
            conn.row_factory = sqlite3.Row
            with closing(conn.cursor()) as cursor:
                cursor.execute(
                    "SELECT json_blob FROM snapshots WHERE id = ?",
                    (args.decrypt_snapshot,)
                )
                row = cursor.fetchone()
                if row:
                    encrypted_blob = row[0]
                    import json
                    blob_dict = json.loads(encrypted_blob)

                    logging.info("Decrypting data...")
                    decrypted_json = decrypt_data(blob_dict, priv_key)

                    if decrypted_json:
                        print("\n--- DECRYPTED DATA START ---")
                        print(json.dumps(decrypted_json, indent=2))
                        print("--- DECRYPTED DATA END ---\n")
                    else:
                        logging.error("Decryption failed (Check key or data integrity).")
                else:
                    logging.error(f"Snapshot ID {args.decrypt_snapshot} not found.")
        except Exception as e:
            logging.error(f"Decryption Utility Error: {e}")

        sys.exit(0)

    # --------------------------------------------------------------------------
    # CONTROLLER DISPATCH
    # --------------------------------------------------------------------------
    try:
        mode = config['general']['mode']

        if mode == 'snapshot':
            # v0.70 Snapshot Logic (Secure Store-and-Forward)
            duration = args.interval if args.interval else config['snapshot'].get('duration', 30)
            logging.info(f"[START] Starting Snapshot Mode ({duration}s)...")

            ctrl = SnapshotController(config, db)
            ctrl.run(duration=duration)

        elif mode == 'live':
            # v0.60 Legacy Live Mode (Terminal UI)
            logging.warning("[COMPAT] Starting Legacy Live Mode.")
            ctrl = LiveController(config, db, SHUTDOWN_EVENT)
            ctrl.run()

        elif mode == 'daemon':
            # v0.80 Daemon Mode (Universal Collector)
            logging.info("[START] Starting Daemon Mode (Background Collector)...")
            ctrl = DaemonController(config, db, SHUTDOWN_EVENT)
            ctrl.run()  # This enters the efficient infinite loop

        elif mode == 'local-live':
            # v0.80 Local-Live Mode (Daemon + Web Interface)
            logging.info("[START] Starting Local-Live Mode (Daemon + Web)...")

            # 1. Start Daemon in a separate thread (Producer)
            daemon_ctrl = DaemonController(config, db, SHUTDOWN_EVENT)
            daemon_thread = threading.Thread(target=daemon_ctrl.run, name="DaemonThread")
            daemon_thread.daemon = True  # Ensure it dies if main thread dies hard
            daemon_thread.start()

            # 2. Start Web Interface (Consumer) - Thread Daemonized
            try:
                web_ctrl = WebController(config, db)
                web_thread = threading.Thread(target=web_ctrl.run, name="WebThread")
                web_thread.daemon = True
                web_thread.start()
                logging.info("[WEB] Web Interface running in background.")
            except Exception as e:
                logging.error(f"[WEB] Failed to start Web UI: {e}")
                SHUTDOWN_EVENT.set()

            logging.info("[INFO] Use Ctrl+C to stop both Daemon and Web.")

            # 3. Main Loop (Just waits for Ctrl+C)
            while not SHUTDOWN_EVENT.is_set():
                time.sleep(0.5)

            # 4. Graceful Shutdown Sequence
            logging.info("[STOP] Stopping services...")

            # Wait for daemon to finish current cycle (max 5s wait)
            if daemon_thread.is_alive():
                daemon_thread.join(timeout=5)

            logging.info("[STOP] Daemon stopped. Killing Web Server...")
            # We don't join web_thread because Flask is blocking.
            # Instead, we fall through to 'finally' and force exit.

        elif mode == 'server':
            # v0.60 Legacy Server Mode (being refactored)
            logging.warning("[BETA] Server Mode logic is being refactored for v0.80.")
            ctrl = ServerController(config, db, SHUTDOWN_EVENT)
            ctrl.run()

        else:
            logging.error(f"Unknown mode: {mode}")
            print("Usage: python3 main.py --mode [snapshot|live|daemon|server|local-live]")
            sys.exit(1)

    except Exception as e:
        logging.critical(f"Unhandled Exception in Main: {e}")
        import traceback
        traceback.print_exc()
    finally:
        logging.info("[EXIT] Application terminated.")
        # [FIX] Force kill all threads (Flask) to ensure port 8080 is released immediately
        # Standard sys.exit() is not enough for threaded Flask.
        os._exit(0)


if __name__ == "__main__":
    main()
