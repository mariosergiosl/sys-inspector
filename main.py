# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: main.py
# USAGE: python3 main.py --mode [daemon|server] [OPTIONS]
#        If no options provided, settings are loaded from conf/config.yaml
#
# DESCRIPTION: Master Entry Point for Sys-Inspector.
#              Orchestrates the two modes that remain: daemon (the agent that
#              collects) and server (the one that receives and renders).
#
#              [2026-08-19, C-134] Os modos snapshot, live e local-live foram
#              REMOVIDOS. Eram tres implementacoes paralelas do mesmo ato de
#              coletar, e elas divergiram em silencio (ver C-132). O caso de uso
#              local passa a ser agente e servidor na MESMA maquina, e o uso
#              pontual continua cabendo em uma linha, com --once.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.91.0
# ==============================================================================

import sys
import signal
import argparse
import threading
import logging
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
    # Flask so e necessario para os modos com interface web; exigir de todos
    # obrigaria um coletor puro a carregar um servidor web sem uso.
    required_modules = ['yaml', 'cryptography']
    missing_modules = []

    for mod in required_modules:
        try:
            __import__(mod)
        except ImportError:
            missing_modules.append(mod)

    if missing_modules:
        print(f"[!] Missing critical modules: {', '.join(missing_modules)}")
        print("[*] Triggering auto-setup...")

        # [SEC] Resolve setup_env.sh only from trusted, fixed locations.
        # Nao usar shutil.which(): buscar no $PATH como root permitiria que
        # um 'setup_env.sh' malicioso, colocado antes no PATH, fosse executado.
        base_dir = os.path.dirname(os.path.abspath(__file__))
        candidate_paths = [
            os.path.join(base_dir, "tools", "setup_env.sh"),  # dev / source tree
            "/usr/bin/setup_env.sh",                          # RPM / pip install
        ]

        script_path = None
        for candidate in candidate_paths:
            if os.path.exists(candidate):
                script_path = candidate
                break

        if not script_path:
            print("[ERROR] Setup script not found in trusted locations. Aborting.")
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
    # Apenas o que TODO modo usa. Os controllers sao importados sob demanda,
    # ja que cada modo tem exigencias diferentes: coletar precisa de eBPF (bcc,
    # headers do kernel), receber e analisar nao. Importar todos aqui obrigava
    # um servidor a ter o ferramental de compilacao eBPF instalado sem nunca
    # usa-lo, o que impedia rodar o servidor em hosts sem esse toolchain.
    try:
        from src.utils.config_loader import load_config
        from src.core.database import DatabaseManager
        from src.core.crypto import load_private_key, decrypt_data
    except ImportError as e:
        print(f"[CRITICAL] Failed to import core modules after setup: {e}")
        sys.exit(1)

    def load_controller(mode_name):
        """
        Importa o controller do modo escolhido, e so ele.

        Uma dependencia ausente e reportada com o motivo e a acao, em vez de um
        ModuleNotFoundError cru que nao diz ao operador o que instalar.
        """
        controllers = {
            'daemon': ('src.controllers.daemon_controller', 'DaemonController'),
            'server': ('src.controllers.server_controller', 'ServerController'),
        }
        module_path, class_name = controllers[mode_name]
        try:
            module = __import__(module_path, fromlist=[class_name])
            return getattr(module, class_name)
        except ImportError as exc:
            missing = str(exc).lower()
            print(f"[CRITICAL] Mode '{mode_name}' cannot start: {exc}")
            if "bcc" in missing:
                print("HINT: this mode collects with eBPF and needs 'python3-bcc' "
                      "plus the kernel headers. Modes that only receive or "
                      "analyse data (server) do not.")
            elif "flask" in missing:
                print("HINT: 'flask' is missing. Run 'pip install flask' or "
                      "'./tools/setup_env.sh --install'")
            sys.exit(1)

    # 3. Argument Parsing
    parser = argparse.ArgumentParser(description="Sys-Inspector v0.80 Agent")

    # NOTE: default=None ensures we don't override config.yaml if flag is missing
    parser.add_argument("--mode", choices=['daemon', 'server'],
                        default=None, help="Execution mode (Overrules config.yaml)")

    parser.add_argument("--config", default="conf/config.yaml",
                        help="Path to configuration file")

    # [C-134] Preserva o primeiro uso em UMA LINHA, que era o que o modo
    # snapshot oferecia. Nao e um modo novo: e o mesmo agente, parando apos um
    # ciclo. Sem server_ip e sem token, o Outbox ja fica desligado sozinho e a
    # captura fica guardada localmente.
    parser.add_argument("--once", action="store_true",
                        help="Run a single collection cycle and exit "
                             "(daemon mode only)")

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

    # Apply the configured log level (overrides the INFO bootstrap default).
    # Fallback seguro para INFO se o valor estiver ausente ou invalido.
    log_level_name = config.get('general', {}).get('log_level', 'INFO').upper()
    logging.getLogger().setLevel(getattr(logging, log_level_name, logging.INFO))

    # --------------------------------------------------------------------------
    # AUTO-PROVISION CRYPTOGRAPHIC IDENTITY
    # --------------------------------------------------------------------------
    try:
        from src.core.crypto import ensure_crypto_environment
        seguranca = config.get('security', {}) or {}
        caminho_publica = seguranca['public_key_path']
        # A chave PRIVADA do analista e opcional, e num agente ela deve mesmo
        # estar ausente: ele cifra o que coleta e nao consegue reabrir.
        #
        # Ate 2026-09-18 isto era lido com acesso direto e estourava KeyError,
        # de modo que a configuracao CORRETA de um agente era recusada na
        # partida. Na pratica obrigava todo agente a declarar um caminho para
        # a chave que ele nao pode ter, e foi o que se encontrou no
        # laboratorio: config apontando um arquivo que nunca existiu.
        #
        # O destino so e usado quando a chave PUBLICA falta e o par precisa
        # nascer; nesse caso a privada nasce ao lado dela, que e onde alguem
        # iria procurar.
        caminho_privada = seguranca.get('private_key_path') or os.path.join(
            os.path.dirname(caminho_publica) or ".", "private_key.pem")
        ensure_crypto_environment(caminho_publica, caminho_privada)
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
        priv_path = (config.get('security', {}) or {}).get('private_key_path')
        if not priv_path:
            logging.error("No private_key_path configured. Decryption needs "
                          "the analyst private key, which lives on the server "
                          "and never on an agent.")
            sys.exit(1)
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

        if mode == 'daemon':
            # O agente. Coleta, cifra, guarda e entrega ao servidor.
            if args.once:
                logging.info("[START] Starting Daemon Mode (single cycle)...")
            else:
                logging.info("[START] Starting Daemon Mode (Background Collector)...")
            ctrl = load_controller('daemon')(config, db, SHUTDOWN_EVENT,
                                             run_once=args.once)
            ctrl.run()  # Loops until shutdown, or returns after one cycle

        elif mode == 'server':
            if args.once:
                logging.warning("[ARGS] --once so vale no modo daemon; ignorado.")
            # v0.60 Legacy Server Mode (being refactored)
            logging.warning("[BETA] Server Mode logic is being refactored for v0.80.")
            ctrl = load_controller('server')(config, db, SHUTDOWN_EVENT)
            ctrl.run()

        else:
            logging.error(f"Unknown mode: {mode}")
            print("Usage: python3 main.py --mode [daemon|server]")
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
