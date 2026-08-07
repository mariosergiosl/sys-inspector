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
# VERSION: v0.90.16
# ==============================================================================

import sqlite3
import time
import os
import json
import logging
from contextlib import closing

# DEFAULT_DB_PATH = "data/sys_inspector.db"
DEFAULT_DB_PATH = "/var/lib/sys-inspector/sys_inspector.db"
DEFAULT_RETENTION_COUNT = 100


class DatabaseManager:
    def __init__(self, db_path=None, max_snapshots=DEFAULT_RETENTION_COUNT):
        self.db_path = db_path if db_path else DEFAULT_DB_PATH
        self.max_snapshots = max_snapshots
        self.logger = logging.getLogger("DBManager")

        # Ensure data directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except PermissionError:
                self.logger.critical(f"Permission denied creating directory: {db_dir}")
                raise

        # Identidade estavel do agente local, compartilhada por todos os modos
        # (snapshot/daemon/live/server) que recebem este DatabaseManager.
        self.agent_id = self._load_or_create_agent_id()

        self._init_db()

    def _load_or_create_agent_id(self):
        """
        Le (ou cria e persiste) um UUID estavel do agente, gravado ao lado do
        arquivo de banco. Mantem a identidade entre reinicios e unifica o
        agent_uuid usado por todos os modos.
        """
        import uuid
        id_dir = os.path.dirname(self.db_path) or "."
        id_file = os.path.join(id_dir, ".agent_id")
        try:
            if os.path.exists(id_file):
                with open(id_file, "r") as f:
                    existing = f.read().strip()
                    if existing:
                        return existing
            new_id = str(uuid.uuid4())
            with open(id_file, "w") as f:
                f.write(new_id)
            return new_id
        except Exception as e:
            # Fallback: id efemero se nao for possivel persistir.
            self.logger.warning(f"Could not persist .agent_id: {e}")
            return str(uuid.uuid4())

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

                # 2.1 Cadeia de custodia: digest da captura e do antecessor,
                # em claro de proposito, para verificar a integridade e a
                # continuidade da serie sem precisar descriptografar nada.
                # ALTER guardado por try: bancos criados antes desta versao
                # ganham as colunas sem perder os dados ja coletados.
                for column, ctype in (("digest", "TEXT"),
                                      ("previous_digest", "TEXT"),
                                      ("custody", "TEXT"),
                                      # Contagem de achados por severidade, em
                                      # claro: permite triar a frota inteira
                                      # ("qual host esta pior?") sem
                                      # descriptografar captura por captura.
                                      # Guarda numeros, nunca o conteudo.
                                      ("findings_summary", "TEXT")):
                    try:
                        conn.execute("ALTER TABLE snapshots ADD COLUMN %s %s"
                                     % (column, ctype))
                    except Exception:
                        pass  # ja existe

                # 3. Indexes
                # FQDN do agente, em claro como os demais metadados de
                # inventario. ALTER guardado: bancos antigos ganham a coluna.
                for coluna, tipo in (("fqdn", "TEXT"), ("cycle_seconds", "INTEGER")):
                    try:
                        conn.execute("ALTER TABLE agents ADD COLUMN %s %s"
                                     % (coluna, tipo))
                    except Exception:
                        pass

                conn.execute("CREATE INDEX IF NOT EXISTS idx_snap_synced ON snapshots(synced)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_snap_agent_ts ON snapshots(agent_uuid, timestamp)")

                conn.commit()
        except Exception as e:
            self.logger.critical(f"Schema Initialization Failed: {e}")
            raise

    # --------------------------------------------------------------------------
    # WRITE OPERATIONS
    # --------------------------------------------------------------------------
    def get_last_digest(self, agent_uuid="local"):
        """
        Digest da ultima captura deste agente, que sera o elo anterior da
        proxima. None quando ainda nao ha antecessor.
        """
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute(
                    "SELECT digest FROM snapshots WHERE agent_uuid = ? "
                    "AND digest IS NOT NULL ORDER BY id DESC LIMIT 1",
                    (agent_uuid,))
                row = cursor.fetchone()
                return row[0] if row else None
        except Exception as e:
            self.logger.error(f"Get Last Digest Failed: {e}")
            return None

    def get_custody_chain(self, agent_uuid="local"):
        """
        Serie de registros de custodia do agente, em ordem cronologica, para
        verificar se alguma captura foi removida ou reordenada.
        """
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute(
                    "SELECT custody FROM snapshots WHERE agent_uuid = ? "
                    "AND custody IS NOT NULL ORDER BY id ASC", (agent_uuid,))
                return [json.loads(r[0]) for r in cursor if r[0]]
        except Exception as e:
            self.logger.error(f"Get Custody Chain Failed: {e}")
            return []

    def insert_snapshot(self, encrypted_bundle, agent_uuid="local", metrics=None,
                        custody=None, findings_summary=None):
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
                cur = conn.execute("""
                    INSERT INTO snapshots (
                        agent_uuid, timestamp,
                        cpu_avg, mem_used_mb, pids_count, alert_score, is_alert,
                        json_blob, synced, digest, previous_digest, custody,
                        findings_summary
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                """, (
                    agent_uuid,
                    time.time(),
                    metrics.get('cpu', 0),
                    metrics.get('mem', 0),
                    metrics.get('pids', 0),
                    metrics.get('score', 0),
                    1 if metrics.get('score', 0) > 0 else 0,
                    blob_json,
                    (custody or {}).get('digest'),
                    (custody or {}).get('previous_digest'),
                    json.dumps(custody) if custody else None,
                    json.dumps(findings_summary) if findings_summary else None
                ))
                # Guarda o id da linha recem-inserida para retorno ao chamador
                # (antes retornava True, o que fazia o log exibir "ID: True").
                snap_id = cur.lastrowid

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
                return snap_id
        except Exception as e:
            self.logger.error(f"Insert Failed: {e}")
            return None

    def mark_as_synced(self, snapshot_ids):
        if not snapshot_ids: return
        try:
            with closing(self._get_conn()) as conn:
                placeholders = ','.join('?' * len(snapshot_ids))
                sql = f"UPDATE snapshots SET synced=1 WHERE id IN ({placeholders})"
                conn.execute(sql, snapshot_ids)
                conn.commit()
        except Exception as e:
            self.logger.error(f"Mark Synced Failed: {e}")

    def update_agent_status(self, uuid, status, hostname=None, ip=None,
                            os_info=None, fqdn=None, cycle_seconds=None):
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
                if fqdn:
                    sql += ", fqdn=?"
                    params.append(fqdn)
                if cycle_seconds:
                    sql += ", cycle_seconds=?"
                    params.append(int(cycle_seconds))

                sql += " WHERE uuid=?"
                params.append(uuid)

                conn.execute(sql, params)
                conn.commit()
        except Exception as e:
            self.logger.error(f"Agent Update Failed: {e}")

    # --------------------------------------------------------------------------
    # READ OPERATIONS
    # --------------------------------------------------------------------------
    def get_confirmed_candidates(self, limit=200):
        """
        Capturas ja entregues cujo digest ainda nao foi confirmado pelo servidor.

        Sao as candidatas a liberar espaco no agente. Entregue nao significa
        guardado: a entrega termina na fila de ingestao do servidor, e entre a
        fila e o disco ainda ha um passo que pode falhar. Apagar aqui com base
        no aceite da entrega perderia a captura nas DUAS pontas.
        """
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute("""
                    SELECT id, digest FROM snapshots
                    WHERE synced = 1 AND digest IS NOT NULL
                      AND json_blob IS NOT NULL
                    ORDER BY id ASC LIMIT ?
                """, (limit,))
                return [{"id": r[0], "digest": r[1]} for r in cursor]
        except Exception as e:
            self.logger.error(f"Listing confirmed candidates failed: {e}")
            return []

    def purge_confirmed(self, snapshot_ids):
        """
        Libera o conteudo local das capturas que o servidor confirmou guardar.

        A LINHA permanece, com digest e encadeamento: e o mesmo cuidado da
        retencao no servidor, porque apagar o elo romperia a cadeia de custodia
        do proprio agente e a verificacao local passaria a falhar.
        """
        if not snapshot_ids:
            return 0
        try:
            with closing(self._get_conn()) as conn:
                marcas = ",".join("?" * len(snapshot_ids))
                cur = conn.execute(
                    "UPDATE snapshots SET json_blob = NULL WHERE id IN (%s)"
                    % marcas, list(snapshot_ids))
                conn.commit()
                return cur.rowcount
        except Exception as e:
            self.logger.error(f"Purging confirmed snapshots failed: {e}")
            return 0

    def set_capabilities(self, agent_uuid, capabilities):
        """
        Guarda o retrato de capacidades enviado pelo agente.

        Em coluna propria e em claro: e metadado operacional, nao conteudo de
        investigacao, e a triagem da frota precisa dele sem descriptografar
        nada.
        """
        if not capabilities:
            return
        try:
            with closing(self._get_conn()) as conn:
                try:
                    conn.execute("ALTER TABLE agents ADD COLUMN capabilities TEXT")
                except Exception:
                    pass
                conn.execute("UPDATE agents SET capabilities = ? WHERE uuid = ?",
                             (json.dumps(capabilities), agent_uuid))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Storing capabilities failed: {e}")

    def get_capabilities(self, agent_uuid=None):
        """Capacidades de um agente, ou de todos, para a tela da frota."""
        try:
            with closing(self._get_conn()) as conn:
                try:
                    conn.execute("ALTER TABLE agents ADD COLUMN capabilities TEXT")
                    conn.commit()
                except Exception:
                    pass
                if agent_uuid:
                    row = conn.execute(
                        "SELECT capabilities FROM agents WHERE uuid = ?",
                        (agent_uuid,)).fetchone()
                    return json.loads(row[0]) if row and row[0] else {}
                saida = {}
                for r in conn.execute("SELECT uuid, capabilities FROM agents"):
                    saida[r[0]] = json.loads(r[1]) if r[1] else {}
                return saida
        except Exception as e:
            self.logger.error(f"Reading capabilities failed: {e}")
            return {} if agent_uuid else {}

    def digests_present(self, digests):
        """
        Quais destes digests estao de fato guardados aqui.

        Chamada no SERVIDOR para responder ao agente. Conferir o digest, e nao o
        id, e o que torna a resposta confiavel: o id e local de cada lado, o
        digest identifica o conteudo.
        """
        if not digests:
            return []
        try:
            with closing(self._get_conn()) as conn:
                marcas = ",".join("?" * len(digests))
                cursor = conn.execute(
                    "SELECT digest FROM snapshots WHERE digest IN (%s) "
                    "AND json_blob IS NOT NULL" % marcas, list(digests))
                return [r[0] for r in cursor]
        except Exception as e:
            self.logger.error(f"Checking digests failed: {e}")
            return []

    def get_pending_snapshots(self, limit=50):
        try:
            with closing(self._get_conn()) as conn:
                # Leva junto metricas, custodia e resumo de achados: o servidor
                # precisa deles para montar a triagem da frota sem
                # descriptografar, e a custodia carrega o digest que identifica
                # a captura de forma idempotente no reenvio.
                cursor = conn.execute("""
                    SELECT id, json_blob, cpu_avg, mem_used_mb, pids_count,
                           alert_score, custody, findings_summary
                    FROM snapshots
                    WHERE synced=0
                    ORDER BY id ASC LIMIT ?
                """, (limit,))
                pending = []
                for r in cursor:
                    def _load(raw):
                        try:
                            return json.loads(raw) if raw else {}
                        except Exception:
                            return {}
                    pending.append({
                        'id': r['id'],
                        'data': json.loads(r['json_blob']),
                        'metrics': {'cpu': r['cpu_avg'], 'mem': r['mem_used_mb'],
                                    'pids': r['pids_count'],
                                    'score': r['alert_score']},
                        'custody': _load(r['custody']),
                        'findings_summary': _load(r['findings_summary']),
                    })
                return pending
        except Exception as e:
            self.logger.error(f"Get Pending Failed: {e}")
            return []

    def get_history(self, start_ts, end_ts, agent_filter=None):
        """
        Retorna a lista leve de snapshots (apenas colunas quentes) dentro da
        janela de tempo, ordenada do mais recente para o mais antigo.

        Espelha o contrato de storage/db_handler.DatabaseHandler.get_history:
        cada item e um dict com id, timestamp, agent_uuid e as metricas quentes.
        Os controllers live/server dependem do acesso por chave (ex.: item['id']).

        PARAMETER start_ts: limite inferior do timestamp (epoch, inclusivo).
        PARAMETER end_ts: limite superior do timestamp (epoch, inclusivo).
        PARAMETER agent_filter: se informado, restringe a um agent_uuid.
        """
        cols = ['id', 'timestamp', 'agent_uuid', 'cpu_avg',
                'mem_used_mb', 'alert_score', 'is_alert']
        sql = """
            SELECT id, timestamp, agent_uuid, cpu_avg,
                   mem_used_mb, alert_score, is_alert
            FROM snapshots
            WHERE timestamp BETWEEN ? AND ?
        """
        params = [start_ts, end_ts]

        if agent_filter:
            sql += " AND agent_uuid = ?"
            params.append(agent_filter)

        sql += " ORDER BY timestamp DESC"

        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute(sql, params)
                return [dict(zip(cols, row)) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Get History Failed: {e}")
            return []

    def get_snapshot_details(self, snap_id):
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute("SELECT json_blob FROM snapshots WHERE id = ?", (snap_id,))
                row = cursor.fetchone()
                return json.loads(row[0]) if row else None
        except Exception:
            return None

    def get_fleet_status(self):
        """
        Situacao de risco de cada agente, para a triagem da frota.

        Junta os metadados do agente com a ULTIMA captura dele, usando apenas
        colunas em claro. Assim o analista consegue ordenar dezenas ou centenas
        de hosts por gravidade ("qual esta pior?") sem descriptografar nada, que
        seria caro e exporia conteudo desnecessariamente.
        """
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute("""
                    SELECT a.uuid, a.hostname, a.ip_address, a.os_info,
                           a.fqdn, a.cycle_seconds, a.status, a.last_seen,
                           s.timestamp AS last_capture,
                           s.alert_score, s.is_alert, s.cpu_avg,
                           s.mem_used_mb, s.pids_count, s.findings_summary
                    FROM agents a
                    LEFT JOIN snapshots s ON s.id = (
                        SELECT id FROM snapshots
                        WHERE agent_uuid = a.uuid
                        ORDER BY id DESC LIMIT 1
                    )
                    ORDER BY a.last_seen DESC
                """)
                fleet = []
                for row in cursor:
                    item = dict(row)
                    raw = item.pop("findings_summary", None)
                    try:
                        item["findings"] = json.loads(raw) if raw else {}
                    except Exception:
                        item["findings"] = {}
                    fleet.append(item)
                return fleet
        except Exception as e:
            self.logger.error(f"Get Fleet Status Failed: {e}")
            return []

    def get_agents(self):
        try:
            with closing(self._get_conn()) as conn:
                cursor = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC")
                return [dict(row) for row in cursor]
        except Exception as e:
            # Log error strictly to help debug permissions issues
            self.logger.error(f"Get Agents Failed: {e}")
            return []
