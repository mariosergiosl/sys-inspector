# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/ingest.py
# DESCRIPTION: Server side of the transport: the ingestion queue that every
#              capture passes through before reaching its final place.
#
# ONE MECHANISM:
#              A capture that arrives over the network from a remote agent and
#              one produced by the collector running on this very host follow
#              the same path: land in the queue, then get drained by the
#              processor. Server mode and local-live mode therefore share one
#              queueing rule, one priority rule and one place where duplicates
#              are settled, instead of two code paths that drift apart.
#
# WHY A QUEUE:
#              Accepting fast and processing afterwards keeps a burst from a
#              fleet flushing its backlog from blocking the receiver, and gives
#              the server, not the agent, control over how much flows in.
#
# NOTES:       Compatible with Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.91.0
# ==============================================================================

import json
import time
import logging
import sqlite3
from contextlib import closing

LOG = logging.getLogger("Ingest")

# Estados de uma entrada na fila.
ST_PENDING = "PENDING"
ST_DONE = "DONE"
ST_FAILED = "FAILED"

# Prioridade: menor numero e atendido primeiro. O padrao fica no meio da faixa
# para permitir promover e rebaixar um agente sem renumerar os demais.
PRIORITY_DEFAULT = 50

# Substitui o conteudo de uma entrada ja processada. A captura foi salva e
# assinada no armazenamento definitivo; manter a copia na fila so duplicaria
# cada evidencia e, como a fila nunca teve retencao, crescia sem limite.
PAYLOAD_DESCARTADO = '{"_purged": true}'

# Vagas concedidas por rodada a um agente. Limita o quanto um unico host
# despeja de uma vez quando volta de uma indisponibilidade longa.
DEFAULT_SLOTS = 10


class IngestQueue(object):
    """
    Fila de ingestao do servidor.

    Guarda a captura recebida como veio, marca de onde veio e em que ordem deve
    ser tratada, e so entao a entrega ao armazenamento definitivo.
    """

    def __init__(self, db_path, max_slots=DEFAULT_SLOTS):
        self.db_path = db_path
        self.max_slots = max_slots
        self._init_schema()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with closing(self._conn()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ingest_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_uuid TEXT NOT NULL,
                    digest TEXT,
                    received_at REAL NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 50,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    origin TEXT NOT NULL DEFAULT 'remote',
                    payload TEXT NOT NULL,
                    error TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_priority (
                    agent_uuid TEXT PRIMARY KEY,
                    priority INTEGER NOT NULL DEFAULT 50
                )
            """)
            # O digest identifica a captura: duas entregas da mesma captura nao
            # podem virar duas evidencias.
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_queue_digest "
                         "ON ingest_queue(digest) WHERE digest IS NOT NULL")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_status "
                         "ON ingest_queue(status, priority, received_at)")
            conn.commit()

    # --------------------------------------------------------------------------
    # PRIORIDADE
    # --------------------------------------------------------------------------
    def get_priority(self, agent_uuid):
        """Prioridade configurada do agente; o padrao quando nao ha registro."""
        try:
            with closing(self._conn()) as conn:
                row = conn.execute(
                    "SELECT priority FROM agent_priority WHERE agent_uuid = ?",
                    (agent_uuid,)).fetchone()
                return int(row["priority"]) if row else PRIORITY_DEFAULT
        except Exception:
            return PRIORITY_DEFAULT

    def set_priority(self, agent_uuid, priority):
        """
        Muda a posicao de um agente na fila.

        Serve ao caso pratico de uma investigacao: o host sob suspeita passa na
        frente dos demais, sem precisar parar a coleta da frota.
        """
        with closing(self._conn()) as conn:
            conn.execute(
                "INSERT INTO agent_priority (agent_uuid, priority) VALUES (?, ?) "
                "ON CONFLICT(agent_uuid) DO UPDATE SET priority = excluded.priority",
                (agent_uuid, int(priority)))
            # Reordena o que ja esta esperando, senao a mudanca so valeria para
            # o que chegasse depois.
            conn.execute("UPDATE ingest_queue SET priority = ? "
                         "WHERE agent_uuid = ? AND status = ?",
                         (int(priority), agent_uuid, ST_PENDING))
            conn.commit()

    # --------------------------------------------------------------------------
    # CONCESSAO DE VAGA
    # --------------------------------------------------------------------------
    def grant_slots(self, agent_uuid, pending):
        """
        Responde quantas capturas o servidor aceita deste agente agora.

        A decisao e do servidor porque so ele enxerga a frota inteira: um agente
        com muito acumulo nao pode monopolizar a ingestao enquanto os outros
        esperam.
        """
        try:
            with closing(self._conn()) as conn:
                backlog = conn.execute(
                    "SELECT COUNT(*) AS n FROM ingest_queue WHERE status = ?",
                    (ST_PENDING,)).fetchone()["n"]
                waiting = conn.execute(
                    "SELECT COUNT(DISTINCT agent_uuid) AS n FROM ingest_queue "
                    "WHERE status = ?", (ST_PENDING,)).fetchone()["n"]
        except Exception:
            backlog, waiting = 0, 0

        # Fila muito cheia: pede espera em vez de aceitar e acumular sem fim.
        if backlog >= self.max_slots * 20:
            return {"granted": False, "slots": 0, "retry_after": 60,
                    "reason": "server backlog"}

        # Divide as vagas entre os agentes que estao esperando, garantindo pelo
        # menos uma para ninguem ficar parado.
        share = max(1, self.max_slots // max(1, waiting or 1))
        return {"granted": True, "slots": min(share, int(pending or 1)),
                "retry_after": 0, "priority": self.get_priority(agent_uuid)}

    # --------------------------------------------------------------------------
    # ENTRADA
    # --------------------------------------------------------------------------
    def enqueue(self, agent_uuid, payload, origin="remote"):
        """
        Coloca uma captura na fila.

        Retorna 'received' quando entrou, ou 'duplicate' quando aquela captura
        ja havia sido recebida: reenviar apos um reconhecimento perdido nao
        pode gerar duas evidencias iguais.
        """
        digest = ((payload or {}).get("custody") or {}).get("digest")
        try:
            with closing(self._conn()) as conn:
                conn.execute(
                    "INSERT INTO ingest_queue (agent_uuid, digest, received_at, "
                    "priority, status, origin, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (agent_uuid, digest, time.time(),
                     self.get_priority(agent_uuid), ST_PENDING, origin,
                     json.dumps(payload)))
                conn.commit()
                return "received"
        except sqlite3.IntegrityError:
            return "duplicate"
        except Exception as exc:
            LOG.error("Enqueue failed: %s", exc)
            return "error"

    # --------------------------------------------------------------------------
    # SAIDA
    # --------------------------------------------------------------------------
    def next_batch(self, limit=None):
        """
        Proximas capturas a processar, na ordem da fila: prioridade primeiro,
        chegada como desempate.
        """
        limit = limit or self.max_slots
        try:
            with closing(self._conn()) as conn:
                rows = conn.execute(
                    "SELECT id, agent_uuid, digest, payload, origin FROM ingest_queue "
                    "WHERE status = ? ORDER BY priority ASC, received_at ASC LIMIT ?",
                    (ST_PENDING, limit)).fetchall()
                batch = []
                for row in rows:
                    item = dict(row)
                    try:
                        item["payload"] = json.loads(item["payload"])
                    except Exception:
                        item["payload"] = {}
                    batch.append(item)
                return batch
        except Exception as exc:
            LOG.error("Reading the queue failed: %s", exc)
            return []

    def mark_done(self, entry_id):
        """
        Marca a entrada como processada e DESCARTA o payload.

        A fila e um buffer de transporte, nao um segundo arquivo. Guardar o
        payload depois de a captura estar salva significa manter cada evidencia
        em duplicidade, e como a fila nunca teve retencao, essa copia crescia
        sem limite: medido em campo, 785 entradas ocupavam 1.03 GB, 86% do banco
        inteiro, contra 65 MB das capturas de fato guardadas.

        O registro da entrada permanece: quem entregou, quando, com que digest e
        qual foi o desfecho. E o rastro que importa; o conteudo ja esta no lugar
        definitivo e assinado.
        """
        # Marcador explicito em vez de NULL: a coluna e NOT NULL desde o
        # esquema original, e trocar isso exigiria migrar bancos ja em uso. O
        # marcador tambem e mais honesto que um valor vazio, porque diz o que
        # aconteceu a quem for ler a linha.
        try:
            with closing(self._conn()) as conn:
                conn.execute("UPDATE ingest_queue SET status = ?, "
                             "attempts = attempts + 1, payload = ? "
                             "WHERE id = ?",
                             (ST_DONE, PAYLOAD_DESCARTADO, entry_id))
                conn.commit()
        except Exception as exc:
            LOG.error("Completing queue entry %s failed: %s", entry_id, exc)

    def mark_failed(self, entry_id, error=""):
        """Marca a entrada como falha, preservando o motivo para analise."""
        self._set_status(entry_id, ST_FAILED, error)

    def _set_status(self, entry_id, status, error=""):
        try:
            with closing(self._conn()) as conn:
                conn.execute("UPDATE ingest_queue SET status = ?, "
                             "attempts = attempts + 1, error = ? WHERE id = ?",
                             (status, error or None, entry_id))
                conn.commit()
        except Exception as exc:
            LOG.error("Updating queue entry %s failed: %s", entry_id, exc)

    # --------------------------------------------------------------------------
    # OBSERVACAO
    # --------------------------------------------------------------------------
    def stats(self):
        """Situacao da fila, para o painel e para diagnostico."""
        summary = {"pending": 0, "done": 0, "failed": 0, "by_agent": {}}
        try:
            with closing(self._conn()) as conn:
                for row in conn.execute(
                        "SELECT status, COUNT(*) AS n FROM ingest_queue GROUP BY status"):
                    key = str(row["status"]).lower()
                    if key in summary:
                        summary[key] = row["n"]
                for row in conn.execute(
                        "SELECT agent_uuid, COUNT(*) AS n, MIN(priority) AS p "
                        "FROM ingest_queue WHERE status = ? GROUP BY agent_uuid",
                        (ST_PENDING,)):
                    summary["by_agent"][row["agent_uuid"]] = {
                        "pending": row["n"], "priority": row["p"]}
        except Exception as exc:
            LOG.error("Queue stats failed: %s", exc)
        return summary


def process_batch(queue, db, limit=None):
    """
    Drena a fila para o armazenamento definitivo.

    E o unico ponto onde uma captura vira evidencia guardada, venha ela da rede
    ou da coleta local, o que mantem um so comportamento para os dois modos.
    Retorna quantas foram processadas.
    """
    processed = 0
    for item in queue.next_batch(limit):
        payload = item.get("payload") or {}
        try:
            agent_uuid = item.get("agent_uuid") or "unknown"
            db.insert_snapshot(
                payload.get("bundle"),
                agent_uuid=agent_uuid,
                metrics=payload.get("metrics") or {},
                custody=payload.get("custody") or {},
                findings_summary=payload.get("findings_summary") or {},
            )
            # Registra quem e o host, para a frota nao listar tudo como
            # "unknown": esses campos viajam em claro justamente para isso.
            host = payload.get("host") or {}
            if host:
                db.update_agent_status(agent_uuid, "ONLINE",
                                       hostname=host.get("hostname"),
                                       ip=host.get("ip_address"),
                                       os_info=host.get("os_info"),
                                       fqdn=host.get("fqdn"),
                                       cycle_seconds=host.get("cycle_seconds"))
            queue.mark_done(item["id"])
            processed += 1
        except Exception as exc:
            LOG.error("Processing queue entry %s failed: %s", item["id"], exc)
            queue.mark_failed(item["id"], str(exc))
    return processed
