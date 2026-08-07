# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/commands.py
# DESCRIPTION: Command queue the analyst fills and the agent drains.
#
# DIRECTION OF TRAFFIC (deliberate):
#              The server never opens a connection to an agent. The agent asks
#              whether there is anything for it and writes the result back.
#              Everything flows agent to server.
#
#              That is not a limitation, it is the safer design: the inspected
#              host needs no inbound port and no listening service, so the tool
#              does not add attack surface to the very machine under
#              investigation, and it keeps working for agents behind NAT or a
#              restrictive firewall, which is the normal case in the field.
#
# WHY QUEUED:  A command is a request, not an order executed at a distance. It
#              waits until the agent comes asking, is delivered once, and its
#              outcome is recorded, so there is always an auditable trail of who
#              asked for what and what happened.
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

LOG = logging.getLogger("Commands")

# Comandos aceitos. Lista fechada de proposito: o servidor nao manda o agente
# executar texto arbitrario, apenas acoes previstas e auditaveis.
CMD_COLLECT = "collect"          # captura sob demanda
CMD_CHAOS_COLLECT = "chaos"      # cenario de teste e captura (apenas em lab)
CMD_RESTART = "restart"          # reinicia o proprio agente

ALLOWED = (CMD_COLLECT, CMD_CHAOS_COLLECT, CMD_RESTART)

ST_PENDING = "PENDING"
ST_SENT = "SENT"
ST_DONE = "DONE"
ST_FAILED = "FAILED"

# Um comando esquecido na fila nao pode ser executado dias depois, quando o
# contexto que o motivou nao existe mais.
DEFAULT_TTL = 3600

# Tempo maximo que um comando pode ficar entregue sem desfecho. Uma captura sob
# demanda leva poucos minutos; passado este limite a hipotese realista nao e
# "ainda esta rodando", e sim que o agente morreu, foi reiniciado ou roda uma
# versao que nem entende o pedido. Melhor dizer isso ao analista do que exibir
# indefinidamente um estado de execucao que nao existe.
STUCK_LIMIT = 600

# Quanto se espera pelo desfecho antes de reentregar o pedido. Precisa ser maior
# que a execucao mais demorada prevista (o cenario de teste roda por 300s), senao
# o servidor reentregaria um comando que esta simplesmente em andamento, e o
# agente responderia "ja executei" quando ainda nem terminou.
RETRY_AFTER = 420


class CommandQueue(object):
    """Fila de comandos por agente, preenchida pelo analista."""

    def __init__(self, db_path, ttl=DEFAULT_TTL):
        self.db_path = db_path
        self.ttl = ttl
        self._init_schema()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with closing(self._conn()) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_uuid TEXT NOT NULL,
                    command TEXT NOT NULL,
                    params TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    created_at REAL NOT NULL,
                    delivered_at REAL,
                    finished_at REAL,
                    result TEXT,
                    requested_by TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cmd_agent "
                         "ON agent_commands(agent_uuid, status)")
            conn.commit()

    # --------------------------------------------------------------------------
    # LADO DO ANALISTA
    # --------------------------------------------------------------------------
    def enqueue(self, agent_uuid, command, params=None, requested_by=""):
        """
        Registra um pedido para um agente.

        Recusa comandos fora da lista prevista: o servidor nao deve conseguir
        mandar o agente executar qualquer coisa, mesmo que a interface seja
        comprometida.
        """
        if command not in ALLOWED:
            raise ValueError("command not allowed: %s" % command)

        with closing(self._conn()) as conn:
            cur = conn.execute(
                "INSERT INTO agent_commands (agent_uuid, command, params, "
                "status, created_at, requested_by) VALUES (?, ?, ?, ?, ?, ?)",
                (agent_uuid, command, json.dumps(params or {}), ST_PENDING,
                 time.time(), requested_by or ""))
            conn.commit()
            return cur.lastrowid

    def list_for(self, agent_uuid=None, limit=50):
        """Historico de comandos, para o painel mostrar o que foi pedido."""
        sql = "SELECT * FROM agent_commands"
        params = []
        if agent_uuid:
            sql += " WHERE agent_uuid = ?"
            params.append(agent_uuid)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        try:
            with closing(self._conn()) as conn:
                return [dict(r) for r in conn.execute(sql, params)]
        except Exception as exc:
            LOG.error("Listing commands failed: %s", exc)
            return []

    # --------------------------------------------------------------------------
    # LADO DO AGENTE (ele pergunta; o servidor nunca chama)
    # --------------------------------------------------------------------------
    def take_for(self, agent_uuid):
        """
        Entrega os comandos pendentes de um agente e os marca como enviados.

        Chamado quando o AGENTE pergunta. Comandos vencidos sao descartados em
        vez de entregues, para nao executar tarde um pedido cujo motivo ja
        passou.
        """
        agora = time.time()
        entregues = []
        try:
            with closing(self._conn()) as conn:
                # Entrega o que nunca saiu E o que saiu mas nao teve desfecho ha
                # mais de RETRY_AFTER. Sem a reentrega, um agente que morresse
                # logo apos receber levaria o pedido junto, em silencio. A
                # duplicidade que isso poderia causar e barrada do outro lado:
                # o agente registra o que ja executou e reconfirma sem repetir.
                linhas = conn.execute(
                    "SELECT id, command, params, created_at FROM agent_commands "
                    "WHERE agent_uuid = ? AND (status = ? OR "
                    "(status = ? AND delivered_at < ?)) ORDER BY id ASC",
                    (agent_uuid, ST_PENDING, ST_SENT,
                     agora - RETRY_AFTER)).fetchall()

                for linha in linhas:
                    if agora - linha["created_at"] > self.ttl:
                        conn.execute(
                            "UPDATE agent_commands SET status = ?, finished_at = ?, "
                            "result = ? WHERE id = ?",
                            (ST_FAILED, agora, "expired before the agent asked",
                             linha["id"]))
                        continue
                    try:
                        params = json.loads(linha["params"] or "{}")
                    except Exception:
                        params = {}
                    entregues.append({"id": linha["id"],
                                      "command": linha["command"],
                                      "params": params})
                    conn.execute(
                        "UPDATE agent_commands SET status = ?, delivered_at = ? "
                        "WHERE id = ?", (ST_SENT, agora, linha["id"]))
                conn.commit()
        except Exception as exc:
            LOG.error("Delivering commands failed: %s", exc)
        return entregues

    def report(self, command_id, ok, result=""):
        """
        Registra o desfecho informado pelo agente.

        O resultado fecha o rastro: quem pediu, quando foi entregue e o que
        aconteceu, que e o minimo para uma acao ser auditavel.
        """
        try:
            with closing(self._conn()) as conn:
                conn.execute(
                    "UPDATE agent_commands SET status = ?, finished_at = ?, "
                    "result = ? WHERE id = ?",
                    (ST_DONE if ok else ST_FAILED, time.time(),
                     str(result)[:2000], command_id))
                conn.commit()
        except Exception as exc:
            LOG.error("Recording command %s outcome failed: %s", command_id, exc)

    def expire_stuck(self, limite=STUCK_LIMIT):
        """
        Fecha comandos entregues que nunca reportaram desfecho.

        Acontece quando o agente e reiniciado ou morre no meio da execucao: o
        pedido fica eternamente "em execucao" e o analista nunca sabe se rodou.
        Marcar como falho com o motivo e mais honesto do que deixar um estado
        que nao corresponde a nada.
        """
        limiar = time.time() - limite
        try:
            with closing(self._conn()) as conn:
                cur = conn.execute(
                    "UPDATE agent_commands SET status = ?, finished_at = ?, "
                    "result = ? WHERE status = ? AND delivered_at < ?",
                    (ST_FAILED, time.time(),
                     "sem retorno do agente (provavel reinicio durante a execucao)",
                     ST_SENT, limiar))
                conn.commit()
                return cur.rowcount
        except Exception as exc:
            LOG.error("Expiring stuck commands failed: %s", exc)
            return 0

    def pending_count(self, agent_uuid):
        """Quantos pedidos ainda aguardam o agente perguntar."""
        try:
            with closing(self._conn()) as conn:
                return conn.execute(
                    "SELECT COUNT(*) FROM agent_commands WHERE agent_uuid = ? "
                    "AND status = ?", (agent_uuid, ST_PENDING)).fetchone()[0]
        except Exception:
            return 0
