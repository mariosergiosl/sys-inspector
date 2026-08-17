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
# Cancelado pelo operador antes de sair para o agente. E um desfecho proprio, e
# nao um apagamento: a linha fica, com quem cancelou e quando. Remover a linha
# esconderia que o pedido chegou a existir, e o valor desta fila e justamente o
# rastro de quem pediu o que.
ST_CANCELLED = "CANCELLED"

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

# Teto de pedidos aguardando por agente. Guarda contra enfileiramento em rajada:
# em campo, cerca de 30 comandos foram parar na fila de um agente durante um
# troubleshooting e rodaram todos em sequencia quando ele voltou, sem que o
# operador tivesse como interromper pela interface.
MAX_PENDING_PER_AGENT = 10


class CommandRefused(Exception):
    """
    Pedido recusado na ENTRADA da fila.

    Recusar e melhor do que deduplicar em silencio: o operador clicou esperando
    uma acao, e precisa saber que ela nao foi enfileirada e por que. Deduplicar
    calado seria mais uma fonte de divergencia entre o que a tela mostra e o que
    o sistema fara.
    """

    def __init__(self, mensagem, existing_id=None):
        Exception.__init__(self, mensagem)
        self.existing_id = existing_id


class DuplicateCommand(CommandRefused):
    """Ja ha um pedido do mesmo tipo aguardando ou em execucao neste agente."""


class QueueLimitReached(CommandRefused):
    """O agente ja acumulou pedidos demais aguardando."""


class CommandQueue(object):
    """Fila de comandos por agente, preenchida pelo analista."""

    def __init__(self, db_path, ttl=DEFAULT_TTL,
                 max_pending=MAX_PENDING_PER_AGENT):
        self.db_path = db_path
        self.ttl = ttl
        self.max_pending = max_pending
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

        Recusa tambem duplicata e rajada, levantando CommandRefused. Repetir um
        pedido que ja esta em voo nao e inofensivo: um cenario de teste se
        replanta em cima de si mesmo e perde a cena, e um restart derruba o
        agente no meio de uma captura.
        """
        if command not in ALLOWED:
            raise ValueError("command not allowed: %s" % command)

        with closing(self._conn()) as conn:
            # Mesmo tipo ja em voo para o mesmo agente e quase sempre engano:
            # clique repetido, ou nova tentativa durante uma lentidao. O estado
            # SENT entra na checagem porque entregue nao e concluido; quando o
            # agente morre com o pedido na mao, quem libera a vez e o
            # expire_stuck, nao um segundo pedido empilhado.
            ativo = conn.execute(
                "SELECT id FROM agent_commands WHERE agent_uuid = ? "
                "AND command = ? AND status IN (?, ?) "
                "ORDER BY id DESC LIMIT 1",
                (agent_uuid, command, ST_PENDING, ST_SENT)).fetchone()
            if ativo:
                raise DuplicateCommand(
                    "ja existe um '%s' aguardando ou em execucao neste agente"
                    % command, existing_id=ativo["id"])

            # Teto por agente: barra a rajada mesmo quando os pedidos sao de
            # tipos diferentes, caso que o dedup sozinho deixaria passar.
            aguardando = conn.execute(
                "SELECT COUNT(*) FROM agent_commands "
                "WHERE agent_uuid = ? AND status = ?",
                (agent_uuid, ST_PENDING)).fetchone()[0]
            if aguardando >= self.max_pending:
                raise QueueLimitReached(
                    "o agente ja tem %d pedido(s) aguardando, teto de %d; "
                    "limpe a fila antes de enfileirar outro"
                    % (aguardando, self.max_pending))

            cur = conn.execute(
                "INSERT INTO agent_commands (agent_uuid, command, params, "
                "status, created_at, requested_by) VALUES (?, ?, ?, ?, ?, ?)",
                (agent_uuid, command, json.dumps(params or {}), ST_PENDING,
                 time.time(), requested_by or ""))
            conn.commit()
            return cur.lastrowid

    def cancel(self, command_id, requested_by=""):
        """
        Cancela um pedido que ainda AGUARDA. Devolve True se cancelou.

        Nunca toca em um pedido ja entregue: quando o agente esta com a ordem na
        mao, o servidor nao tem como desfaze-la, e fingir que cancelou deixaria a
        tela mentindo sobre o que vai acontecer no host. Um SENT perdido e
        encerrado pelo expire_stuck, que e quem sabe distinguir demora de morte.

        Idempotente: cancelar de novo devolve False sem efeito, entao um clique
        repetido ou um recarregamento de pagina nao produzem dano.
        """
        quem = requested_by or "operador"
        try:
            with closing(self._conn()) as conn:
                cur = conn.execute(
                    "UPDATE agent_commands SET status = ?, finished_at = ?, "
                    "result = ? WHERE id = ? AND status = ?",
                    (ST_CANCELLED, time.time(),
                     "cancelado por %s antes da entrega" % quem,
                     command_id, ST_PENDING))
                conn.commit()
                return cur.rowcount > 0
        except Exception as exc:
            LOG.error("Cancelling command %s failed: %s", command_id, exc)
            return False

    def clear_pending(self, agent_uuid, requested_by=""):
        """
        Cancela tudo que AGUARDA neste agente e devolve quantos foram.

        E o botao de recuperacao: quando a fila entope, o operador precisa
        conseguir esvaziar pela propria tela, sem mexer no banco por fora, que
        era a unica saida durante o incidente.
        """
        quem = requested_by or "operador"
        try:
            with closing(self._conn()) as conn:
                cur = conn.execute(
                    "UPDATE agent_commands SET status = ?, finished_at = ?, "
                    "result = ? WHERE agent_uuid = ? AND status = ?",
                    (ST_CANCELLED, time.time(),
                     "fila limpa por %s" % quem, agent_uuid, ST_PENDING))
                conn.commit()
                return cur.rowcount
        except Exception as exc:
            LOG.error("Clearing queue of %s failed: %s", agent_uuid, exc)
            return 0

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
