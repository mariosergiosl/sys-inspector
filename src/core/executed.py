# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/executed.py
# DESCRIPTION: Registro local dos comandos que este agente ja executou.
#
# WHY:         Entrega confiavel de comandos so tem duas formas possiveis, e as
#              duas sozinhas sao ruins:
#
#              - No MAXIMO uma vez: o servidor marca como entregue no momento em
#                que responde. Se o agente morrer em seguida, ninguem executa e o
#                pedido se perde.
#              - PELO MENOS uma vez: o servidor so encerra o pedido quando recebe
#                confirmacao, e reentrega enquanto nao receber. Nada se perde,
#                mas uma confirmacao perdida na rede faz o mesmo comando rodar
#                duas vezes.
#
#              Para uma acao que ALTERA o host inspecionado, rodar duas vezes nao
#              e aceitavel: seria plantar o cenario de teste em cima de si mesmo,
#              ou reiniciar o agente no meio de uma captura.
#
#              A saida e nao escolher: entregar pelo menos uma vez E tornar a
#              execucao idempotente. O agente anota o que ja executou; se o mesmo
#              pedido voltar, ele reconhece, confirma de novo e NAO executa.
#              Assim nada se perde e nada roda em duplicidade.
#
# WHERE:       O registro vive no agente, ao lado do banco local, porque e ele
#              quem sabe o que de fato executou. Guardar isso no servidor seria
#              confiar de novo na rede que ja se admitiu nao ser confiavel.
#
# NOTES:       Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import time
import logging
import sqlite3
from contextlib import closing

LOG = logging.getLogger("Executed")

# Por quanto tempo a lembranca e mantida. Precisa cobrir com folga qualquer
# janela de reentrega; passado isso, o servidor ha muito desistiu do pedido e
# guardar o registro so faria a tabela crescer sem servir a ninguem.
RETENCAO = 86400


class ExecutionLedger(object):
    """Lembra quais comandos ja foram executados por ESTE agente."""

    def __init__(self, db_path, retencao=RETENCAO):
        self.db_path = db_path
        self.retencao = retencao
        self._init_schema()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        try:
            with closing(self._conn()) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS executed_commands (
                        command_id INTEGER PRIMARY KEY,
                        command TEXT,
                        finished_at REAL NOT NULL,
                        result TEXT
                    )
                """)
                conn.commit()
        except Exception as exc:
            LOG.error("Ledger schema failed: %s", exc)

    def already_done(self, command_id):
        """
        Diz se este pedido ja foi executado, devolvendo o resultado anterior.

        Devolver o resultado importa: permite ao agente reconfirmar ao servidor
        exatamente o que aconteceu na primeira vez, em vez de responder algo
        generico sobre uma execucao que ele nao repetiu.
        """
        if command_id is None:
            return None
        try:
            with closing(self._conn()) as conn:
                linha = conn.execute(
                    "SELECT result FROM executed_commands WHERE command_id = ?",
                    (command_id,)).fetchone()
                return linha["result"] if linha else None
        except Exception as exc:
            LOG.error("Ledger lookup failed: %s", exc)
            # Na duvida, deixa executar. Perder um pedido e pior do que a
            # possibilidade remota de repeti-lo quando o proprio registro
            # esta inacessivel.
            return None

    def remember(self, command_id, command, result=""):
        """Anota que este pedido foi executado, com o que resultou."""
        if command_id is None:
            return
        try:
            with closing(self._conn()) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO executed_commands "
                    "(command_id, command, finished_at, result) "
                    "VALUES (?, ?, ?, ?)",
                    (command_id, command, time.time(), str(result)[:2000]))
                conn.execute("DELETE FROM executed_commands WHERE finished_at < ?",
                             (time.time() - self.retencao,))
                conn.commit()
        except Exception as exc:
            LOG.error("Ledger write failed: %s", exc)
