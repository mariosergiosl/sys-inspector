# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/retention.py
# DESCRIPTION: Quanto tempo a evidencia fica, e o que se pode apagar dela.
#
# WHY:         Sem politica, o banco cresce ate acabar o disco. Medido em campo:
#              1.2 GB em um dia com dois agentes. Mas apagar evidencia nao e uma
#              decisao de armazenamento, e uma decisao PERICIAL, e por isso este
#              modulo trata as duas coisas juntas.
#
# THE PROBLEM: As capturas sao encadeadas por digest, cada uma referenciando a
#              anterior. Apagar a captura N rompe a cadeia entre N-1 e N+1, e a
#              verificacao de integridade do conjunto passa a falhar. Ou seja,
#              uma politica de retencao ingenua destroi em silencio justamente a
#              propriedade que da valor pericial ao material.
#
# THE ANSWER:  Dois modos declarados, escolhidos pelo operador e REGISTRADOS na
#              propria captura, mais a lapide.
#
#              - `forensic`: nada e apagado. Investigacao criminal ou pericia
#                nao admite lacuna, e o custo em disco e o menor dos problemas.
#              - `security`: retencao normal, mas o payload apagado deixa uma
#                LAPIDE com digest, assinatura e carimbo. A cadeia continua
#                verificavel ponta a ponta mesmo sem o conteudo.
#
#              O modo fica visivel no laudo. Sem isso, alguem apresentaria em
#              juizo material coletado em modo relaxado acreditando ser o outro,
#              que e um erro caro e irreversivel.
#
# NOTES:       Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.92.0
# ==============================================================================

import time
import logging
import sqlite3
from contextlib import closing

LOG = logging.getLogger("Retention")

# Modos de operacao. O nome aparece no laudo.
MODE_FORENSIC = "forensic"
MODE_SECURITY = "security"

# Padroes. Seguem a pratica corrente de gestao de log de seguranca: manter o
# detalhe por semanas e o rastro por muito mais tempo. Numeros conservadores de
# proposito, ja que a personalizacao existe e o dano de guardar demais e menor
# do que o de apagar cedo.
DEFAULT_MAX_AGE_DAYS = 90        # idade maxima do payload
DEFAULT_MAX_TOTAL_MB = 10240     # teto de disco para as capturas (10 GB)
DEFAULT_MAX_PER_AGENT = 500      # teto por agente, para um host falante nao
                                 # empurrar os outros para fora
DEFAULT_VACUUM_EVERY = 500       # a cada N remocoes, devolve espaco ao sistema


class RetentionPolicy(object):
    """
    Politica de retencao aplicada ao armazenamento definitivo.

    Os tres limites convivem porque respondem a perguntas diferentes: idade
    protege o disco de um historico eterno, tamanho protege de um pico, e o
    limite por agente impede que um host de ciclo curto consuma a cota de todos.
    Usar apenas contagem, como era antes, fazia um agente rapido apagar o
    proprio historico em horas enquanto ocupava o mesmo disco de um lento.
    """

    def __init__(self, db_path, config=None):
        cfg = (config or {}).get("retention", {}) or {}
        self.db_path = db_path
        self.mode = cfg.get("mode", MODE_SECURITY)
        self.max_age_days = int(cfg.get("max_age_days", DEFAULT_MAX_AGE_DAYS))
        self.max_total_mb = int(cfg.get("max_total_mb", DEFAULT_MAX_TOTAL_MB))
        self.max_per_agent = int(cfg.get("max_per_agent", DEFAULT_MAX_PER_AGENT))
        self.vacuum_every = int(cfg.get("vacuum_every", DEFAULT_VACUUM_EVERY))
        self._since_vacuum = 0

    # --------------------------------------------------------------------------
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    @property
    def preserves_everything(self):
        """No modo forense nada e apagado, e o disco e problema do operador."""
        return self.mode == MODE_FORENSIC

    # --------------------------------------------------------------------------
    def _tombstone(self, conn, ids):
        """
        Substitui o conteudo por uma lapide, preservando a cadeia.

        Guarda-se digest, digest anterior, assinatura e carimbo: e o suficiente
        para verificar que a sequencia de capturas nao foi adulterada, mesmo sem
        o conteudo. Apagar a linha inteira romperia o encadeamento e faria toda
        a verificacao posterior falhar, sem que ninguem soubesse por que.
        """
        conn.execute("UPDATE snapshots SET json_blob = NULL, purged_at = ? "
                     "WHERE id IN (%s)" % ",".join("?" * len(ids)),
                     [time.time()] + list(ids))

    def _ensure_schema(self, conn):
        try:
            conn.execute("ALTER TABLE snapshots ADD COLUMN purged_at REAL")
        except sqlite3.OperationalError:
            pass   # ja existe

    # --------------------------------------------------------------------------
    def apply(self):
        """
        Aplica a politica e devolve o que foi feito.

        Nada e removido antes de a captura estar efetivamente gravada; este
        metodo roda depois da ingestao, nunca durante.
        """
        if self.preserves_everything:
            return {"mode": self.mode, "purged": 0, "reason": "forensic mode"}

        removidos = 0
        try:
            with closing(self._conn()) as conn:
                self._ensure_schema(conn)
                removidos += self._por_idade(conn)
                removidos += self._por_agente(conn)
                removidos += self._por_tamanho(conn)
                conn.commit()
        except Exception as exc:
            LOG.error("Applying retention failed: %s", exc)
            return {"mode": self.mode, "purged": 0, "error": str(exc)}

        self._since_vacuum += removidos
        if self._since_vacuum >= self.vacuum_every:
            self.reclaim_space()
            self._since_vacuum = 0

        return {"mode": self.mode, "purged": removidos}

    def _alvos(self, conn, sql, params):
        linhas = conn.execute(sql, params).fetchall()
        return [r["id"] for r in linhas]

    def _por_idade(self, conn):
        """O detalhe antigo perde utilidade operacional; o rastro permanece."""
        if self.max_age_days <= 0:
            return 0
        limite = time.time() - (self.max_age_days * 86400)
        ids = self._alvos(conn,
                          "SELECT id FROM snapshots WHERE timestamp < ? "
                          "AND json_blob IS NOT NULL", (limite,))
        if ids:
            self._tombstone(conn, ids)
        return len(ids)

    def _por_agente(self, conn):
        """Impede que um host falante consuma a cota da frota inteira."""
        if self.max_per_agent <= 0:
            return 0
        total = 0
        for (uuid,) in conn.execute(
                "SELECT DISTINCT agent_uuid FROM snapshots").fetchall():
            ids = self._alvos(
                conn,
                "SELECT id FROM snapshots WHERE agent_uuid = ? "
                "AND json_blob IS NOT NULL ORDER BY id DESC LIMIT -1 OFFSET ?",
                (uuid, self.max_per_agent))
            if ids:
                self._tombstone(conn, ids)
                total += len(ids)
        return total

    def _por_tamanho(self, conn):
        """
        Teto de disco, aplicado do mais antigo para o mais novo.

        E o limite que de fato protege o servidor: idade e contagem podem ser
        satisfeitas e ainda assim um pico de capturas grandes encher o volume.
        """
        if self.max_total_mb <= 0:
            return 0
        teto = self.max_total_mb * 1048576
        total = conn.execute("SELECT COALESCE(SUM(LENGTH(json_blob)), 0) "
                             "FROM snapshots").fetchone()[0]
        if total <= teto:
            return 0

        removidos = []
        for linha in conn.execute(
                "SELECT id, LENGTH(json_blob) AS peso FROM snapshots "
                "WHERE json_blob IS NOT NULL ORDER BY id ASC"):
            if total <= teto:
                break
            removidos.append(linha["id"])
            total -= linha["peso"] or 0
        if removidos:
            self._tombstone(conn, removidos)
        return len(removidos)

    # --------------------------------------------------------------------------
    def reclaim_space(self):
        """
        Devolve ao sistema o espaco das linhas removidas.

        O SQLite marca a pagina como livre e a reutiliza, mas NUNCA encolhe o
        arquivo sozinho. Sem isto, apagar capturas nao libera um byte de disco e
        a politica de retencao parece nao funcionar.
        """
        try:
            with closing(self._conn()) as conn:
                conn.execute("VACUUM")
            LOG.info("[RETENTION] Space reclaimed from the database")
            return True
        except Exception as exc:
            LOG.error("VACUUM failed: %s", exc)
            return False

    # --------------------------------------------------------------------------
    def usage(self):
        """Situacao atual, para o painel e para decidir se a politica basta."""
        try:
            with closing(self._conn()) as conn:
                dados = conn.execute(
                    "SELECT COUNT(*) AS n, "
                    "COALESCE(SUM(LENGTH(json_blob)), 0) AS peso, "
                    "SUM(CASE WHEN json_blob IS NULL THEN 1 ELSE 0 END) AS lapides "
                    "FROM snapshots").fetchone()
                paginas = conn.execute("PRAGMA page_count").fetchone()[0]
                livres = conn.execute("PRAGMA freelist_count").fetchone()[0]
                tam = conn.execute("PRAGMA page_size").fetchone()[0]
                return {"mode": self.mode,
                        "snapshots": dados["n"],
                        "tombstones": dados["lapides"] or 0,
                        "payload_mb": round((dados["peso"] or 0) / 1048576.0, 1),
                        "file_mb": round(paginas * tam / 1048576.0, 1),
                        "reclaimable_mb": round(livres * tam / 1048576.0, 1)}
        except Exception as exc:
            LOG.error("Reading usage failed: %s", exc)
            return {}
