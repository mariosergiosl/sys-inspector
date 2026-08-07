# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/events.py
# DESCRIPTION: O evento como entidade de primeira classe.
#
# WHY:         Ate aqui a ferramenta guarda ESTADO: como o host estava no
#              instante da captura. Estado responde "o que existe". A pericia
#              precisa de outra resposta, que estado nenhum alcanca: "o que
#              aconteceu, e em que ordem".
#
#              A frase que so um evento produz e do tipo "o cron foi plantado
#              quatro segundos DEPOIS de o shell reverso abrir". Nenhuma captura
#              isolada contem isso, por mais completa que seja, porque ordem nao
#              e propriedade de um retrato. E dessa frase que sai a conclusao de
#              um laudo, e e por ela que este modulo existe.
#
# ADDITIVE:    Nao substitui nem migra o modelo de capturas. Uma tabela ao lado,
#              alimentada pelo que ja se coleta. Capturas continuam sendo a
#              evidencia assinada; eventos sao a leitura temporal dela. Trocar um
#              pelo outro exigiria reescrever a cadeia de custodia inteira para
#              ganhar o que se ganha somando.
#
# CLOCK:       Todo evento carrega o desvio de relogio conhecido do host que o
#              produziu. Ordenar eventos de maquinas diferentes sem isso gera uma
#              sequencia plausivel e ERRADA, o que e pior que nao ter sequencia:
#              parece resposta. O desvio viaja junto para que a ordenacao seja
#              verificavel e nao confiada.
#
# NOTES:       Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import json
import time
import hashlib
import logging
import sqlite3
from contextlib import closing

LOG = logging.getLogger("Events")

# ------------------------------------------------------------------------------
# TIPOS DE EVENTO
#
# Vocabulario fechado, pelo mesmo motivo da escala unica de severidade: eventos
# de fontes diferentes so se comparam se falarem a mesma lingua. Um tipo novo
# entra aqui e passa a valer para correlacao, ordenacao e exibicao de uma vez.
# ------------------------------------------------------------------------------
EV_PROCESS_START = "process.start"
EV_PROCESS_END = "process.end"
EV_CONNECTION = "network.connect"
EV_FILE_WRITE = "file.write"
EV_FILE_DELETE = "file.delete"
EV_PERSISTENCE = "persistence.created"
EV_FINDING = "finding.raised"
EV_AUTH = "auth.session"
EV_CAPTURE = "capture.taken"
EV_COMMAND = "command.executed"

TIPOS = (EV_PROCESS_START, EV_PROCESS_END, EV_CONNECTION, EV_FILE_WRITE,
         EV_FILE_DELETE, EV_PERSISTENCE, EV_FINDING, EV_AUTH, EV_CAPTURE,
         EV_COMMAND)


def make_event(ts, tipo, agent_uuid, subject="", detail=None,
               severity=None, clock_offset=0.0, capture_id=None):
    """
    Monta um evento normalizado.

    PARAMETER ts: quando aconteceu, segundo o relogio do HOST que observou.
    PARAMETER clock_offset: desvio conhecido desse relogio, em segundos. E o que
                            permite comparar com eventos de outra maquina.
    """
    return {"ts": float(ts or 0),
            "type": tipo,
            "agent_uuid": agent_uuid or "",
            "subject": str(subject or "")[:400],
            "detail": detail or {},
            "severity": severity or "",
            "clock_offset": float(clock_offset or 0.0),
            "capture_id": capture_id}


def event_fingerprint(evento):
    """
    Identidade estavel do evento, para nao duplicar no reenvio.

    Inclui o instante porque duas execucoes do mesmo comando em momentos
    distintos sao eventos DIFERENTES; e justamente essa repeticao no tempo que a
    correlacao usa para distinguir acao pontual de persistencia ativa.
    """
    base = "|".join([str(evento.get("ts")), evento.get("type", ""),
                     evento.get("agent_uuid", ""), evento.get("subject", "")])
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:32]


def corrected_ts(evento):
    """
    Instante corrigido pelo desvio de relogio do host.

    E o unico valor que pode ser usado para ordenar eventos de maquinas
    diferentes. O instante bruto serve para o laudo daquele host; a ordem entre
    hosts exige a correcao, senao 12 segundos de defasagem invertem a relacao
    entre causa e efeito.
    """
    return float(evento.get("ts", 0)) - float(evento.get("clock_offset", 0.0))


class EventStore(object):
    """Armazenamento dos eventos, ao lado das capturas."""

    def __init__(self, db_path):
        self.db_path = db_path
        self._init_schema()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        try:
            with closing(self._conn()) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        fingerprint TEXT UNIQUE,
                        ts REAL NOT NULL,
                        corrected_ts REAL NOT NULL,
                        type TEXT NOT NULL,
                        agent_uuid TEXT NOT NULL,
                        subject TEXT,
                        detail TEXT,
                        severity TEXT,
                        clock_offset REAL DEFAULT 0,
                        capture_id INTEGER
                    )
                """)
                # A consulta dominante e "o que aconteceu nesta janela, em
                # ordem", entre um ou varios hosts. O indice segue essa forma.
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_tempo "
                             "ON events(corrected_ts)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ev_agente "
                             "ON events(agent_uuid, corrected_ts)")
                conn.commit()
        except Exception as exc:
            LOG.error("Event schema failed: %s", exc)

    # --------------------------------------------------------------------------
    def add(self, eventos):
        """
        Grava eventos, ignorando os que ja existem.

        A deduplicacao pela impressao digital permite reenvio sem cuidado
        especial: a mesma captura processada duas vezes nao duplica a linha do
        tempo, o que seria pior que perder um evento, porque inventaria
        repeticao onde nao houve.
        """
        if not eventos:
            return 0
        gravados = 0
        try:
            with closing(self._conn()) as conn:
                for ev in eventos:
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO events (fingerprint, ts, "
                            "corrected_ts, type, agent_uuid, subject, detail, "
                            "severity, clock_offset, capture_id) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (event_fingerprint(ev), ev.get("ts"),
                             corrected_ts(ev), ev.get("type"),
                             ev.get("agent_uuid"), ev.get("subject"),
                             json.dumps(ev.get("detail") or {}),
                             ev.get("severity") or "",
                             ev.get("clock_offset") or 0.0,
                             ev.get("capture_id")))
                        gravados += conn.total_changes and 1 or 0
                    except Exception:
                        continue
                conn.commit()
        except Exception as exc:
            LOG.error("Storing events failed: %s", exc)
        return gravados

    def timeline(self, inicio=None, fim=None, agent_uuid=None, limit=500):
        """
        A linha do tempo: tudo que aconteceu, em ordem, de um ou de todos.

        Ordenada pelo instante CORRIGIDO, porque e o unico comparavel entre
        maquinas. Sem filtro de agente, atravessa a frota, que e onde aparece o
        encadeamento que uma maquina sozinha nao mostra.
        """
        sql = "SELECT * FROM events WHERE 1=1"
        params = []
        if inicio is not None:
            sql += " AND corrected_ts >= ?"
            params.append(float(inicio))
        if fim is not None:
            sql += " AND corrected_ts <= ?"
            params.append(float(fim))
        if agent_uuid:
            sql += " AND agent_uuid = ?"
            params.append(agent_uuid)
        sql += " ORDER BY corrected_ts ASC LIMIT ?"
        params.append(int(limit))

        try:
            with closing(self._conn()) as conn:
                saida = []
                for r in conn.execute(sql, params):
                    item = dict(r)
                    try:
                        item["detail"] = json.loads(item.get("detail") or "{}")
                    except Exception:
                        item["detail"] = {}
                    saida.append(item)
                return saida
        except Exception as exc:
            LOG.error("Reading timeline failed: %s", exc)
            return []

    def stats(self):
        """Quantos eventos, de que tipo, para o painel."""
        try:
            with closing(self._conn()) as conn:
                total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                por_tipo = dict(
                    (r[0], r[1]) for r in conn.execute(
                        "SELECT type, COUNT(*) FROM events GROUP BY type"))
                return {"total": total, "by_type": por_tipo}
        except Exception:
            return {"total": 0, "by_type": {}}


# ------------------------------------------------------------------------------
# EXTRACAO A PARTIR DO QUE JA SE COLETA
# ------------------------------------------------------------------------------
def events_from_capture(payload, agent_uuid, capture_id=None, clock_offset=0.0):
    """
    Deriva eventos de uma captura ja existente.

    Nada de novo e coletado: o que se faz e LER como sequencia o que ja estava
    guardado como estado. Por isso o modelo pode ser introduzido sem tocar no
    agente, e por isso capturas antigas tambem alimentam a linha do tempo.

    O inicio de um processo tem instante proprio (start_time) e portanto vira
    evento com hora real. Um achado nao tem instante proprio, entao herda o da
    captura: e o momento em que passou a ser observado, e nao quando o artefato
    surgiu, distincao que o painel precisa preservar para nao afirmar demais.
    """
    eventos = []
    if not payload:
        return eventos

    ts_captura = float(payload.get("timestamp") or time.time())

    for proc in (payload.get("processes") or {}).values():
        if not isinstance(proc, dict):
            continue
        inicio = proc.get("start_time") or 0
        if not inicio:
            continue
        eventos.append(make_event(
            inicio, EV_PROCESS_START, agent_uuid,
            subject=(proc.get("cmd") or "")[:300],
            detail={"pid": proc.get("pid"), "ppid": proc.get("ppid"),
                    "user": proc.get("username"),
                    "score": proc.get("anomaly_score") or 0},
            severity="High" if (proc.get("anomaly_score") or 0) >= 70 else "",
            clock_offset=clock_offset, capture_id=capture_id))

        for conexao in (proc.get("connections") or [])[:10]:
            eventos.append(make_event(
                inicio, EV_CONNECTION, agent_uuid, subject=str(conexao),
                detail={"pid": proc.get("pid"), "cmd": (proc.get("cmd") or "")[:200]},
                clock_offset=clock_offset, capture_id=capture_id))

    for f in (payload.get("findings") or []):
        if not isinstance(f, dict):
            continue
        eventos.append(make_event(
            ts_captura, EV_FINDING, agent_uuid,
            subject=(f.get("title") or "")[:300],
            detail={"source": f.get("source"), "technique": f.get("technique"),
                    "target": f.get("target"),
                    "observed_only": True},
            severity=f.get("severity") or "",
            clock_offset=clock_offset, capture_id=capture_id))

    eventos.append(make_event(
        ts_captura, EV_CAPTURE, agent_uuid,
        subject="captura #%s" % (capture_id or "?"),
        detail={"processes": len(payload.get("processes") or {}),
                "findings": len(payload.get("findings") or [])},
        clock_offset=clock_offset, capture_id=capture_id))

    return eventos
