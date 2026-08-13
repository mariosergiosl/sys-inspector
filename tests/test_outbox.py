# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_outbox.py
# DESCRIPTION: Testa o transporte do agente para o servidor.
#
#              A regra que sustenta tudo: uma captura so e marcada como enviada
#              quando o servidor confirma. Um reconhecimento perdido faz
#              reenviar (e o servidor deduplica pelo digest); o contrario
#              perderia prova, que e o unico erro inaceitavel aqui.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

import pytest

from src.core.database import DatabaseManager
from src.core.outbox import Outbox


def _db():
    d = tempfile.mkdtemp()
    return DatabaseManager(db_path=os.path.join(d, "outbox.db"))


def _config(**kw):
    daemon = {"server_ip": "10.0.0.1", "server_port": 8080,
              "auth_token": "segredo", "use_tls": False}
    daemon.update(kw)
    return {"daemon": daemon}


class _FakeServer(object):
    """Servidor simulado, para exercitar o transporte sem rede."""

    def __init__(self, slots=10, granted=True, status="received", fail=False):
        self.slots = slots
        self.granted = granted
        self.status = status
        self.fail = fail
        self.ingested = []
        self.slot_requests = []

    def post(self, path, payload):
        if self.fail:
            raise IOError("connection refused")
        if path.endswith("/queue/request"):
            self.slot_requests.append(payload)
            return {"granted": self.granted, "slots": self.slots,
                    "retry_after": 30}
        self.ingested.append(payload)
        return {"status": self.status}


def _outbox(db, server, **cfg):
    box = Outbox(db, _config(**cfg))
    box._post = server.post
    return box


def _queue(db, count=3):
    for i in range(count):
        db.insert_snapshot({"n": i}, agent_uuid=db.agent_id,
                           metrics={"score": i},
                           custody={"digest": "d%d" % i},
                           findings_summary={"Critical": i})


# ------------------------------------------------------------------------------
# Ativacao
# ------------------------------------------------------------------------------
def test_disabled_without_configuration():
    """Sem destino configurado o agente permanece puramente local."""
    assert Outbox(_db(), {"daemon": {}}).enabled is False


def test_placeholder_token_does_not_enable_delivery():
    """
    O valor de exemplo do arquivo de configuracao nao pode ser confundido com
    configuracao real, senao o agente tentaria enviar para um destino ficticio.
    """
    box = Outbox(_db(), _config(auth_token="CHANGE_ME"))
    assert box.enabled is False


def test_enabled_with_destination_and_token():
    """Com destino e token, a entrega fica ativa."""
    assert Outbox(_db(), _config()).enabled is True


def test_disabled_outbox_delivers_nothing():
    """Desativado, nem sequer consulta a fila local."""
    db = _db()
    _queue(db)
    assert Outbox(db, {"daemon": {}}).deliver_once() == 0


# ------------------------------------------------------------------------------
# Entrega
# ------------------------------------------------------------------------------
def test_pending_captures_are_delivered_and_marked():
    """As capturas sao entregues e saem da fila local."""
    db = _db()
    _queue(db, 3)
    server = _FakeServer()
    assert _outbox(db, server).deliver_once() == 3
    assert len(server.ingested) == 3
    assert db.get_pending_snapshots() == []


def test_delivery_carries_what_the_fleet_view_needs():
    """
    O envio leva metricas, custodia e resumo de achados: sem eles o servidor
    nao consegue montar a triagem sem descriptografar.
    """
    db = _db()
    _queue(db, 1)
    server = _FakeServer()
    _outbox(db, server).deliver_once()
    sent = server.ingested[0]
    for field in ("agent_uuid", "bundle", "metrics", "custody", "findings_summary"):
        assert field in sent, field
    assert sent["custody"]["digest"] == "d0"


def test_nothing_to_send_is_not_an_error():
    """Fila vazia simplesmente nao gera trafego."""
    server = _FakeServer()
    assert _outbox(_db(), server).deliver_once() == 0
    assert server.ingested == []


# ------------------------------------------------------------------------------
# Controle de fluxo pelo servidor
# ------------------------------------------------------------------------------
def test_agent_asks_the_server_before_sending():
    """
    Quem controla a fila e o servidor: o agente pede vaga antes de despejar o
    acumulo, o que evita que a frota inteira o afogue apos uma indisponibilidade.
    """
    db = _db()
    _queue(db, 5)
    server = _FakeServer()
    _outbox(db, server).deliver_once()
    assert server.slot_requests
    assert server.slot_requests[0]["pending"] == 5


def test_server_can_limit_how_much_is_accepted():
    """Concedendo 2 vagas, apenas 2 capturas sao enviadas."""
    db = _db()
    _queue(db, 5)
    server = _FakeServer(slots=2)
    assert _outbox(db, server).deliver_once() == 2
    assert len(db.get_pending_snapshots()) == 3


def test_server_can_ask_the_agent_to_wait():
    """Vaga negada nao envia nada e nao e tratado como falha."""
    db = _db()
    _queue(db, 3)
    server = _FakeServer(granted=False)
    box = _outbox(db, server)
    assert box.deliver_once() == 0
    assert server.ingested == []
    assert box._failures == 0


# ------------------------------------------------------------------------------
# Falha e retentativa
# ------------------------------------------------------------------------------
def test_captures_survive_a_server_outage():
    """
    Servidor fora do ar nao perde captura: ela continua pendente e sera
    reenviada. E o ponto central do store-and-forward.
    """
    db = _db()
    _queue(db, 3)
    box = _outbox(db, _FakeServer(fail=True))
    assert box.deliver_once() == 0
    assert len(db.get_pending_snapshots()) == 3


def test_backoff_grows_after_repeated_failures():
    """Falhas seguidas espacam as tentativas em vez de repetir na mesma cadencia."""
    db = _db()
    _queue(db, 1)
    box = _outbox(db, _FakeServer(fail=True))
    box.deliver_once()
    primeiro = box._next_attempt
    box._next_attempt = 0  # libera para tentar de novo
    box.deliver_once()
    assert box._failures == 2
    assert box._next_attempt > primeiro


def test_backoff_blocks_immediate_retry():
    """Durante o backoff o agente nao insiste."""
    db = _db()
    _queue(db, 1)
    server = _FakeServer(fail=True)
    box = _outbox(db, server)
    box.deliver_once()
    box._post = _FakeServer().post  # servidor voltaria, mas ainda esta em espera
    assert box.deliver_once() == 0


def test_rejected_capture_stays_in_the_queue():
    """Se o servidor recusa, a captura permanece pendente para analise."""
    db = _db()
    _queue(db, 2)
    assert _outbox(db, _FakeServer(status="rejected")).deliver_once() == 0
    assert len(db.get_pending_snapshots()) == 2


def test_duplicate_is_treated_as_delivered():
    """
    Se o servidor ja tem a captura, insistir para sempre seria pior do que
    aceitar o reconhecimento: a prova ja chegou ao destino.
    """
    db = _db()
    _queue(db, 2)
    assert _outbox(db, _FakeServer(status="duplicate")).deliver_once() == 2
    assert db.get_pending_snapshots() == []
