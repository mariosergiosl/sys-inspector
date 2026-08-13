# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_ingest.py
# DESCRIPTION: Testa a fila de ingestao do servidor.
#
#              MECANISMO UNICO: uma captura vinda da rede e uma produzida na
#              propria maquina seguem o mesmo caminho, entram na fila e sao
#              drenadas pelo mesmo processador. Server e live compartilham a
#              regra de enfileiramento, de prioridade e de deduplicacao.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

import pytest

from src.core.database import DatabaseManager
from src.core.ingest import (IngestQueue, process_batch, PRIORITY_DEFAULT,
                             ST_PENDING)


@pytest.fixture
def env():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "server.db")
    return IngestQueue(path), DatabaseManager(db_path=path)


def _payload(digest="d1", critical=0):
    return {"bundle": {"cipher": "x"},
            "metrics": {"score": 10, "cpu": 1, "mem": 2, "pids": 3},
            "custody": {"digest": digest, "previous_digest": "0" * 64},
            "findings_summary": {"Critical": critical}}


# ------------------------------------------------------------------------------
# Entrada
# ------------------------------------------------------------------------------
def test_capture_is_accepted(env):
    """Uma captura entregue entra na fila."""
    queue, _ = env
    assert queue.enqueue("agent-a", _payload()) == "received"
    assert queue.stats()["pending"] == 1


def test_resent_capture_is_not_duplicated(env):
    """
    Reenvio apos um reconhecimento perdido nao pode virar duas evidencias. A
    identidade e o digest da custodia.
    """
    queue, _ = env
    assert queue.enqueue("agent-a", _payload("mesmo")) == "received"
    assert queue.enqueue("agent-a", _payload("mesmo")) == "duplicate"
    assert queue.stats()["pending"] == 1


def test_captures_without_digest_still_enter(env):
    """Captura sem custodia (agente antigo) e aceita em vez de recusada."""
    queue, _ = env
    assert queue.enqueue("a", {"bundle": {}}) == "received"


def test_local_and_remote_share_the_queue(env):
    """
    O mecanismo e o mesmo para a coleta local e para o agente remoto: as duas
    origens convivem na mesma fila.
    """
    queue, _ = env
    queue.enqueue("local", _payload("d-local"), origin="local")
    queue.enqueue("remoto", _payload("d-remoto"), origin="remote")
    origens = {i["origin"] for i in queue.next_batch()}
    assert origens == {"local", "remote"}


# ------------------------------------------------------------------------------
# Prioridade
# ------------------------------------------------------------------------------
def test_default_priority(env):
    """Sem configuracao, todo agente entra na prioridade padrao."""
    queue, _ = env
    assert queue.get_priority("novo") == PRIORITY_DEFAULT


def test_priority_changes_the_order(env):
    """
    Caso pratico: o host sob investigacao passa na frente sem que a coleta da
    frota precise parar.
    """
    queue, _ = env
    queue.enqueue("comum", _payload("d1"))
    queue.set_priority("urgente", 1)
    queue.enqueue("urgente", _payload("d2"))
    assert queue.next_batch()[0]["agent_uuid"] == "urgente"


def test_priority_change_reorders_what_is_already_waiting(env):
    """
    Mudar a prioridade precisa valer para o que JA esta na fila; do contrario
    promover um agente so afetaria as proximas capturas.
    """
    queue, _ = env
    queue.enqueue("comum", _payload("d1"))
    queue.enqueue("alvo", _payload("d2"))
    queue.set_priority("alvo", 1)
    assert queue.next_batch()[0]["agent_uuid"] == "alvo"


# ------------------------------------------------------------------------------
# Concessao de vaga
# ------------------------------------------------------------------------------
def test_server_grants_slots(env):
    """O servidor responde quantas capturas aceita."""
    queue, _ = env
    answer = queue.grant_slots("a", pending=5)
    assert answer["granted"] is True
    assert answer["slots"] >= 1


def test_slots_never_exceed_what_the_agent_has(env):
    """Nao adianta conceder mais vagas do que o agente tem para enviar."""
    queue, _ = env
    assert queue.grant_slots("a", pending=2)["slots"] <= 2


def test_server_asks_to_wait_when_overloaded(env):
    """
    Com a fila muito cheia o servidor pede espera, em vez de aceitar sem limite
    e acumular ate cair.
    """
    queue, _ = env
    for i in range(queue.max_slots * 20 + 1):
        queue.enqueue("a", _payload("d%d" % i))
    answer = queue.grant_slots("a", pending=1)
    assert answer["granted"] is False
    assert answer["retry_after"] > 0


# ------------------------------------------------------------------------------
# Processamento
# ------------------------------------------------------------------------------
def test_queue_is_drained_into_storage(env):
    """A captura sai da fila e vira evidencia guardada."""
    queue, db = env
    queue.enqueue("agent-a", _payload(critical=2))
    assert process_batch(queue, db) == 1
    assert queue.stats()["pending"] == 0
    assert queue.stats()["done"] == 1


def test_processed_capture_feeds_the_fleet_view(env):
    """
    Depois de processada, a captura alimenta a triagem da frota com as
    contagens que vieram do agente.
    """
    queue, db = env
    queue.enqueue("agent-a", _payload(critical=3))
    process_batch(queue, db)
    fleet = {i["uuid"]: i for i in db.get_fleet_status()}
    assert fleet["agent-a"]["findings"]["Critical"] == 3
    assert fleet["agent-a"]["alert_score"] == 10


def test_custody_survives_the_transport(env):
    """O digest chega ao servidor, permitindo verificar a cadeia do agente."""
    queue, db = env
    queue.enqueue("agent-a", _payload("digest-do-agente"))
    process_batch(queue, db)
    assert db.get_last_digest("agent-a") == "digest-do-agente"


def test_empty_queue_processes_nothing(env):
    """Fila vazia nao gera trabalho nem erro."""
    queue, db = env
    assert process_batch(queue, db) == 0


def test_stats_report_pending_per_agent(env):
    """O painel de fila precisa saber quem esta esperando e quanto."""
    queue, _ = env
    queue.enqueue("a", _payload("d1"))
    queue.enqueue("a", _payload("d2"))
    queue.enqueue("b", _payload("d3"))
    por_agente = queue.stats()["by_agent"]
    assert por_agente["a"]["pending"] == 2
    assert por_agente["b"]["pending"] == 1
