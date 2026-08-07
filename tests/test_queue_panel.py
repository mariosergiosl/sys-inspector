# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_queue_panel.py
# DESCRIPTION: Ordem de atendimento da fila de ingestao.
#
#              A fila existe para o servidor nao ser derrubado por uma frota
#              inteira reportando ao mesmo tempo. Numa investigacao, porem, um
#              host importa mais que os outros, e o analista precisa poder
#              coloca-lo na frente sem parar a coleta dos demais.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

from src.core.ingest import IngestQueue, PRIORITY_DEFAULT

FONTE = os.path.join("src", "controllers", "server_controller.py")


@pytest.fixture
def fila(tmp_path):
    return IngestQueue(str(tmp_path / "q.db"))


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


# ------------------------------------------------------------------------------
# PRIORIDADE
# ------------------------------------------------------------------------------
def test_unknown_agent_uses_the_default(fila):
    """Um agente sem ajuste explicito nao pode ficar sem posicao na fila."""
    assert fila.get_priority("nunca-visto") == PRIORITY_DEFAULT


def test_priority_survives_a_reread(fila):
    fila.set_priority("agente-a", 10)
    assert fila.get_priority("agente-a") == 10


def test_priority_change_reorders_what_is_already_waiting(fila):
    """
    Se so valesse para o que chega depois, promover um host sob investigacao nao
    adiantaria nada: o que ja estava na fila continuaria na frente.
    """
    fila.enqueue("agente-a", {"x": 1})
    fila.enqueue("agente-b", {"x": 2})
    fila.set_priority("agente-b", 5)

    lote = fila.next_batch(limit=2)
    assert lote[0]["agent_uuid"] == "agente-b"


def test_stats_report_what_is_waiting_per_agent(fila):
    """O painel precisa mostrar quem esta acumulando, nao so o total."""
    fila.enqueue("agente-a", {"x": 1})
    fila.enqueue("agente-a", {"x": 2})
    fila.enqueue("agente-b", {"x": 3})

    stats = fila.stats()
    assert stats["pending"] == 3
    assert stats["by_agent"]["agente-a"]["pending"] == 2


# ------------------------------------------------------------------------------
# A TELA
# ------------------------------------------------------------------------------
def test_server_exposes_the_queue_panel(codigo):
    assert "'/queue'" in codigo
    assert "_serve_queue" in codigo


def test_priority_can_be_changed_from_the_panel(codigo):
    assert "'/priority/'" in codigo
    assert "set_priority" in codigo


def test_panel_explains_the_direction_of_the_scale(codigo):
    """
    "Prioridade 10" nao diz por si se e mais ou menos urgente. Sem a legenda, o
    analista pode atrasar justamente o host que queria adiantar.
    """
    bloco = codigo.split("def _serve_queue")[1].split("def _serve_command_log")[0]
    assert "menor" in bloco


def test_panel_escapes_agent_names(codigo):
    """
    Hostname vem do host inspecionado, que pode estar comprometido. Sem escapar,
    ele injetaria HTML na tela de quem investiga.

    A identificacao do agente (nome, FQDN, IP e UUID) passou a ser feita por
    `_identifica_agente`, entao e la que o escape precisa estar; a tela so o
    chama. O teste confere os dois lados para o escape nao se perder na mudanca.
    """
    bloco = codigo.split("def _serve_queue")[1].split("def _serve_command_log")[0]
    assert "_identifica_agente(" in bloco

    helper = codigo.split("def _identifica_agente")[1].split("def _legenda_risco")[0]
    for campo in ("host", "fqdn", "ip", "uuid"):
        assert "_esc(%s)" % campo in helper


def test_queue_is_reachable_from_the_fleet(codigo):
    """A rota vem da barra de navegacao unica, e nao de um link por tela."""
    assert '"/queue"' in codigo
    assert "_barra_navegacao" in codigo
