# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_command_log.py
# DESCRIPTION: Rastro auditavel dos pedidos feitos aos agentes.
#
#              Observado em campo: tres pedidos de cenario ficaram parados em
#              SENT sem qualquer desfecho, porque o agente foi reiniciado depois
#              de recolhe-los. Da interface nao havia como saber se o comando
#              chegou a rodar, o que e inaceitavel numa ferramenta que precisa
#              responder "essa acao foi executada, quando e por quem?".
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import time

import pytest

from src.core.commands import (CommandQueue, CMD_CHAOS_COLLECT, CMD_COLLECT,
                               ST_FAILED, ST_SENT)

FONTE_SERVIDOR = os.path.join("src", "controllers", "server_controller.py")


@pytest.fixture
def fila(tmp_path):
    return CommandQueue(str(tmp_path / "cmd.db"))


@pytest.fixture(scope="module")
def codigo_servidor():
    return io.open(FONTE_SERVIDOR, encoding="utf-8").read()


# ------------------------------------------------------------------------------
# COMANDO QUE NUNCA VOLTOU
# ------------------------------------------------------------------------------
def test_delivered_command_without_outcome_is_closed_as_failed(fila):
    """
    Um pedido entregue e nunca reportado nao pode ficar eternamente "em
    execucao": esse estado nao corresponde a nada e esconde a falha.
    """
    cid = fila.enqueue("agente-a", CMD_CHAOS_COLLECT)
    fila.take_for("agente-a")

    # Simula a entrega ocorrida muito antes do limite tolerado.
    with fila._conn() as conn:
        conn.execute("UPDATE agent_commands SET delivered_at = ? WHERE id = ?",
                     (time.time() - 4000, cid))

    assert fila.expire_stuck(limite=1800) == 1

    registro = fila.list_for("agente-a")[0]
    assert registro["status"] == ST_FAILED
    assert registro["result"]
    assert registro["finished_at"]


def test_recent_delivery_is_left_alone(fila):
    """
    Uma captura legitima leva tempo. Fechar um comando recem-entregue marcaria
    como falho justamente o trabalho que esta em andamento.
    """
    fila.enqueue("agente-a", CMD_COLLECT)
    fila.take_for("agente-a")

    assert fila.expire_stuck(limite=1800) == 0
    assert fila.list_for("agente-a")[0]["status"] == ST_SENT


def test_reported_command_is_not_touched(fila):
    """Quem ja reportou desfecho nao pode ser reescrito pela varredura."""
    cid = fila.enqueue("agente-a", CMD_COLLECT)
    fila.take_for("agente-a")
    fila.report(cid, True, "captura 42 concluida")

    fila.expire_stuck(limite=0)

    registro = fila.list_for("agente-a")[0]
    assert registro["status"] == "DONE"
    assert registro["result"] == "captura 42 concluida"


# ------------------------------------------------------------------------------
# O HISTORICO PRECISA SER LEGIVEL
# ------------------------------------------------------------------------------
def test_history_spans_every_agent(fila):
    """
    Sem filtro, o log mostra a frota inteira: o analista quer ver o que foi
    pedido no ambiente, nao abrir um host de cada vez.
    """
    fila.enqueue("agente-a", CMD_COLLECT, requested_by="1.2.3.4")
    fila.enqueue("agente-b", CMD_CHAOS_COLLECT, requested_by="1.2.3.4")

    agentes = set(r["agent_uuid"] for r in fila.list_for())
    assert agentes == {"agente-a", "agente-b"}


def test_history_keeps_the_four_timestamps(fila):
    """
    Pedido, entrega e termino sao momentos distintos. Guardar os tres e o que
    permite separar "o agente demorou a perguntar" de "a execucao demorou".
    """
    cid = fila.enqueue("agente-a", CMD_COLLECT, requested_by="analista")
    fila.take_for("agente-a")
    fila.report(cid, True, "ok")

    r = fila.list_for("agente-a")[0]
    assert r["created_at"] <= r["delivered_at"] <= r["finished_at"]
    assert r["requested_by"] == "analista"


def test_requester_is_recorded(fila):
    """Uma acao remota sem autor identificado nao e auditavel."""
    fila.enqueue("agente-a", CMD_COLLECT, requested_by="192.168.56.1")
    assert fila.list_for()[0]["requested_by"] == "192.168.56.1"


# ------------------------------------------------------------------------------
# A TELA
# ------------------------------------------------------------------------------
def test_server_exposes_the_log_page(codigo_servidor):
    """O rastro so serve se puder ser consultado sem abrir o banco na mao."""
    assert "'/log'" in codigo_servidor
    assert "_serve_command_log" in codigo_servidor


def test_log_page_closes_stuck_commands_before_showing(codigo_servidor):
    """
    Abrir o log e o momento natural de reconciliar: exibir SENT antigo como se
    ainda estivesse rodando reproduziria exatamente a confusao original.
    """
    assert "expire_stuck()" in codigo_servidor


def test_fleet_links_to_the_log(codigo_servidor):
    """
    Um registro que ninguem encontra nao cumpre a funcao de registro.

    O link deixou de ser escrito a mao em cada tela e passou a sair da barra de
    navegacao unica (`_NAVEGACAO`), que agora e o que precisa conter a rota.
    """
    assert '"/log"' in codigo_servidor
    assert "_barra_navegacao" in codigo_servidor
