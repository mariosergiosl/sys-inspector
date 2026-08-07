# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_commands.py
# DESCRIPTION: Fila de comandos do analista para o agente.
#
#              DIRECAO DO TRAFEGO: o servidor nunca abre conexao com o agente.
#              O agente pergunta e escreve. O host inspecionado nao expoe porta
#              nem servico escutando, o que evita acrescentar superficie de
#              ataque justamente na maquina sob investigacao e funciona atras
#              de NAT ou firewall restritivo.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import time
import tempfile

import pytest

from src.core.commands import (CommandQueue, CMD_COLLECT, CMD_CHAOS_COLLECT,
                               CMD_RESTART, ST_PENDING, ST_SENT, ST_DONE,
                               ST_FAILED)


@pytest.fixture
def fila():
    d = tempfile.mkdtemp()
    return CommandQueue(os.path.join(d, "cmd.db"))


def test_queued_command_waits_for_the_agent(fila):
    """O pedido fica aguardando; nada e executado a distancia pelo servidor."""
    fila.enqueue("a1", CMD_COLLECT, requested_by="dashboard")
    assert fila.pending_count("a1") == 1


def test_agent_receives_only_its_own_commands(fila):
    """Um agente nunca recebe ordem destinada a outro."""
    fila.enqueue("a1", CMD_COLLECT)
    fila.enqueue("a2", CMD_RESTART)
    recebidos = fila.take_for("a1")
    assert len(recebidos) == 1
    assert recebidos[0]["command"] == CMD_COLLECT


def test_command_is_delivered_once(fila):
    """
    Entregue uma vez: se o agente perguntar de novo, nao repete a acao. Uma
    coleta duplicada seria desperdicio; um restart duplicado, dano.
    """
    fila.enqueue("a1", CMD_COLLECT)
    assert len(fila.take_for("a1")) == 1
    assert fila.take_for("a1") == []


def test_only_known_commands_are_accepted(fila):
    """
    Lista fechada: o servidor nao manda o agente executar texto arbitrario,
    mesmo que a interface seja comprometida.
    """
    for proibido in ("rm -rf /", "shell", "exec", ""):
        with pytest.raises(ValueError):
            fila.enqueue("a1", proibido)


def test_all_supported_actions_are_accepted(fila):
    """As tres acoes previstas funcionam."""
    for acao in (CMD_COLLECT, CMD_CHAOS_COLLECT, CMD_RESTART):
        assert fila.enqueue("a1", acao)


def test_expired_command_is_not_delivered():
    """
    Pedido esquecido nao pode ser executado muito depois, quando o motivo que
    o gerou ja passou.
    """
    d = tempfile.mkdtemp()
    curta = CommandQueue(os.path.join(d, "c.db"), ttl=0)
    curta.enqueue("a1", CMD_COLLECT)
    time.sleep(0.01)
    assert curta.take_for("a1") == []
    assert curta.list_for("a1")[0]["status"] == ST_FAILED


def test_outcome_is_recorded(fila):
    """O desfecho fecha o rastro: quem pediu, quando chegou, o que aconteceu."""
    ident = fila.enqueue("a1", CMD_COLLECT, requested_by="mario")
    fila.take_for("a1")
    fila.report(ident, True, "capture collected")
    registro = fila.list_for("a1")[0]
    assert registro["status"] == ST_DONE
    assert registro["result"] == "capture collected"
    assert registro["requested_by"] == "mario"
    assert registro["delivered_at"] and registro["finished_at"]


def test_failure_is_recorded_too(fila):
    """Falha tambem fica registrada, com o motivo."""
    ident = fila.enqueue("a1", CMD_CHAOS_COLLECT)
    fila.take_for("a1")
    fila.report(ident, False, "chaos_maker.sh not installed")
    assert fila.list_for("a1")[0]["status"] == ST_FAILED


def test_state_moves_pending_to_sent(fila):
    """O estado acompanha a entrega, para o painel mostrar o que falta."""
    fila.enqueue("a1", CMD_COLLECT)
    assert fila.list_for("a1")[0]["status"] == ST_PENDING
    fila.take_for("a1")
    assert fila.list_for("a1")[0]["status"] == ST_SENT


def test_pending_count_ignores_delivered(fila):
    """O contador do painel reflete o que ainda aguarda o agente perguntar."""
    fila.enqueue("a1", CMD_COLLECT)
    fila.enqueue("a1", CMD_RESTART)
    assert fila.pending_count("a1") == 2
    fila.take_for("a1")
    assert fila.pending_count("a1") == 0
