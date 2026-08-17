# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_command_recovery.py
# DESCRIPTION: Controles de RECUPERACAO da fila de comandos: cancelar um pedido
#              e limpar a fila de um agente.
#
# WHY:         No incidente da fila entupida o operador ficou preso: nao havia
#              como ver, cancelar ou limpar pela interface, e a unica saida era
#              mexer no banco por fora. O objetivo destes controles e que o
#              operador consiga DIAGNOSTICAR e RECUPERAR pela propria tela.
#
#              A regra que separa o seguro do perigoso: cancelar age apenas
#              sobre o que AGUARDA. Um pedido ja entregue esta com o agente, e o
#              servidor nao tem como desfaze-lo; dizer que cancelou seria a tela
#              mentindo sobre o que vai acontecer no host.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

import pytest

from src.core.commands import (CommandQueue, CMD_COLLECT, CMD_CHAOS_COLLECT,
                               CMD_RESTART, ST_CANCELLED, ST_SENT)


@pytest.fixture
def fila():
    d = tempfile.mkdtemp()
    return CommandQueue(os.path.join(d, "cmd.db"))


def _status(fila, ident):
    return {r["id"]: r["status"] for r in fila.list_for()}.get(ident)


# ------------------------------------------------------------------------------
# Cancelar um pedido
# ------------------------------------------------------------------------------
def test_pending_command_can_be_cancelled(fila):
    """O que ainda aguarda pode ser cancelado, e sai da contagem."""
    ident = fila.enqueue("a1", CMD_CHAOS_COLLECT)
    assert fila.cancel(ident, requested_by="mario") is True
    assert fila.pending_count("a1") == 0
    assert _status(fila, ident) == ST_CANCELLED


def test_cancelled_command_is_never_delivered(fila):
    """Cancelado nao chega ao agente."""
    ident = fila.enqueue("a1", CMD_CHAOS_COLLECT)
    fila.cancel(ident)
    assert fila.take_for("a1") == []


def test_delivered_command_is_not_cancelled(fila):
    """
    Pedido ja entregue nao e cancelavel: o agente esta com a ordem na mao e o
    servidor nao tem como desfaze-la.
    """
    ident = fila.enqueue("a1", CMD_RESTART)
    fila.take_for("a1")
    assert fila.cancel(ident) is False
    assert _status(fila, ident) == ST_SENT


def test_cancel_is_idempotent(fila):
    """Cancelar duas vezes nao produz efeito novo (clique repetido, reload)."""
    ident = fila.enqueue("a1", CMD_COLLECT)
    assert fila.cancel(ident) is True
    assert fila.cancel(ident) is False


def test_cancel_keeps_the_trail(fila):
    """
    Cancelar MARCA, nao apaga: a linha continua na lista com quem cancelou.
    Remover esconderia que o pedido chegou a existir.
    """
    ident = fila.enqueue("a1", CMD_COLLECT, requested_by="dashboard")
    fila.cancel(ident, requested_by="mario")
    registro = [r for r in fila.list_for("a1") if r["id"] == ident][0]
    assert registro["status"] == ST_CANCELLED
    assert "mario" in (registro["result"] or "")
    assert registro["requested_by"] == "dashboard"
    assert registro["finished_at"]


# ------------------------------------------------------------------------------
# Limpar a fila do agente
# ------------------------------------------------------------------------------
def test_clearing_removes_only_what_is_waiting(fila):
    """
    Limpar cancela os que aguardam e NAO toca no que ja foi entregue, que e a
    exigencia de idempotencia do controle de recuperacao.
    """
    entregue = fila.enqueue("a1", CMD_CHAOS_COLLECT)
    fila.take_for("a1")
    fila.enqueue("a1", CMD_COLLECT)
    fila.enqueue("a1", CMD_RESTART)

    assert fila.clear_pending("a1", requested_by="mario") == 2
    assert fila.pending_count("a1") == 0
    assert _status(fila, entregue) == ST_SENT


def test_clearing_one_agent_does_not_touch_the_fleet(fila):
    """Limpar a fila de um host nao mexe na dos outros."""
    fila.enqueue("a1", CMD_COLLECT)
    fila.enqueue("a2", CMD_COLLECT)
    fila.clear_pending("a1")
    assert fila.pending_count("a2") == 1


def test_clearing_an_empty_queue_is_harmless(fila):
    """Limpar fila vazia devolve zero, sem erro."""
    assert fila.clear_pending("a1") == 0


def test_slot_is_free_after_clearing(fila):
    """
    Depois de limpar, o mesmo comando pode ser enfileirado de novo: e assim que
    o operador se recupera de uma fila entupida sem esperar o TTL.
    """
    fila.enqueue("a1", CMD_CHAOS_COLLECT)
    fila.clear_pending("a1")
    assert fila.enqueue("a1", CMD_CHAOS_COLLECT)
