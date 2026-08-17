# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_command_enqueue_guard.py
# DESCRIPTION: Guarda a ENTRADA da fila de comandos contra duplicata e rajada.
#
# WHY:         Durante o troubleshooting de um servidor caido, cerca de 30
#              pedidos de cenario foram enfileirados para o mesmo agente. Quando
#              ele voltou, executou os 30 em sequencia, cada um replantando o
#              cenario sobre o anterior, e o operador nao tinha como interromper
#              pela interface. A fila aceitava tudo: so validava se o comando
#              estava na lista prevista.
#
#              Recusar na entrada e melhor do que deduplicar em silencio. O
#              operador clicou esperando uma acao; precisa saber que ela nao foi
#              enfileirada, e por que.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

import pytest

from src.core.commands import (CommandQueue, CMD_COLLECT, CMD_CHAOS_COLLECT,
                               CMD_RESTART, DuplicateCommand,
                               QueueLimitReached, CommandRefused)


@pytest.fixture
def fila():
    d = tempfile.mkdtemp()
    return CommandQueue(os.path.join(d, "cmd.db"))


# ------------------------------------------------------------------------------
# Duplicata
# ------------------------------------------------------------------------------
def test_same_command_twice_is_refused(fila):
    """O segundo pedido igual, ainda aguardando, e recusado."""
    fila.enqueue("a1", CMD_CHAOS_COLLECT)
    with pytest.raises(DuplicateCommand):
        fila.enqueue("a1", CMD_CHAOS_COLLECT)
    assert fila.pending_count("a1") == 1


def test_refusal_points_to_the_command_already_in_flight(fila):
    """A recusa carrega o id do pedido existente, para a tela poder apontar."""
    primeiro = fila.enqueue("a1", CMD_COLLECT)
    with pytest.raises(CommandRefused) as erro:
        fila.enqueue("a1", CMD_COLLECT)
    assert erro.value.existing_id == primeiro


def test_delivered_but_unfinished_command_still_blocks(fila):
    """
    Entregue nao e concluido. Enquanto o agente nao devolve o desfecho, um
    segundo pedido igual continua sendo engano: quem libera a vez de um pedido
    perdido e o expire_stuck, nunca outro pedido empilhado por cima.
    """
    fila.enqueue("a1", CMD_CHAOS_COLLECT)
    fila.take_for("a1")
    with pytest.raises(DuplicateCommand):
        fila.enqueue("a1", CMD_CHAOS_COLLECT)


def test_finished_command_frees_the_slot(fila):
    """Concluido o anterior, o mesmo comando pode ser pedido de novo."""
    ident = fila.enqueue("a1", CMD_COLLECT)
    fila.take_for("a1")
    fila.report(ident, True, "captura entregue")
    assert fila.enqueue("a1", CMD_COLLECT)


def test_other_agents_are_not_affected(fila):
    """O bloqueio e por agente: a frota inteira nao para por causa de um host."""
    fila.enqueue("a1", CMD_CHAOS_COLLECT)
    assert fila.enqueue("a2", CMD_CHAOS_COLLECT)


def test_different_commands_coexist(fila):
    """Tipos diferentes convivem: o dedup e por tipo, nao por agente."""
    fila.enqueue("a1", CMD_COLLECT)
    assert fila.enqueue("a1", CMD_CHAOS_COLLECT)
    assert fila.enqueue("a1", CMD_RESTART)
    assert fila.pending_count("a1") == 3


# ------------------------------------------------------------------------------
# Rajada
# ------------------------------------------------------------------------------
def test_burst_of_mixed_commands_hits_the_ceiling():
    """
    O teto por agente barra a rajada mesmo com tipos diferentes, caso que o
    dedup sozinho deixaria passar. E a defesa que faltava no incidente.
    """
    d = tempfile.mkdtemp()
    curta = CommandQueue(os.path.join(d, "c.db"), max_pending=2)
    curta.enqueue("a1", CMD_COLLECT)
    curta.enqueue("a1", CMD_CHAOS_COLLECT)
    with pytest.raises(QueueLimitReached):
        curta.enqueue("a1", CMD_RESTART)
    assert curta.pending_count("a1") == 2


def test_ceiling_counts_only_what_is_waiting():
    """
    O teto conta o que AGUARDA. Um pedido ja entregue saiu da fila de espera e
    nao pode consumir a cota, senao um agente lento ficaria bloqueado.
    """
    d = tempfile.mkdtemp()
    curta = CommandQueue(os.path.join(d, "c.db"), max_pending=1)
    curta.enqueue("a1", CMD_COLLECT)
    curta.take_for("a1")
    assert curta.enqueue("a1", CMD_CHAOS_COLLECT)
