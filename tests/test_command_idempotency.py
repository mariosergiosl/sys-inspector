# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_command_idempotency.py
# DESCRIPTION: Entrega confiavel de comandos, sem perder e sem repetir.
#
#              Entrega tem duas formas possiveis e as duas sozinhas sao ruins.
#              "No maximo uma vez" perde o pedido quando o agente morre logo
#              depois de receber. "Pelo menos uma vez" nunca perde, mas uma
#              confirmacao extraviada faz o mesmo comando rodar duas vezes, o
#              que para uma acao que ALTERA o host inspecionado e inaceitavel.
#
#              A solucao nao escolhe entre as duas: o servidor reentrega ate
#              saber o desfecho, e o agente registra o que ja executou, de modo
#              que uma reentrega seja reconfirmada e nunca repetida.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import time

import pytest

from src.core.commands import (CommandQueue, RETRY_AFTER, CMD_CHAOS_COLLECT,
                               CMD_COLLECT, ST_SENT)
from src.core.executed import ExecutionLedger


@pytest.fixture
def fila(tmp_path):
    return CommandQueue(str(tmp_path / "cmd.db"))


@pytest.fixture
def registro(tmp_path):
    return ExecutionLedger(str(tmp_path / "agent.db"))


def _envelhecer_entrega(fila, cid, segundos):
    with fila._conn() as conn:
        conn.execute("UPDATE agent_commands SET delivered_at = ? WHERE id = ?",
                     (time.time() - segundos, cid))


# ------------------------------------------------------------------------------
# O SERVIDOR NAO DESISTE
# ------------------------------------------------------------------------------
def test_command_without_outcome_is_delivered_again(fila):
    """
    Era o buraco: o agente recebia, morria e o pedido sumia sem que ninguem
    soubesse se tinha rodado.
    """
    cid = fila.enqueue("agente-a", CMD_COLLECT)
    assert len(fila.take_for("agente-a")) == 1

    _envelhecer_entrega(fila, cid, RETRY_AFTER + 60)
    assert [c["id"] for c in fila.take_for("agente-a")] == [cid]


def test_a_command_in_progress_is_not_delivered_again(fila):
    """
    O cenario de teste roda por 300s. Reentregar durante a execucao criaria
    exatamente a duplicidade que se quer evitar.
    """
    cid = fila.enqueue("agente-a", CMD_CHAOS_COLLECT)
    fila.take_for("agente-a")

    _envelhecer_entrega(fila, cid, 60)
    assert fila.take_for("agente-a") == []


def test_retry_window_covers_the_longest_action():
    """
    Se a janela fosse menor que a acao mais demorada, o servidor reentregaria
    todo cenario de teste antes de ele terminar.
    """
    assert RETRY_AFTER > 300


def test_a_reported_command_is_never_delivered_again(fila):
    """Saber o desfecho encerra o assunto."""
    cid = fila.enqueue("agente-a", CMD_COLLECT)
    fila.take_for("agente-a")
    fila.report(cid, True, "ok")

    _envelhecer_entrega(fila, cid, RETRY_AFTER + 60)
    assert fila.take_for("agente-a") == []


# ------------------------------------------------------------------------------
# O AGENTE NAO REPETE
# ------------------------------------------------------------------------------
def test_unknown_command_is_allowed_to_run(registro):
    assert registro.already_done(1) is None


def test_an_executed_command_is_recognized(registro):
    registro.remember(1, CMD_CHAOS_COLLECT, "cenario plantado")
    assert registro.already_done(1) == "cenario plantado"


def test_the_original_outcome_is_replayed(registro):
    """
    Reconfirmar com o resultado real da primeira execucao e mais honesto do que
    responder algo generico sobre uma execucao que nao se repetiu.
    """
    registro.remember(7, CMD_COLLECT, "captura de 20s concluida")
    assert registro.already_done(7) == "captura de 20s concluida"


def test_the_ledger_survives_an_agent_restart(tmp_path):
    """
    A memoria precisa estar em disco: guardada so em RAM, ela morreria junto com
    o agente, e e justamente a morte do agente que motiva a reentrega.
    """
    caminho = str(tmp_path / "agent.db")
    ExecutionLedger(caminho).remember(3, CMD_COLLECT, "feito")

    assert ExecutionLedger(caminho).already_done(3) == "feito"


def test_old_entries_do_not_accumulate_forever(tmp_path):
    """Passada a janela de reentrega, guardar o registro so faz a tabela crescer."""
    registro = ExecutionLedger(str(tmp_path / "a.db"), retencao=0)
    registro.remember(1, CMD_COLLECT, "antigo")
    registro.remember(2, CMD_COLLECT, "novo")

    assert registro.already_done(1) is None


def test_an_unreadable_ledger_lets_the_command_run(tmp_path, monkeypatch):
    """
    Se o proprio registro estiver inacessivel, executar e a escolha menos ruim:
    perder um pedido e pior do que a possibilidade remota de repeti-lo.
    """
    registro = ExecutionLedger(str(tmp_path / "a.db"))

    def _explode():
        raise IOError("banco indisponivel")
    monkeypatch.setattr(registro, "_conn", _explode)

    assert registro.already_done(1) is None


# ------------------------------------------------------------------------------
# A LIGACAO ENTRE OS DOIS
# ------------------------------------------------------------------------------
def test_agent_checks_the_ledger_before_executing():
    import io
    import os
    fonte = io.open(os.path.join("src", "controllers", "daemon_controller.py"),
                    encoding="utf-8").read()
    bloco = fonte.split("def _handle_commands")[1].split("def _concluir")[0]
    assert "already_done" in bloco
    assert "continue" in bloco


def test_agent_records_before_reporting():
    """
    Anotar depois de reportar deixaria aberta exatamente a janela que este
    mecanismo existe para fechar: confirmacao perdida, reentrega, execucao dupla.
    """
    import io
    import os
    fonte = io.open(os.path.join("src", "controllers", "daemon_controller.py"),
                    encoding="utf-8").read()
    bloco = fonte.split("def _concluir")[1].split("def _run_chaos")[0]
    assert bloco.index("remember") < bloco.index("report_command")
