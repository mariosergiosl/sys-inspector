# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_next_checkin.py
# DESCRIPTION: Previsao do proximo contato do agente.
#
#              A tela mostrava apenas quando o agente falou pela ultima vez, o
#              que nao responde a pergunta que importa: ele esta vivo? Quarenta
#              segundos de silencio podem ser o intervalo normal de um agente ou
#              o sinal de que ele parou. O timeout fixo de 90s errava dos dois
#              lados: marcava como offline um agente saudavel de ciclo longo e
#              demorava a perceber a ausencia de um de ciclo curto.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

FONTE = os.path.join("src", "controllers", "server_controller.py")
OUTBOX = os.path.join("src", "core", "outbox.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


def test_agent_reports_its_own_cycle():
    """
    O agente informa seu ciclo; o servidor nao tem como adivinhar o intervalo
    configurado em cada host.
    """
    fonte = io.open(OUTBOX, encoding="utf-8").read()
    assert "cycle_seconds" in fonte
    assert "capture_duration" in fonte and "interval" in fonte


def test_status_uses_the_reported_cycle(codigo):
    """A decisao de online passa a usar o ciclo real, nao um numero fixo."""
    assert "cycle_seconds" in codigo
    assert "idade < (ciclo * 2)" in codigo


def test_one_missed_cycle_is_tolerated(codigo):
    """
    Perder um ciclo acontece (rede, carga); dois seguidos ja e ausencia. O
    limite de dois ciclos evita alarme a cada atraso normal.
    """
    assert "ciclo * 2" in codigo


def test_late_agent_is_visually_distinct(codigo):
    """Atraso e ausencia recebem cores diferentes de um agente em dia."""
    assert "atrasado" in codigo
    assert "#ffd166" in codigo and "#ff4d4d" in codigo


def test_column_shows_the_cycle_used(codigo):
    """
    Mostrar o ciclo junto da previsao explica de onde ela vem, em vez de pedir
    que o analista confie num numero sem origem.
    """
    assert "ciclo %ss" in codigo


def test_agent_without_cycle_does_not_break_the_view(codigo):
    """Agente antigo, que nao informa ciclo, nao quebra a tela."""
    assert 'proximo_html = "<span style=\'color:#555\'>-</span>"' in codigo


def test_next_column_exists(codigo):
    """A coluna esta declarada no cabecalho da tabela."""
    assert "<th>Next</th>" in codigo
