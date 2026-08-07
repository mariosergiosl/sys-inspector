# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_timezone_display.py
# DESCRIPTION: Coerencia de fuso horario na tela do gerente.
#
#              Observado em campo: o gerente exibia "last seen" tres horas a
#              frente do relatorio do mesmo agente. O valor vem do
#              CURRENT_TIMESTAMP do SQLite, que e UTC, enquanto o laudo usa a
#              hora local do host. Numa ferramenta forense, misturar fusos sem
#              marcacao pode inverter a ordem dos eventos de uma linha do tempo.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

from src.controllers.server_controller import _human_age

FONTE = os.path.join("src", "controllers", "server_controller.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


def test_comparison_uses_utc(codigo):
    """
    O horario guardado e UTC, entao a comparacao tem que ser em UTC. Usar a
    hora local deslocava o calculo pelo offset do fuso, e um agente saudavel
    podia aparecer como offline (ou o contrario).
    """
    assert "utcnow()" in codigo
    assert "datetime.datetime.now() - last_ts" not in codigo


def test_timezone_is_shown_explicitly(codigo):
    """O horario exibido diz em que fuso esta, sem deixar ambiguidade."""
    assert '"%s UTC"' in codigo


def test_relative_age_is_shown(codigo):
    """
    Alem do horario absoluto, a idade relativa responde de imediato "esse
    agente acabou de reportar ou sumiu?".
    """
    assert "_human_age" in codigo


def test_human_age_reads_naturally():
    """A idade e apresentada na maior unidade que faz sentido."""
    assert _human_age(12) == "12s ago"
    assert _human_age(75) == "1m ago"
    assert _human_age(3700) == "1h ago"
    assert _human_age(90000) == "1d ago"


def test_human_age_handles_zero():
    """Reporte recem-chegado nao quebra a formatacao."""
    assert _human_age(0) == "0s ago"
