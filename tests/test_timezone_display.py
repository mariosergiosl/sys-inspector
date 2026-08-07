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


def test_last_seen_column_shows_short_local_time(codigo):
    """
    A coluna traz a hora local curta, que e a que o analista compara com o
    relogio dele, sem obriga-lo a converter fuso de cabeca.
    """
    assert "datetime.datetime.now() - datetime.datetime.utcnow()" in codigo
    assert 'local.strftime("%H:%M:%S")' in codigo


def test_full_utc_stamp_is_kept_in_small_print(codigo):
    """
    O carimbo completo em UTC nao pode sumir: num laudo o horario precisa ser
    absoluto e sem ambiguidade. Ele fica em letra miuda junto do host.
    """
    assert "seen_full" in codigo
    assert "UTC (%s)" in codigo
    assert "seen_html" in codigo


def test_fqdn_is_shown_when_it_adds_information(codigo):
    """
    O FQDN identifica o host no dominio; exibi-lo quando e igual ao nome curto
    so repetiria a mesma informacao.
    """
    assert "fqdn_html" in codigo
    assert "fqdn != host" in codigo


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
