# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_manager_columns.py
# DESCRIPTION: Colunas novas da tela Manager (pedido do Mario 2026-08-12).
#
# WHY:         FQDN em coluna propria, uptime do host e do agente, status como
#              icone, e a cadencia do agendador visiveis na triagem da frota.
#              Cada um responde uma pergunta que antes exigia abrir outra tela ou
#              deduzir.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

from src.controllers.server_controller import _dur_humana

FONTE = os.path.join("src", "controllers", "server_controller.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


# ------------------------------------------------------------------------------
# DURACAO LEGIVEL
# ------------------------------------------------------------------------------
def test_duracao_usa_a_maior_unidade_que_faz_sentido():
    assert _dur_humana(30) == "30s"
    assert _dur_humana(90) == "1m"
    assert _dur_humana(3700) == "1h 1m"
    assert _dur_humana(90000) == "1d 1h"


def test_duracao_invalida_ou_negativa_nao_quebra():
    assert _dur_humana(None) == "?"
    assert _dur_humana("x") == "?"
    assert _dur_humana(-5) == "?"


# ------------------------------------------------------------------------------
# AS COLUNAS EXISTEM NA TELA
# ------------------------------------------------------------------------------
def test_o_dashboard_tem_coluna_fqdn(codigo):
    bloco = codigo.split("def _serve_dashboard")[1]
    assert ">FQDN<" in bloco
    assert "fqdn_col" in bloco


def test_o_dashboard_mostra_uptime_do_host_e_do_agente(codigo):
    bloco = codigo.split("def _serve_dashboard")[1]
    assert "uptime_col" in bloco
    assert "host_uptime" in bloco
    assert "agent_uptime" in bloco


def test_o_status_e_um_icone(codigo):
    bloco = codigo.split("def _serve_dashboard")[1]
    # ponto colorido, nao a palavra ONLINE num badge de texto
    assert "status_cell" in bloco
    assert "&#9679;" in bloco


def test_a_cadencia_do_agendador_aparece(codigo):
    bloco = codigo.split("def _serve_dashboard")[1]
    assert "CADENCIA" in bloco or "cadencia" in bloco


# ------------------------------------------------------------------------------
# O CAMINHO DE DADOS (agente -> servidor -> frota)
# ------------------------------------------------------------------------------
def test_o_agente_reporta_uptime_e_offset():
    import inspect
    from src.core.outbox import Outbox
    fonte = inspect.getsource(Outbox._host_identity)
    assert "host_uptime" in fonte
    assert "agent_uptime" in fonte
    assert "/proc/uptime" in fonte


def test_o_servidor_guarda_os_campos_novos(codigo):
    assert "host_uptime=host.get(\"host_uptime\")" in codigo
    assert "agent_uptime=host.get(\"agent_uptime\")" in codigo


def test_update_aceita_zero_como_valor_legitimo():
    """
    Host recem-ligado tem uptime pequeno mas real, e offset medido pode ser 0.
    O update usa 'is not None', nao truthy, para nao descartar o zero legitimo.
    """
    import inspect
    from src.core.database import DatabaseManager
    fonte = inspect.getsource(DatabaseManager.update_agent_status)
    assert "host_uptime is not None" in fonte
    assert "clock_offset is not None" in fonte
