# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_server_dashboard.py
# DESCRIPTION: Garante que a tela do gerente sinalize risco e permita voltar.
#
#              Observado no teste distribuido real: com achados criticos
#              acontecendo nos dois agentes, o gerente listava apenas hostname,
#              endereco e status. O analista so descobriria o comprometimento
#              entrando host a host, que e exatamente o que a tela de frota
#              deveria evitar. E, uma vez dentro do relatorio, nao havia
#              caminho de volta.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

FONTE = os.path.join("src", "controllers", "server_controller.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


def test_dashboard_uses_the_fleet_risk_state(codigo):
    """
    A tela usa o estado de risco da frota, nao a lista simples de agentes: os
    dois trazem hostname e status, mas so o primeiro traz os achados.
    """
    assert "db.get_fleet_status()" in codigo
    assert "agents = db.get_agents()" not in codigo


def test_fleet_is_ordered_by_risk(codigo):
    """O host mais comprometido aparece primeiro, respondendo por onde comecar."""
    assert "reverse=True" in codigo
    assert "_risk" in codigo


def test_every_severity_has_a_column(codigo):
    """As quatro severidades acionaveis aparecem na tabela."""
    for level in ("Critical", "High", "Medium", "Low"):
        assert level in codigo, level
    for header in (">Crit<", ">High<", ">Med<", ">Low<"):
        assert header in codigo, header


def test_row_is_marked_by_the_worst_severity(codigo):
    """A linha destaca a pior severidade, para o olho encontrar sem ler numeros."""
    assert "risk_border" in codigo


def test_report_offers_a_way_back_to_the_fleet(codigo):
    """
    O relatorio de um agente precisa ter retorno para a frota; sem isso o
    analista fica preso na pagina.
    """
    assert "Fleet</a>" in codigo
    assert "href='/'" in codigo


def test_back_link_is_injected_once_on_a_safe_anchor(codigo):
    """
    O link entra uma unica vez e numa ancora que existe apenas na marcacao.
    Ancorar em "<body>" pegava a ocorrencia dentro do JavaScript do relatorio
    e quebrava o script inteiro (ver test_html_injection_anchor.py).
    """
    assert "back + anchor, 1)" in codigo
    assert "sticky-wrapper" in codigo
    assert "replace('<body>'" not in codigo
