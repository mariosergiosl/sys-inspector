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


def test_every_severity_is_shown(codigo):
    """
    As quatro severidades acionaveis continuam VISIVEIS, inclusive em zero
    (D-020). O que mudou em 2026-08-20 (F-224) foi a forma: em vez de quatro
    colunas largas para quatro numeros de um digito, uma celula so com os
    quatro lado a lado. A premissa antiga do teste ("cada severidade tem uma
    COLUNA") era sobre o desenho, e o desenho e que mudou; a exigencia real,
    que e nenhuma severidade sumir, esta preservada abaixo.
    """
    for level in ("Critical", "High", "Medium", "Low"):
        assert level in codigo, level
    assert "class='sev-bloco'" in codigo, (
        "o bloco unico de severidades sumiu do fonte")
    assert "sev-cel" in codigo, "as celulas de severidade sumiram"
    # O zero continua desenhado, apenas apagado: um contador que some deixa o
    # operador sem saber se e zero ou se a tela parou de reportar.
    assert 'background:#2a2a2a; color:#555' in codigo


def test_row_is_marked_by_the_worst_severity(codigo):
    """A linha destaca a pior severidade, para o olho encontrar sem ler numeros."""
    assert "risk_border" in codigo


def test_report_offers_a_way_back_to_the_fleet(codigo):
    """
    O relatorio de um agente precisa ter retorno para a frota; sem isso o
    analista fica preso na pagina.
    """
    inicio = codigo.index("back = (")
    bloco = codigo[inicio:inicio + 1200]
    # [F-232, 2026-08-20] O botao passou a se chamar "Manager", e nao "Fleet":
    # ele volta para a tela Manager, e e o nome do DESTINO que o operador
    # procura. O teste continua exigindo o retorno, que e o requisito; so o
    # rotulo mudou.
    assert "Manager</a>" in bloco
    # Aponta para a raiz, independente de como as aspas aparecem no fonte.
    assert "href=" in bloco and "/" in bloco


def test_back_bar_does_not_float_over_the_title(codigo):
    """
    A barra de retorno ocupa espaco no fluxo do documento. Com position:fixed
    ela flutuava sobre o cabecalho e cobria o nome da ferramenta.
    """
    inicio = codigo.index("back = (")
    trecho = codigo[inicio:inicio + 700]
    assert "position:fixed" not in trecho


def test_back_link_is_injected_once_on_a_safe_anchor(codigo):
    """
    O link entra uma unica vez e numa ancora que existe apenas na marcacao.
    Ancorar em "<body>" pegava a ocorrencia dentro do JavaScript do relatorio
    e quebrava o script inteiro (ver test_html_injection_anchor.py).
    """
    assert "back + anchor, 1)" in codigo
    assert "sticky-wrapper" in codigo
    assert "replace('<body>'" not in codigo
