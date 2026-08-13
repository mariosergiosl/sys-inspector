# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_tree_reset.py
# DESCRIPTION: O botao de reset da arvore nao pode recarregar a pagina.
#
#              Observado em campo: clicar em "reset" na arvore de processos
#              jogava o analista de volta para a aba Findings. A causa era um
#              location.reload(), que reprocessa um relatorio de mais de 10MB e
#              volta ao estado inicial do documento, incluindo a aba padrao.
#              Quem pede para resetar a arvore quer continuar nela.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re

import pytest

FONTE = os.path.join("src", "exporters", "web_assets.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


def test_reset_button_does_not_reload_the_page(codigo):
    """
    Nenhum controle da arvore pode recarregar o documento: isso descarta a aba
    ativa, a rolagem e o estado de expansao.
    """
    acoes = re.findall(r'onclick="([^"]+)"', codigo)
    assert not [a for a in acoes if "location.reload" in a]


def test_reset_button_calls_the_in_place_reset(codigo):
    assert 'onclick="resetTree()"' in codigo
    assert "function resetTree()" in codigo


def test_reset_clears_filter_and_collapses(codigo):
    """
    Resetar significa voltar ao estado inicial: sem filtro, so as raizes
    visiveis e nenhum detalhe aberto.
    """
    bloco = codigo.split("function resetTree()")[1].split("function sortView")[0]
    assert "currentFilter" in bloco
    assert "expandedPids.clear()" in bloco
    assert "detailsOpenPids.clear()" in bloco
    assert 'classList.add("hidden")' in bloco


def test_reset_restores_the_original_order(codigo):
    """
    Ordenar por CPU destroi a hierarquia pai-filho no DOM. Sem guardar a ordem
    original, so o recarregamento a traria de volta, que e o que se quer evitar.
    """
    assert "originalOrder" in codigo
    bloco = codigo.split("function sortView")[1][:900]
    assert "state.originalOrder === null" in bloco


def test_reset_clears_active_highlights(codigo):
    """
    Se o destaque do filtro ou da ordenacao sobrevive ao reset, a tela passa a
    indicar um estado que os dados nao refletem mais.
    """
    bloco = codigo.split("function resetTree()")[1].split("function sortView")[0]
    assert 'remove("active")' in bloco
    assert 'remove("sort-active")' in bloco
