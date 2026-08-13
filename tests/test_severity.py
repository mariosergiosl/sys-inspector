# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_severity.py
# DESCRIPTION: Testa o mapeamento anomaly_score -> rotulo de severidade usado no
#              badge de alerta do relatorio.
#
# NOTE:        Este arquivo travava as faixas ANTIGAS (>=128 Critical, >=32 High,
#              >=8 Medium), que liam como magnitude um valor que e campo de bits.
#              As faixas passavam nos testes e mentiam na tela: um processo
#              defunto (128) saia como Critical e um binario apagado executando
#              de /dev/shm (8+2=10) saia como Medium. O criterio agora e o SINAL
#              presente, definido em src/core/risk.py.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.exporters.html_report import _severity_label


def test_score_sem_sinal_nao_produz_rotulo():
    assert _severity_label(0) is None


def test_cada_sinal_isolado_vale_o_que_declara():
    assert _severity_label(2) == "High"      # executa de diretorio gravavel
    assert _severity_label(8) == "High"      # binario apagado em execucao
    assert _severity_label(1) == "Medium"    # biblioteca nao confiavel
    assert _severity_label(32) == "Medium"   # assinatura de mineracao
    assert _severity_label(256) == "Medium"  # atributo imutavel
    assert _severity_label(4) == "Low"       # ferramenta de rede
    assert _severity_label(64) == "Low"      # falha de rede
    assert _severity_label(16) == "Info"     # o proprio EDR/AV
    assert _severity_label(128) == "Info"    # processo defunto


def test_a_inversao_que_a_faixa_numerica_produzia():
    """
    O caso concreto: o defunto valia mais que o binario apagado. Agora nao.
    """
    assert _severity_label(128) == "Info"
    assert _severity_label(8 + 2) == "Critical"


def test_dois_sinais_de_peso_juntos_sobem_um_degrau():
    assert _severity_label(32 + 256) == "High"


def test_severity_invalid_and_negative():
    """Entradas invalidas ou nao positivas retornam None (sem badge)."""
    assert _severity_label(None) is None
    assert _severity_label("x") is None
    assert _severity_label(-5) is None
