# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_risk.py
# DESCRIPTION: A leitura do anomaly_score como campo de bits.
#
# WHY:         O teste que importa aqui nao e o de formatacao, e o de INVERSAO:
#              enquanto o score era lido como magnitude, um processo defunto
#              valia mais que um binario apagado executando de /dev/shm. Os casos
#              abaixo travam essa relacao.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.core import risk
from src.core.findings import (SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH,
                               SEV_CRITICAL)


# ------------------------------------------------------------------------------
# A TABELA NAO PODE DIVERGIR DA ORIGEM
# ------------------------------------------------------------------------------
def test_bits_batem_com_o_coletor():
    """
    Os bits declarados aqui sao os mesmos que o coletor atribui.

    Duas listas do mesmo fato divergindo em silencio ja custou caro neste
    projeto mais de uma vez. Este teste e a trava: mexer no coletor sem mexer na
    leitura quebra aqui, e nao no laudo de alguem.
    """
    pt = pytest.importorskip("src.collectors.process_tree")

    origem = {
        "unsafe_lib": pt.SCORE_UNSAFE_LIB,
        "unsafe_exec": pt.SCORE_MALWARE,
        "net_tool": pt.SCORE_NET_TOOL,
        "deleted_exe": pt.SCORE_DELETED,
        "inspector": pt.SCORE_INSPECTOR,
        "gpu_miner": pt.SCORE_GPU,
        "net_error": pt.SCORE_NET_ISSUE,
        "zombie": pt.SCORE_ZOMBIE,
        "immutable": pt.SCORE_IMMUTABLE,
    }

    aqui = dict((chave, bit) for bit, chave, _r, _s, _e in risk.SINAIS)
    assert aqui == origem


# ------------------------------------------------------------------------------
# DECODIFICACAO
# ------------------------------------------------------------------------------
def test_score_zero_nao_produz_sinal_nem_nivel():
    assert risk.decode(0) == []
    assert risk.level(0) is None
    assert risk.summary(0) == ""


def test_score_invalido_nao_derruba_a_leitura():
    for valor in (None, "", "abc", [], {}):
        assert risk.decode(valor) == []
        assert risk.level(valor) is None


def test_decode_devolve_cada_bit_ligado():
    chaves = [s["key"] for s in risk.decode(2 + 8)]
    assert set(chaves) == {"unsafe_exec", "deleted_exe"}


def test_decode_ordena_do_que_mais_pesa_para_o_que_menos():
    sinais = risk.decode(2 + 128)   # caminho gravavel + defunto
    assert sinais[0]["key"] == "unsafe_exec"
    assert sinais[-1]["key"] == "zombie"


# ------------------------------------------------------------------------------
# A INVERSAO QUE MOTIVOU O MODULO
# ------------------------------------------------------------------------------
def test_defunto_sozinho_e_informativo_e_nao_critico():
    """128 era o maior numero da tabela, e por isso virava o pior caso."""
    assert risk.level(128) == SEV_INFO
    assert risk.needs_attention(128) is False


def test_binario_apagado_em_diretorio_gravavel_pede_atencao():
    """
    2 + 8 = 10 ficava abaixo do limiar 70 e era exibido como brando, embora
    descreva a assinatura que motiva resposta a incidente.
    """
    assert risk.needs_attention(2 + 8) is True
    assert risk.rank(2 + 8) > risk.rank(128)


def test_dois_sinais_de_peso_elevam_um_degrau():
    assert risk.level(2) == SEV_HIGH
    assert risk.level(8) == SEV_HIGH
    assert risk.level(2 + 8) == SEV_CRITICAL


def test_sinal_fraco_nao_eleva_sinal_forte():
    """Falha de rede e defunto sao ruido; nao promovem nada."""
    assert risk.level(2 + 64 + 128) == SEV_HIGH


def test_dois_sinais_fracos_nao_escalam():
    assert risk.level(4 + 64) == SEV_LOW


def test_edr_sozinho_nao_e_suspeita():
    assert risk.level(16) == SEV_INFO
    assert risk.needs_attention(16) is False


def test_dois_medios_viram_alto():
    assert risk.level(32) == SEV_MEDIUM
    assert risk.level(256) == SEV_MEDIUM
    assert risk.level(32 + 256) == SEV_HIGH


# ------------------------------------------------------------------------------
# APRESENTACAO
# ------------------------------------------------------------------------------
def test_summary_nomeia_todos_os_sinais():
    texto = risk.summary(2 + 8)
    assert "gravavel" in texto
    assert "apagado" in texto
    assert "+" in texto


def test_cor_de_score_sem_sinal_e_neutra():
    assert risk.color(0) == "#555"
    assert risk.color(2) == risk.CORES[SEV_HIGH]


def test_toda_severidade_tem_cor():
    for _bit, _chave, _rotulo, severidade, _exp in risk.SINAIS:
        assert severidade in risk.CORES


def test_toda_explicacao_esta_preenchida():
    """Rotulo sem explicacao obriga o leitor a deduzir, que e o que D-020 veda."""
    for _bit, chave, rotulo, _sev, explicacao in risk.SINAIS:
        assert rotulo and explicacao, chave
        assert len(explicacao) > 40, chave


# ------------------------------------------------------------------------------
# SINAL NOVO NAO PODE SUMIR
# ------------------------------------------------------------------------------
def test_bit_desconhecido_e_denunciado():
    """
    Um bit novo no coletor tem que aparecer como desconhecido, e nao ser
    descartado em silencio: sinal perdido sem rastro leva o analista a concluir
    que nao havia nada.
    """
    assert risk.unknown_bits(1024) == 1024
    assert risk.unknown_bits(2 + 8) == 0
