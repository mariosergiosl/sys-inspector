# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_net_badge_arithmetic.py
# DESCRIPTION: A conta do badge de rede tem que FECHAR na tela (F-243).
#
# WHY:         O Mario observou um processo pai com 7 e um filho com 6, sem
#              descarte proprio visivel no pai, e reportou que a conta nao
#              fechava. Investigado em 2026-09-18: nao era erro de contagem.
#
#              O badge sempre somou a SUBARVORE, o processo mais todos os
#              descendentes. O painel de detalhe sempre mostrou o contador
#              PROPRIO do processo. Os dois numeros estavam certos, cada um no
#              seu escopo, e liam-se como contradicao porque o escopo nao estava
#              escrito em lugar nenhum.
#
#              E a copia silenciosa vista pelo avesso: nao sao duas fontes
#              divergindo, sao duas leituras corretas do mesmo fato sem rotulo
#              que as distinga. Custa o mesmo: o leitor conclui defeito onde
#              havia informacao.
#
# O QUE PROVA: que a conta permanece a mesma (nao era ela o defeito) e que o
#              escopo de cada numero esta escrito, no badge e no detalhe.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fonte(caminho):
    """Le um arquivo do projeto como texto, tolerando byte estranho."""
    with io.open(os.path.join(RAIZ, caminho), encoding="utf-8",
                 errors="replace") as fh:
        return fh.read()


def _relatorio():
    """
    O modulo do laudo, ou pula o caso.

    Ele importa process_tree, que exige `pwd`, entao no Windows estes casos
    pulam e valem na CI, que roda Linux.
    """
    return pytest.importorskip(
        "src.exporters.html_report",
        reason="o laudo importa process_tree, que exige pwd (Linux)")


class _No(object):
    """
    Processo minimo para desenhar badge.

    Reproduz o caso relatado: o PAI nao tem descarte proprio (`tcp_drops` zero)
    e a subarvore dele acumula os dos filhos.
    """

    def __init__(self, proprios_d=0, proprios_r=0, arvore_d=0, arvore_r=0):
        self.pid = 100
        self.ppid = 1
        self.cmd = "processo"
        self.uid = 0
        self.state = "S"
        self.is_new = False
        self.tags_accumulated = set()
        self.context_tags = set()
        self.detection_reasons = []
        self.anomaly_score = 0
        self.tree_max_score = 0
        self.tcp_drops = proprios_d
        self.tcp_retrans = proprios_r
        self.tree_tcp_drops = arvore_d
        self.tree_tcp_retrans = arvore_r


# ==============================================================================
# A CONTA NAO MUDA: NAO ERA ELA O DEFEITO
# ==============================================================================

def test_o_badge_continua_somando_a_subarvore():
    """
    GUARDA DE REGRESSAO, e nao prova do defeito. A investigacao concluiu que a
    conta estava certa, entao ela nao pode mudar por causa desta correcao: o
    badge do pai cobre o processo e todos os descendentes.
    """
    rel = _relatorio()
    html = rel._render_badges(_No(proprios_d=0, arvore_d=7))
    assert "❌ 7" in html, "o badge deixou de somar a subarvore (F-243)"


def test_o_badge_soma_descartes_e_retransmissoes():
    """
    O numero sempre foi a soma das duas falhas de rede. Mudar isso quebraria a
    leitura de qualquer laudo ja emitido.
    """
    rel = _relatorio()
    html = rel._render_badges(_No(arvore_d=4, arvore_r=3))
    assert "❌ 7" in html


def test_sem_falha_de_rede_nao_ha_badge():
    """Zero nao vira badge: a arvore ficaria coberta de ruido."""
    rel = _relatorio()
    html = rel._render_badges(_No())
    assert "NET ERR" not in html


# ==============================================================================
# O ESCOPO PASSA A ESTAR ESCRITO
# ==============================================================================

def test_o_tooltip_declara_que_o_numero_cobre_os_descendentes():
    """
    REPROVA A VERSAO COM DEFEITO: o tooltip dizia apenas
    "Network Issues: N Drops, M Retransmits", sem uma palavra sobre escopo. Era
    dali que saia a leitura de que a conta nao fechava.
    """
    rel = _relatorio()
    html = rel._render_badges(_No(proprios_d=0, arvore_d=7))
    assert "descendentes" in html, (
        "o badge voltou a omitir que o numero cobre a subarvore (F-243)")


def test_o_tooltip_separa_o_proprio_do_que_vem_dos_filhos():
    """
    O caso exato relatado: pai sem descarte proprio, sete vindos dos filhos. O
    tooltip tem que dizer as duas metades, senao o leitor volta a deduzir.
    """
    rel = _relatorio()
    html = rel._render_badges(_No(proprios_d=0, proprios_r=0, arvore_d=7))
    assert "Deste processo: 0 drops" in html
    assert "Dos descendentes: 7 drops" in html


def test_a_parte_dos_descendentes_nunca_e_negativa():
    """
    CENARIO ADVERSO: thread de kernel tem contador proprio e subarvore zerada de
    proposito, porque ela nao possui socket. A subtracao crua daria um numero
    impossivel no lugar mais sensivel da tela.
    """
    rel = _relatorio()
    html = rel._render_badges(_No(proprios_d=9, proprios_r=9,
                                  arvore_d=2, arvore_r=1))
    assert "-" not in html.split("Dos descendentes:")[1][:40], (
        "a conta dos descendentes ficou negativa (F-243)")
    assert "Dos descendentes: 0 drops, 0 retransmits" in html


def test_o_tooltip_e_escapado():
    """
    O tooltip passou a ser montado com varias linhas e entra num atributo
    title="...". Sem escapar, qualquer aspa fecharia o atributo, que e o mesmo
    defeito ja corrigido no tooltip do processo pai.
    """
    src = _fonte("src/exporters/html_report.py")
    inicio = src.index("[F-243] A conta do badge de rede")
    bloco = src[inicio:inicio + 2200]
    assert 'title="{_esc(tooltip)}"' in bloco, (
        "o tooltip do badge de rede voltou a entrar sem escapar (F-243)")


# ==============================================================================
# O PAINEL DE DETALHE MOSTRA AS DUAS LEITURAS
# ==============================================================================

def test_o_detalhe_mostra_o_proprio_e_a_subarvore():
    """
    REPROVA A VERSAO COM DEFEITO: o painel mostrava so o contador proprio. Um
    pai com badge 7 e detalhe 0 parecia defeito de contagem, e era so o pai nao
    ter descarte proprio.
    """
    src = _fonte("src/exporters/html_report.py")
    inicio = src.index("Network Resilience")
    bloco = src[inicio:inicio + 2500]
    assert "Deste processo" in bloco, (
        "o painel nao rotula mais o contador proprio (F-243)")
    assert "Com os descendentes" in bloco, (
        "o painel voltou a esconder a leitura da subarvore (F-243)")
    assert "tree_tcp_drops" in bloco and "tree_tcp_retrans" in bloco


def test_o_detalhe_mostra_o_total_que_o_badge_exibe():
    """
    O que fecha a conta para quem le: o painel diz, com todas as letras, qual e
    o numero que aparece no badge.
    """
    src = _fonte("src/exporters/html_report.py")
    inicio = src.index("Network Resilience")
    bloco = src[inicio:inicio + 2500]
    assert "badge: {tree_r + tree_d}" in bloco, (
        "o painel parou de declarar o total exibido no badge (F-243)")


def test_o_detalhe_nao_esconde_o_zero():
    """
    D-020 aplicada aqui: o campo aparece mesmo valendo zero, porque zero e
    justamente a resposta que explicava a duvida do pai sem descarte proprio.
    """
    src = _fonte("src/exporters/html_report.py")
    inicio = src.index("Network Resilience")
    bloco = src[inicio:inicio + 2500]
    assert "if node.tcp_drops" not in bloco.split("Deste processo")[1][:300], (
        "o painel passou a esconder o contador quando ele vale zero (F-243)")


# ==============================================================================
# A LEGENDA DO POPUP DIZIA MENOS DO QUE PRECISAVA
# ==============================================================================

def test_a_legenda_declara_o_escopo_do_badge():
    """
    A legenda dizia "falhas de rede do processo", omitindo exatamente a parte
    que causava a duvida. Um popup de ajuda que omite o ponto dificil e pior
    que nenhum, porque quem o leu acha que ja entendeu.
    """
    src = _fonte("src/exporters/web_assets.py")
    inicio = src.index('("NET ERR"')
    bloco = src[inicio:inicio + 1400]
    assert "DESCENDENTES" in bloco, (
        "a legenda do badge NET ERR voltou a omitir o escopo (F-243)")
    assert "MAIOR que a soma dos filhos visiveis" in bloco
