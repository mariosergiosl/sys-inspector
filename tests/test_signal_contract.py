# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_signal_contract.py
# DESCRIPTION: Nenhum sinal detectado pode desaparecer no caminho ate a tela.
#
# WHY:         O cenario de teste (chaos_maker) e o termometro da ferramenta: e
#              com ele que se afere se a deteccao funciona. Se um sinal se perde
#              entre o coletor e o laudo, o termometro passa a mentir, e toda
#              medicao feita com ele perde valor.
#
#              Foi o que aconteceu com o rotulo DELETED. O coletor detectava o
#              binario apagado do disco, o dado atravessava a cifragem, a rede e
#              o banco intacto, e a renderizacao o descartava porque nao havia
#              entrada correspondente no mapa de badges. O laco fazia
#              "if tag in tag_map", de modo que a perda era TOTALMENTE
#              silenciosa: nenhum erro, nenhum aviso, apenas ausencia. Para
#              quem lia o laudo, "sem badge" e indistinguivel de "nada
#              detectado", que e a pior falha possivel numa ferramenta forense.
#
#              Os testes abaixo comparam as duas pontas direto do codigo-fonte,
#              e nao de uma lista mantida a mao, porque uma lista manual
#              envelhece em silencio pelo mesmo motivo que o defeito original.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re

import pytest

FONTE_COLETOR = os.path.join("src", "collectors", "process_tree.py")
# [F-201] O mapa de badges saiu de dentro de html_report.py (onde vivia
# aninhado em _render_badges) para src/core/badges.py: registro unico
# compartilhado tambem pela barra de filtro do topo (web_assets.py), para as
# duas paradas de renderizacao nunca mais divergirem entre si.
FONTE_BADGES = os.path.join("src", "core", "badges.py")

# Rotulos com tratamento proprio em outro trecho do laudo: a contagem de falhas
# de rede e o selo de severidade tem renderizacao dedicada, e ZOMBIE_PARENT e
# marcador interno de agregacao, que nunca chega a tela.
TRATADOS_A_PARTE = {"NET ERR", "WARN", "ZOMBIE_PARENT"}

# Emoji anexado junto de EDR-WAIT. Nao carrega informacao propria: e o mesmo
# icone que EDR-WAIT ja desenha.
REDUNDANTES = {"\U0001f9ca"}


def _ler(caminho):
    return io.open(caminho, encoding="utf-8").read()


@pytest.fixture(scope="module")
def tags_produzidas():
    """Todo rotulo que o coletor e capaz de atribuir a um processo."""
    fonte = _ler(FONTE_COLETOR)
    achados = re.findall(
        r'(?:context_tags\.append|context_tags\.add|tags_accumulated\.add)'
        r'\(\s*"([^"]+)"', fonte)
    return set(achados)


@pytest.fixture(scope="module")
def tags_renderizaveis():
    """Todo rotulo que o laudo sabe desenhar (badge E filtro, mesma fonte)."""
    fonte = _ler(FONTE_BADGES)
    bloco = fonte.split("TAG_MAP = {")[1].split("\n}")[0]
    return set(re.findall(r'^\s{4}"([^"]+)"\s*:', bloco, re.MULTILINE))


# ------------------------------------------------------------------------------
# O CONTRATO
# ------------------------------------------------------------------------------
def test_every_detected_signal_can_be_drawn(tags_produzidas, tags_renderizaveis):
    """
    O teste central deste arquivo.

    Um rotulo que o coletor produz e a tela nao desenha e informacao perdida
    entre a deteccao e o analista. Foi assim que DELETED, que sinaliza binario
    apagado do disco com o processo ainda em execucao, nunca chegou a ser visto.
    """
    perdidos = tags_produzidas - tags_renderizaveis - TRATADOS_A_PARTE - REDUNDANTES
    assert not perdidos, (
        "O coletor produz rotulos que o laudo nao desenha: %s. "
        "Ou acrescente a entrada em tag_map, ou declare o tratamento "
        "alternativo de forma explicita." % sorted(perdidos))


def test_deleted_binary_is_drawable(tags_renderizaveis):
    """
    Guarda especifica para o defeito encontrado.

    Apagar o executavel depois de rodar e tecnica corrente para nao deixar
    amostra para analise. Se este sinal nao chega a tela, a ferramenta deixa de
    responder justamente a pergunta que motiva a pericia.
    """
    assert "DELETED" in tags_renderizaveis


def test_the_collector_still_detects_a_deleted_binary(tags_produzidas):
    """A outra metade do contrato: a deteccao nao pode ser removida sem alarde."""
    assert "DELETED" in tags_produzidas


# ------------------------------------------------------------------------------
# A PERDA NUNCA MAIS PODE SER SILENCIOSA
# ------------------------------------------------------------------------------
def test_an_unknown_label_is_shown_instead_of_dropped():
    """
    Mesmo com o contrato acima, um rotulo novo pode surgir por outro caminho.
    Exibi-lo com aviso e melhor do que faze-lo sumir: numa ferramenta forense,
    "sem badge" e indistinguivel de "nada detectado", e o analista conclui que
    nao havia nada.
    """
    from src.collectors.process_tree import ProcessNode
    from src.exporters.html_report import _render_badges

    node = ProcessNode(42, 1, "/tmp/x", 0)
    node.context_tags = ["ROTULO_QUE_NAO_EXISTE"]

    html = _render_badges(node)
    assert "ROTULO_QUE_NAO_EXISTE" in html


def test_labels_handled_elsewhere_do_not_produce_a_duplicate():
    """
    A contagem de falhas de rede tem badge proprio. Desenha-la tambem como
    rotulo desconhecido criaria dois selos para o mesmo fato.
    """
    from src.collectors.process_tree import ProcessNode
    from src.exporters.html_report import _render_badges

    node = ProcessNode(42, 1, "/bin/x", 0)
    node.context_tags = ["NET ERR"]

    assert "NET ERR" not in _render_badges(node)


def test_a_known_label_is_drawn_with_its_icon():
    from src.collectors.process_tree import ProcessNode
    from src.exporters.html_report import _render_badges

    node = ProcessNode(42, 1, "/tmp/miner", 0)
    node.context_tags = ["MINER"]

    html = _render_badges(node)
    assert 't-miner' in html
    assert 'data-filter="MINER"' in html


def test_the_deleted_label_reaches_the_report():
    """Verificacao ponta a ponta do defeito corrigido."""
    from src.collectors.process_tree import ProcessNode
    from src.exporters.html_report import _render_badges

    node = ProcessNode(42, 1, "/tmp/apagado", 0)
    node.context_tags = ["DELETED"]

    html = _render_badges(node)
    assert 'data-filter="DELETED"' in html


# ------------------------------------------------------------------------------
# O SENTIDO INVERSO
# ------------------------------------------------------------------------------
def test_drawable_labels_that_nothing_produces_are_known(tags_produzidas,
                                                         tags_renderizaveis):
    """
    Um icone que nada aciona e uma deteccao desenhada e nunca ligada. Nao e
    defeito de exibicao, mas e divida: alguem decidiu que o sinal importava e a
    coleta ficou pelo caminho.

    IMMUTABLE esta nesta condicao. O cenario de teste chega a criar arquivos com
    atributo imutavel, mas nenhum coletor verifica isso hoje. Fica declarado
    aqui para que a divida seja visivel em vez de esquecida.
    """
    orfaos = tags_renderizaveis - tags_produzidas - {"INSPECTOR"}
    assert orfaos == {"IMMUTABLE"}, (
        "Mudou o conjunto de rotulos sem coletor correspondente: %s" % sorted(orfaos))


# ------------------------------------------------------------------------------
# A BARRA DE FILTRO NASCE DO MESMO REGISTRO QUE O BADGE (achado do Mario,
# 2026-08-18): um sinal com badge e sem filtro correspondente esta presente
# so formalmente numa arvore de centenas de processos (D-028).
# ------------------------------------------------------------------------------
def test_toda_tag_do_registro_tem_botao_de_filtro():
    """
    Cada chave de badges.TAG_MAP vira um <span class="filter-btn"> na barra do
    topo. Testa contra o HTML gerado, nao contra uma segunda lista escrita a
    mao, pelo mesmo motivo do resto deste arquivo.
    """
    from src.core import badges as badges_reg
    from src.exporters.web_assets import FILTER_BAR_HTML

    for tag in badges_reg.TAG_MAP:
        assert ("setFilter('%s', this)" % tag) in FILTER_BAR_HTML, tag


def test_toda_tag_do_registro_tem_linha_na_legenda_de_badges():
    """A legenda dos badges (popup '?' ao lado de Filters) lista toda tag."""
    from src.core import badges as badges_reg
    from src.exporters.web_assets import BADGE_LEGEND_HTML

    for tag in badges_reg.TAG_MAP:
        assert ("<td>%s</td>" % tag) in BADGE_LEGEND_HTML, tag


def test_legenda_de_score_nao_trunca_o_texto():
    """
    Regressao: a regra global 'td { white-space:nowrap; text-overflow:ellipsis }'
    da arvore de processos vazava para dentro do popup de legenda do score e
    cortava rotulo/severidade no meio da palavra ("carregou kernel via ke...",
    "Hig..."). '.score-tooltip td' (seletor de classe + elemento) tem
    especificidade maior que 'td' sozinho e por isso sempre vence, mas so se a
    regra PROPRIA existir; sem ela o popup herda a truncagem da arvore.
    """
    from src.exporters.web_assets import CSS_BASE

    assert ".score-tooltip td {" in CSS_BASE
    inicio = CSS_BASE.index(".score-tooltip td {")
    bloco = CSS_BASE[inicio:inicio + 300]
    assert "white-space: normal" in bloco
    assert "overflow: visible" in bloco


# ------------------------------------------------------------------------------
# SIGNIFICADO FORENSE VISIVEL, NAO SO EM HOVER (achado do Mario, 2026-08-18:
# "ainda estou tentando entender a numeracao e valores" no popup de score, e
# "so tem o numero 3" no bloco Probe Signals do detalhe do processo).
# ------------------------------------------------------------------------------
def test_popup_de_score_mostra_a_explicacao_sem_precisar_de_hover():
    """
    A explicacao de cada sinal aparece como texto, nao so no title="".
    Compara contra a versao ESCAPADA (a mesma funcao que o renderizador usa):
    varias explicacoes citam "ATT&CK", e o "&" vira "&amp;" no HTML.
    """
    from src.core import risk
    from src.exporters.web_assets import LEGEND_HTML, _esc_legenda

    for _bit, _chave, _rotulo, _sev, explicacao in risk.SINAIS:
        assert _esc_legenda(explicacao) in LEGEND_HTML, explicacao[:40]


def test_popup_de_badges_traz_significado_forense_alem_do_rotulo_tecnico():
    """Cada linha da legenda de badges tem um segundo texto (o 'leg-sig')."""
    from src.core import badges as badges_reg
    from src.exporters.web_assets import BADGE_LEGEND_HTML, _esc_legenda

    for _tag, (_icone, _cls, _tooltip, significado) in badges_reg.TAG_MAP.items():
        assert _esc_legenda(significado) in BADGE_LEGEND_HTML, significado[:40]


def test_bloco_probe_signals_explica_cada_numero_que_mostra():
    """
    O bloco de detalhe do processo (Probe Signals) nao pode voltar a mostrar
    so o numero cru ("BPF Calls: 3") sem dizer o que aquilo significa.
    """
    from src.core import risk
    from src.exporters.html_report import (
        _PROBE_SIGNAL_ROWS, _EXPLICACAO_RISCO_POR_CHAVE)

    chaves_de_risco = {chave for _b, chave, _r, _s, _e in risk.SINAIS}
    for _campo, rotulo, _modo, chave_risco in _PROBE_SIGNAL_ROWS:
        assert chave_risco in chaves_de_risco, rotulo
        assert len(_EXPLICACAO_RISCO_POR_CHAVE[chave_risco]) > 40, rotulo


def test_titulo_do_bloco_probe_signals_nao_parece_um_carimbo_de_evento():
    """
    Regressao: o titulo era "Probe Signals (2026-08-17)". A data e de
    quando as SONDAS foram codificadas, nao do instante do evento; o Mario
    leu como se fosse timestamp e perguntou onde estava hora/minuto/segundo.
    Sem hora/minuto/segundo, uma data isolada no titulo e sempre ambigua:
    trava que o titulo nao volta a conter uma data sozinha (regex de data
    ISO, "AAAA-MM-DD").
    """
    import re
    from src.collectors.process_tree import ProcessNode
    from src.exporters.html_report import _render_probe_signals

    node = ProcessNode(42, 1, "proc", 0)
    node.bpf_calls = 3
    html = _render_probe_signals(node)
    assert "Probe Signals" in html
    assert not re.search(r"\d{4}-\d{2}-\d{2}", html), (
        "O titulo do bloco Probe Signals voltou a conter uma data isolada.")


# ------------------------------------------------------------------------------
# LOTE 2 (2026-08-19): os sinais novos nascem no registro unico, e o icone do
# badge acompanha o dado em TODO lugar do detalhe do processo, nao so na tabela
# Probe Signals (pedido do Mario).
#
# Estes testes nao repetem "existe botao de filtro?" e "existe linha na
# legenda?": aqueles testes ja varrem TAG_MAP inteiro, e por isso passaram a
# cobrir os sinais novos sozinhos, sem uma linha a mais. Era exatamente esse o
# objetivo do registro unico, e o fato de nao ter dado trabalho e a prova de que
# ele funcionou.
# ------------------------------------------------------------------------------
SINAIS_DO_LOTE_2 = ("TLS_SNI", "MOUNT_OP", "PIVOT_ROOT")


def test_os_sinais_do_lote_2_estao_no_registro_unico(tags_renderizaveis):
    for tag in SINAIS_DO_LOTE_2:
        assert tag in tags_renderizaveis, tag


def test_os_sinais_do_lote_2_sao_de_fato_produzidos_pelo_coletor(tags_produzidas):
    """A outra metade: badge sem coletor e icone que nunca acende."""
    for tag in SINAIS_DO_LOTE_2:
        assert tag in tags_produzidas, tag


def test_cada_sinal_do_lote_2_tem_bit_severidade_e_explicacao():
    from src.core import risk
    from src.core import badges as badges_reg

    chaves = {chave: (sev, exp)
              for _b, chave, _r, sev, exp in risk.SINAIS}
    for tag in SINAIS_DO_LOTE_2:
        chave = tag.lower()
        assert chave in chaves, chave
        severidade, explicacao = chaves[chave]
        assert severidade, chave
        # A explicacao e o texto que o analista le para decidir. Um rotulo
        # tecnico curto ("mount") nao ensina nada a quem nao sabe o que
        # perguntar.
        assert len(explicacao) > 80, chave
        # E a MESMA explicacao no badge: fonte unica (D-021/D-028).
        assert badges_reg.TAG_MAP[tag][3] == explicacao


def test_o_bloco_probe_signals_mostra_os_campos_do_lote_2_com_o_icone():
    """
    O pedido do Mario: o icone do badge tem que aparecer em todo lugar do
    processo expandido que mostre dado ligado a ele, e nao so na arvore. Sem
    isso o leitor precisa decorar qual emoji corresponde a qual campo.
    """
    from src.collectors.process_tree import ProcessNode
    from src.core import badges as badges_reg
    from src.exporters.html_report import _render_probe_signals

    node = ProcessNode(4242, 1, "cliente-tls", 0)
    node.tls_sni = ["chaos-sni-probe.sys-inspector.test"]
    node.mount_ops = ["/mnt/alvo (flags 0x1000)"]
    node.pivot_roots = ["/nova-raiz"]

    html = _render_probe_signals(node)
    for tag, valor in (("TLS_SNI", "chaos-sni-probe.sys-inspector.test"),
                       ("MOUNT_OP", "/mnt/alvo"),
                       ("PIVOT_ROOT", "/nova-raiz")):
        assert valor in html, valor
        assert badges_reg.TAG_MAP[tag][0] in html, tag


def test_campo_vazio_do_lote_2_nao_desenha_linha_nenhuma():
    """
    D-020 na pratica: silencio no bloco significa "a sonda olhou e nao havia",
    e nao "nao foi coletado". Uma linha "TLS SNI: 0" diria a mesma coisa que
    "nao ha sonda de SNI", que sao fatos diferentes.
    """
    from src.collectors.process_tree import ProcessNode
    from src.exporters.html_report import _render_probe_signals

    node = ProcessNode(4242, 1, "processo-quieto", 0)
    assert _render_probe_signals(node) == ""


def test_os_sinais_do_lote_2_sobem_na_arvore_como_os_demais():
    """
    Regressao do F-201: os badges sobem para o ancestral a partir de uma lista
    DERIVADA de TAG_MAP. Se alguem voltar a escrever essa lista a mao, os sinais
    novos param de aparecer no PID 1 e o score da subarvore fica sem o icone que
    o explica -- que foi exatamente o defeito corrigido no lote anterior.
    """
    from src.collectors.process_tree import TAGS_QUE_SOBEM_NA_ARVORE

    for tag in SINAIS_DO_LOTE_2:
        assert tag in TAGS_QUE_SOBEM_NA_ARVORE, tag
