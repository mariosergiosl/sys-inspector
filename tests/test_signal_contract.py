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
FONTE_LAUDO = os.path.join("src", "exporters", "html_report.py")

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
    """Todo rotulo que o laudo sabe desenhar."""
    fonte = _ler(FONTE_LAUDO)
    bloco = fonte.split("tag_map = {")[1].split("\n    }")[0]
    return set(re.findall(r'^\s{8}"([^"]+)"\s*:', bloco, re.MULTILINE))


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
