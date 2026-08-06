# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_html_escaping.py
# DESCRIPTION: Garante que dados controlados pelo host analisado (linha de
#              comando, caminhos, usuario) nao escapem do HTML do relatorio.
#
#              Regressao real: uma cmdline contendo aspas fechava o atributo
#              title="..." do badge ZOMBIE e o restante do texto vazava para a
#              coluna ALERTS. O mesmo vetor permitiria injetar marcacao no laudo
#              lido pelo analista.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.exporters.html_report import _esc, _render_badges
from src.collectors.process_tree import ProcessTree, ProcessNode


# ------------------------------------------------------------------------------
# Helper de escape
# ------------------------------------------------------------------------------
def test_escapes_quotes_and_markup():
    """Aspas e sinais de marcacao sao neutralizados."""
    assert '"' not in _esc('sed "s/x//"')
    assert "&quot;" in _esc('sed "s/x//"')
    assert "<" not in _esc("<script>alert(1)</script>")
    assert "&lt;script&gt;" in _esc("<script>alert(1)</script>")


def test_escapes_ampersand_from_shell_redirect():
    """Redirecionamento de shell (2>&1) nao vira entidade HTML quebrada."""
    out = _esc("cmd 2>&1")
    assert "&amp;" in out
    assert ">" not in out


def test_none_becomes_empty_string():
    """Valor ausente nao imprime a palavra 'None' no laudo."""
    assert _esc(None) == ""


# ------------------------------------------------------------------------------
# Regressao do vazamento no badge
# ------------------------------------------------------------------------------
def _tree_with_zombie(parent_cmd):
    """Monta uma arvore com um zumbi cujo pai tem a cmdline informada."""
    tree = ProcessTree()
    parent = ProcessNode(100, 1, parent_cmd, 0)
    child = ProcessNode(101, 100, "child", 0)
    child.context_tags = ["ZOMBIE"]
    tree.nodes[100] = parent
    tree.nodes[101] = child
    return tree


def test_zombie_tooltip_does_not_break_out_of_attribute():
    """
    Cmdline do pai com aspas nao pode fechar o atributo title, senao o texto
    vaza para a coluna ALERTS (bug observado em captura real).
    """
    tree = _tree_with_zombie('bash -c sed "s/\\x1b//g" 2>&1')
    html = _render_badges(tree.nodes[101], tree)

    # O atributo title deve conter exatamente uma abertura e um fechamento.
    title_start = html.count('title="')
    assert title_start >= 1
    # Nenhuma aspa crua do dado deve sobrar dentro do atributo renderizado.
    assert 'sed "s/' not in html
    assert "&quot;" in html


def test_zombie_tooltip_neutralizes_injected_markup():
    """
    Marcacao na cmdline do pai nao pode virar HTML no laudo.

    O texto da evidencia CONTINUA visivel (um laudo deve mostrar a linha de
    comando real); o que nao pode e ela formar uma tag executavel. Por isso a
    verificacao e sobre os caracteres perigosos, nao sobre o texto sumir.
    """
    tree = _tree_with_zombie('evil"><img src=x onerror=alert(1)>')
    html = _render_badges(tree.nodes[101], tree)

    # Nenhuma tag real formada a partir do dado.
    assert "<img" not in html
    # Os caracteres perigosos viraram entidades.
    assert "&lt;img" in html
    assert "&quot;&gt;" in html
    # A evidencia permanece legivel para o analista.
    assert "onerror=alert(1)" in html


def test_badge_structure_is_preserved():
    """O badge continua sendo emitido normalmente (sem regressao de layout)."""
    tree = _tree_with_zombie("/usr/bin/normal-parent")
    html = _render_badges(tree.nodes[101], tree)
    assert 'class="tag t-zombie"' in html
    assert 'data-filter="ZOMBIE"' in html
    assert "🧟" in html
