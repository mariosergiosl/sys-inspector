# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_report_structure.py
# DESCRIPTION: Guarda a estrutura do relatorio contra regressao. A introducao
#              das abas nao pode remover nem alterar a arvore de processos, seus
#              controles, filtros e colunas, que sao a interface principal.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.exporters.web_assets import HTML_TEMPLATE, CSS_BASE, JS_BLOCK


# ------------------------------------------------------------------------------
# Preservacao da arvore de processos
# ------------------------------------------------------------------------------
def test_process_table_and_controls_are_preserved():
    """
    A tabela, os controles e o cabecalho de colunas continuam no template.
    Verifica o nome da classe, nao o atributo inteiro, para nao quebrar quando
    uma classe auxiliar (ex.: panel-hidden) e acrescentada ao elemento.
    """
    for marker in ('class="table-container', 'class="controls',
                   'class="tbl-hdr', "{TABLE_ROWS}", 'id="search"'):
        assert marker in HTML_TEMPLATE, marker


def test_all_process_columns_are_preserved():
    """Nenhuma coluna da arvore foi perdida."""
    for column in ("Command Tree", "PID", "Duration", "User", "Nice", "CPU%",
                   "RSS", "Disk &Delta;", "Disk &Sigma;", "Net TX", "Net RX",
                   "Alerts"):
        assert column in HTML_TEMPLATE, column


def test_toolbar_actions_are_preserved():
    """Ordenacao, filtros e limpeza continuam disponiveis."""
    for action in ("setFilter(", "sortView(", "filterTable()", "window.print()"):
        assert action in HTML_TEMPLATE or action in JS_BLOCK, action


def test_inventory_cards_are_preserved():
    """Os blocos de inventario (SO, disco, rede) seguem no relatorio."""
    for slot in ("{OS_CONTENT}", "{DISK_CONTENT}", "{NET_CONTENT}"):
        assert slot in HTML_TEMPLATE, slot


# ------------------------------------------------------------------------------
# Abas
# ------------------------------------------------------------------------------
def test_tabs_exist_for_findings_and_processes():
    """As duas abas estao declaradas e alternam via showTab."""
    assert 'class="tabbar"' in HTML_TEMPLATE
    assert "showTab('findings'" in HTML_TEMPLATE
    assert "showTab('processes'" in HTML_TEMPLATE


def test_process_elements_are_grouped_in_one_panel():
    """
    Controles, cabecalho e tabela pertencem ao mesmo painel, para alternarem
    juntos e a arvore nunca aparecer pela metade.
    """
    assert HTML_TEMPLATE.count('data-panel="processes"') == 3


def test_table_header_keeps_its_flex_layout():
    """
    O cabecalho de colunas depende de display:flex inline. Se a alternancia de
    aba zerar esse inline, ele volta para block e as colunas empilham na
    vertical (regressao observada em 2026-08-06).
    """
    idx = HTML_TEMPLATE.index('class="tbl-hdr')
    trecho = HTML_TEMPLATE[idx:idx + 260]
    assert "display:flex" in trecho
    assert "display:none" not in trecho


def test_panels_toggle_by_class_not_inline_style():
    """A troca de aba usa a classe panel-hidden, preservando os estilos inline."""
    assert ".panel-hidden" in CSS_BASE
    assert "classList.add('panel-hidden')" in JS_BLOCK
    assert "classList.remove('panel-hidden')" in JS_BLOCK
    # Nenhum painel pode nascer com display:none inline.
    for marker in ('data-panel="processes"', 'data-panel="findings"'):
        pos = 0
        while True:
            pos = HTML_TEMPLATE.find(marker, pos)
            if pos == -1:
                break
            fim = HTML_TEMPLATE.find(">", pos)
            assert "display:none" not in HTML_TEMPLATE[pos:fim], marker
            pos = fim


def test_findings_panel_slot_exists():
    """O painel de achados tem seu proprio espaco no template."""
    assert 'data-panel="findings"' in HTML_TEMPLATE
    assert "{FINDINGS_CONTENT}" in HTML_TEMPLATE


def test_tab_switching_logic_toggles_by_panel():
    """A troca de aba opera por data-panel, sem remover nada do DOM."""
    assert "function showTab(" in JS_BLOCK
    assert "data-panel" in JS_BLOCK


def test_findings_helpers_exist():
    """Expandir evidencia e filtrar por severidade estao implementados."""
    assert "function toggleFinding(" in JS_BLOCK
    assert "function filterFindings(" in JS_BLOCK


def test_tab_and_findings_styles_are_defined():
    """As classes usadas pelo painel tem estilo, para nao renderizar cru."""
    for cls in (".tabbar", ".tab-active", ".fnd-item", ".fnd-sev", ".fnd-src",
                ".fnd-ev-v"):
        assert cls in CSS_BASE, cls


def test_template_placeholders_are_consistent():
    """
    Todo placeholder do template precisa ser fornecido por quem o renderiza;
    um placeholder novo sem valor quebra a geracao com KeyError.
    """
    import re
    found = set(re.findall(r"\{([A-Z_]+)\}", HTML_TEMPLATE))
    expected = {"VERSION", "HOSTNAME", "TIMESTAMP", "CSS_BLOCK", "JS_BLOCK",
                "LEGEND_HTML", "OS_CONTENT", "DISK_CONTENT", "NET_CONTENT",
                "FINDINGS_CONTENT", "FINDINGS_BADGE", "ATTACK_CONTENT",
                "TABLE_ROWS"}
    assert found == expected, found ^ expected
