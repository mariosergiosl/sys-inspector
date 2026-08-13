# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_tab_coupling.py
# DESCRIPTION: Testa o acoplamento entre as abas do laudo (Passo 3, D-022): a
#              tecnica no achado leva a aba ATT&CK, e a tecnica na aba ATT&CK
#              leva de volta aos achados que a citam; a faixa guiada "como ler";
#              o rotulo da aba ATT&CK com contagem de tecnicas.
#
#              O Mario apontou que so o "?" nao bastava: as abas ficavam soltas.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core.findings import Finding, SEV_CRITICAL, SRC_PERSISTENCE
from src.exporters.html_report import render_findings_panel, render_attack_panel
from src.exporters.web_assets import HTML_TEMPLATE, JS_BLOCK


def _f(technique="T1053.003"):
    return Finding(title="t", severity=SEV_CRITICAL, source=SRC_PERSISTENCE,
                   technique=technique,
                   evidence={"reference": "/dev/shm/x"}).to_dict()


# ------------------------------------------------------------------------------
# Achado -> aba ATT&CK
# ------------------------------------------------------------------------------
def test_technique_badge_is_clickable_to_attack_tab():
    """O badge da tecnica pivota para a aba ATT&CK, sem abrir/fechar o achado."""
    html = render_findings_panel([_f()])
    assert "pivotToAttack('T1053.003')" in html
    assert "stopPropagation" in html


def test_finding_item_carries_its_technique():
    """O item do achado guarda a tecnica, para o filtro de volta encontra-lo."""
    html = render_findings_panel([_f("T1543.002")])
    assert 'data-technique="T1543.002"' in html


# ------------------------------------------------------------------------------
# Aba ATT&CK -> achados
# ------------------------------------------------------------------------------
def test_attack_item_has_anchor_id():
    """Cada tecnica tem ancora, para o pivo do achado rolar ate ela."""
    html = render_attack_panel([_f("T1574.006")])
    assert 'id="atk-T1574.006"' in html


def test_attack_item_links_back_to_findings():
    """A tecnica citada oferece voltar aos achados que a citam."""
    html = render_attack_panel([_f("T1053.003")])
    assert "filterFindingsByTechnique('T1053.003')" in html
    assert "Ver achados" in html


# ------------------------------------------------------------------------------
# Faixa guiada e rotulo da aba
# ------------------------------------------------------------------------------
def test_read_guide_strip_is_present():
    """A faixa 'como ler' (1 Achados -> 2 Processes -> 3 ATT&CK) existe."""
    assert "read-guide" in HTML_TEMPLATE
    assert "Como ler" in HTML_TEMPLATE


def test_attack_tab_has_a_count_badge_placeholder():
    """A aba ATT&CK ganha rotulo com contagem de tecnicas."""
    assert "{ATTACK_BADGE}" in HTML_TEMPLATE


def test_pivot_helpers_exist_in_js():
    """As duas funcoes de pivo entre abas estao no JS do laudo."""
    assert "function pivotToAttack" in JS_BLOCK
    assert "function filterFindingsByTechnique" in JS_BLOCK


# ------------------------------------------------------------------------------
# O template inteiro ainda formata (pega placeholder novo sem valor)
# ------------------------------------------------------------------------------
def test_template_formats_with_all_placeholders():
    """
    Adicionar {ATTACK_BADGE} quebraria qualquer chamador que nao o fornecesse.
    Este teste formata o template com o conjunto completo de campos que os dois
    chamadores usam, garantindo que o template nao referencia nada alem disso.
    """
    campos = dict(
        VERSION="x", HOSTNAME="h", TIMESTAMP="t", CSS_BLOCK="", JS_BLOCK="",
        LEGEND_HTML="", OS_CONTENT="", DISK_CONTENT="", NET_CONTENT="",
        FINDINGS_CONTENT="", FINDINGS_BADGE="", ATTACK_CONTENT="",
        ATTACK_BADGE="<span>3</span>", TABLE_ROWS="")
    saida = HTML_TEMPLATE.format(**campos)
    assert "read-guide" in saida
    assert "<span>3</span>" in saida
