# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_findings_panel.py
# DESCRIPTION: Testa a aba Findings do relatorio: ordenacao por gravidade,
#              exibicao da origem (source) e da tecnica ATT&CK, evidencia
#              anexada, escaping e a escala unica de severidade compartilhada
#              com a arvore de processos.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.exporters.html_report import (render_findings_panel, _severity_label,
                                       SEVERITY_COLORS)
from src.core.findings import (Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM,
                               SEV_HIGH, SEV_CRITICAL, SRC_PERSISTENCE)


def _finding(**kw):
    """Cria um Finding serializado, como viaja no payload da captura."""
    base = dict(title="t", severity=SEV_HIGH, source=SRC_PERSISTENCE)
    base.update(kw)
    return Finding(**base).to_dict()


# ------------------------------------------------------------------------------
# Escala unica de severidade
# ------------------------------------------------------------------------------
def test_severity_uses_the_shared_scale():
    """A arvore usa os mesmos rotulos do Finding, nao uma escala paralela."""
    assert _severity_label(128) == SEV_CRITICAL
    assert _severity_label(64) == SEV_HIGH
    assert _severity_label(8) == SEV_MEDIUM
    assert _severity_label(1) == SEV_LOW
    assert _severity_label(0) is None


def test_every_severity_has_a_color():
    """Toda severidade da escala tem cor definida (consistencia visual)."""
    for sev in (SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL):
        assert sev in SEVERITY_COLORS


# ------------------------------------------------------------------------------
# Painel
# ------------------------------------------------------------------------------
def test_empty_findings_render_a_message_not_a_crash():
    """Captura sem achados nao quebra o relatorio."""
    html = render_findings_panel([])
    assert "fnd-empty" in html


def test_most_severe_finding_comes_first():
    """A lista e ranqueada: o analista ve o pior primeiro."""
    items = [
        _finding(title="baixo", severity=SEV_LOW),
        _finding(title="critico", severity=SEV_CRITICAL),
        _finding(title="medio", severity=SEV_MEDIUM),
    ]
    html = render_findings_panel(items)
    assert html.index("critico") < html.index("medio") < html.index("baixo")


def test_source_is_visible_in_the_panel():
    """
    Requisito do Mario: tem que ficar claro O QUE coletou a informacao.
    """
    html = render_findings_panel([_finding(source="persistence")])
    assert "fnd-src" in html
    assert "persistence" in html


def test_attack_technique_is_shown():
    """A tecnica MITRE ATT&CK aparece no achado."""
    html = render_findings_panel([_finding(technique="T1543.002")])
    assert "T1543.002" in html


def test_evidence_and_recommendation_are_rendered():
    """A evidencia bruta e a acao recomendada acompanham o achado."""
    html = render_findings_panel([_finding(
        evidence={"reference": "/tmp/implant.sh"},
        recommendation="Inspect the referenced binary.")])
    assert "/tmp/implant.sh" in html
    assert "Inspect the referenced binary." in html


def test_summary_counts_by_severity():
    """O resumo mostra a contagem por severidade."""
    items = [_finding(severity=SEV_CRITICAL, target="a"),
             _finding(severity=SEV_CRITICAL, target="b"),
             _finding(severity=SEV_LOW, target="c")]
    html = render_findings_panel(items)
    assert "fnd-summary" in html
    assert SEV_CRITICAL in html


def test_findings_panel_escapes_host_controlled_data():
    """
    Caminhos e evidencias vem do host analisado: nao podem injetar marcacao.
    """
    html = render_findings_panel([_finding(
        title='evil"><img src=x onerror=alert(1)>',
        target="/tmp/<script>",
        evidence={"content": "<script>alert(1)</script>"})])
    assert "<img" not in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_long_evidence_is_truncated():
    """Evidencia gigante e truncada para nao inflar o laudo."""
    html = render_findings_panel([_finding(evidence={"content": "A" * 5000})])
    assert "[truncated]" in html


def test_item_carries_severity_for_filtering():
    """Cada achado expoe a severidade para o filtro da interface."""
    html = render_findings_panel([_finding(severity=SEV_HIGH)])
    assert 'data-sev="High"' in html
