# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_findings_enrichment.py
# DESCRIPTION: Testa o enriquecimento da aba Findings (Passo 3 do contrato,
#              D-022): selo de confianca, linha de custodia, tooltip explicando
#              cada campo da evidencia, legenda de severidade COM acao, e o
#              renome de "Mostrar todos" para "Ver todos os niveis".
#
#              Sao respostas do contrato que agora existem e precisam aparecer no
#              laudo sem inventar o que nao ha (confianca None nao vira selo).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core.findings import (
    Finding, SEV_CRITICAL, SEV_HIGH, SRC_PERSISTENCE,
    CONF_PROBABLE, CONF_HEURISTIC, CUSTODY_METADATA, CUSTODY_NONE)
from src.exporters.html_report import render_findings_panel


def _dict(**kw):
    base = dict(title="t", severity=SEV_HIGH, source=SRC_PERSISTENCE)
    base.update(kw)
    return Finding(**base).to_dict()


# ------------------------------------------------------------------------------
# Confianca
# ------------------------------------------------------------------------------
def test_confidence_badge_appears_when_declared():
    """Confianca declarada vira selo com o rotulo PT."""
    html = render_findings_panel([_dict(confidence=CONF_PROBABLE)])
    assert "provavel" in html
    assert "fnd-conf" in html


def test_confidence_absent_when_not_declared():
    """Sem confianca, nenhum selo (nao inventa certeza)."""
    html = render_findings_panel([_dict(confidence=None)])
    assert "fnd-conf" not in html


def test_heuristic_confidence_is_labelled():
    """Heuristica aparece nomeada, para nao ser lida como fato."""
    html = render_findings_panel([_dict(confidence=CONF_HEURISTIC)])
    assert "heuristico" in html


# ------------------------------------------------------------------------------
# Custodia
# ------------------------------------------------------------------------------
def test_custody_line_shows_level():
    """A custodia diz o que foi preservado do artefato."""
    html = render_findings_panel(
        [_dict(custody={"level": CUSTODY_METADATA})])
    assert "Custodia" in html
    assert "so metadado" in html


def test_custody_none_warns_nothing_preserved():
    """Custodia vazia avisa que nada do artefato foi retido."""
    html = render_findings_panel([_dict(custody={"level": CUSTODY_NONE})])
    assert "nada" in html


# ------------------------------------------------------------------------------
# Tooltip da evidencia (para que serve cada campo)
# ------------------------------------------------------------------------------
def test_known_evidence_keys_get_a_tooltip():
    """reference/meta/provenance ganham explicacao no title."""
    html = render_findings_panel([_dict(
        evidence={"reference": "/dev/shm/x", "meta": {"uid": 0},
                  "provenance": {"packaged": False}})])
    assert "o que de fato roda" in html.lower()
    assert "metadados do arquivo" in html.lower()
    assert "plantado" in html.lower()


def test_unknown_evidence_key_has_no_fake_help():
    """Chave desconhecida nao ganha tooltip inventado."""
    html = render_findings_panel([_dict(evidence={"xyz": "algo"})])
    # a chave aparece, mas sem cursor de ajuda (nao fingimos significado)
    assert "xyz" in html
    assert "cursor:help' title=" not in html.split("xyz")[0][-120:]


# ------------------------------------------------------------------------------
# Legenda de severidade com acao e renome do filtro
# ------------------------------------------------------------------------------
def test_help_explains_severity_with_action():
    """A ajuda diz o que cada severidade significa E o que fazer."""
    html = render_findings_panel([_dict(severity=SEV_CRITICAL)])
    assert "conter agora" in html
    assert "investigar hoje" in html


def test_show_all_filter_was_renamed():
    """'Mostrar todos' virou 'Ver todos os niveis', mais claro."""
    html = render_findings_panel([_dict()])
    assert "Ver todos os niveis" in html
    assert "Mostrar todos" not in html
