# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_severity.py
# DESCRIPTION: Testa o mapeamento anomaly_score -> rotulo de severidade usado no
#              badge de alerta do relatorio (C2). Faixas provisorias ate a
#              normalizacao definitiva na aba Findings.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.exporters.html_report import _severity_label


def test_severity_thresholds():
    """Cada faixa numerica mapeia para o rotulo esperado."""
    assert _severity_label(0) is None
    assert _severity_label(1) == "Low"
    assert _severity_label(7) == "Low"
    assert _severity_label(8) == "Medium"
    assert _severity_label(31) == "Medium"
    assert _severity_label(32) == "High"
    assert _severity_label(64) == "High"
    assert _severity_label(128) == "Critical"
    assert _severity_label(256) == "Critical"


def test_severity_invalid_and_negative():
    """Entradas invalidas ou nao positivas retornam None (sem badge)."""
    assert _severity_label(None) is None
    assert _severity_label("x") is None
    assert _severity_label(-5) is None
