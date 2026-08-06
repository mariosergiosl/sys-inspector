# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_findings.py
# DESCRIPTION: Testa a entidade Finding: escala de severidade, fingerprint
#              estavel, ordenacao por gravidade, deduplicacao e resumo.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core.findings import (Finding, sort_findings, dedupe_findings,
                               summarize_by_severity, SEV_INFO, SEV_LOW,
                               SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL,
                               SRC_PERSISTENCE, SRC_EBPF)


def _mk(title="t", severity=SEV_LOW, source=SRC_PERSISTENCE, target="x"):
    return Finding(title=title, severity=severity, source=source, target=target)


def test_source_is_preserved():
    """A origem do achado e preservada (precisa ficar visivel na interface)."""
    assert _mk(source=SRC_EBPF).source == SRC_EBPF
    assert _mk(source=SRC_PERSISTENCE).source == SRC_PERSISTENCE


def test_invalid_severity_falls_back_to_info():
    """Severidade fora da escala vira Info em vez de propagar valor invalido."""
    assert Finding("t", "Bogus", SRC_PERSISTENCE).severity == SEV_INFO


def test_fingerprint_is_stable_and_distinct():
    """Mesma identidade gera o mesmo fingerprint; alvo diferente muda o valor."""
    assert _mk(target="/etc/a").fingerprint == _mk(target="/etc/a").fingerprint
    assert _mk(target="/etc/a").fingerprint != _mk(target="/etc/b").fingerprint


def test_fingerprint_ignores_evidence():
    """A evidencia pode variar entre capturas sem quebrar a correlacao."""
    a = Finding("t", SEV_LOW, SRC_PERSISTENCE, target="x", evidence={"mtime": 1})
    b = Finding("t", SEV_LOW, SRC_PERSISTENCE, target="x", evidence={"mtime": 2})
    assert a.fingerprint == b.fingerprint


def test_sort_puts_most_severe_first():
    """Ordenacao ranqueia do mais grave para o menos grave."""
    items = [_mk("a", SEV_LOW), _mk("b", SEV_CRITICAL),
             _mk("c", SEV_INFO), _mk("d", SEV_HIGH)]
    order = [f.severity for f in sort_findings(items)]
    assert order == [SEV_CRITICAL, SEV_HIGH, SEV_LOW, SEV_INFO]


def test_dedupe_removes_repeats_preserving_order():
    """Achados identicos sao colapsados em um so."""
    items = [_mk(target="/etc/a"), _mk(target="/etc/a"), _mk(target="/etc/b")]
    assert len(dedupe_findings(items)) == 2


def test_summary_counts_by_severity():
    """O resumo conta corretamente por nivel."""
    counts = summarize_by_severity([_mk(severity=SEV_HIGH),
                                    _mk("z", SEV_HIGH, target="y"),
                                    _mk("w", SEV_MEDIUM, target="k")])
    assert counts[SEV_HIGH] == 2
    assert counts[SEV_MEDIUM] == 1
    assert counts[SEV_CRITICAL] == 0


def test_to_dict_exposes_source_and_rank():
    """A serializacao carrega a origem e o peso, usados pela interface."""
    data = _mk(severity=SEV_CRITICAL).to_dict()
    assert data["source"] == SRC_PERSISTENCE
    assert data["rank"] == 4
    assert "fingerprint" in data
