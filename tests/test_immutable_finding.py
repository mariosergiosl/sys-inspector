# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_immutable_finding.py
# DESCRIPTION: Arquivo imutavel detectado como Finding de persistencia.
#
# WHY:         A certificacao do chaos revelou que a deteccao do arquivo imutavel
#              saia INTERMITENTE: ela vivia como um bit somado ao anomaly_score do
#              PID 1 dentro do motor eBPF, e ali era fragil. A deteccao confiavel
#              vive no coletor de persistencia, que roda determinístico a cada
#              captura e produz Findings decifrados no servidor pelo mesmo caminho
#              dos demais (cron, systemd, ld.so.preload) -- que NUNCA falharam.
#
# NOTES:       Nao depende de root nem de chattr: injeta a saida do scanner.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.collectors import persistence as pers
from src.core.findings import SEV_HIGH, SRC_PERSISTENCE
from src.core.attack import TECHNIQUES


def test_immutable_file_vira_finding(monkeypatch):
    monkeypatch.setattr(
        "src.collectors.process_tree._immutable_files_in",
        lambda *_a, **_k: ["/tmp/chaos_artifacts/immutable.dat (----i-----------)"])
    monkeypatch.setattr(pers, "_stat_info", lambda _p: {"mtime": 1})

    findings = pers._collect_immutable_files()
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == SEV_HIGH
    assert f.source == SRC_PERSISTENCE
    assert f.technique == "T1222.002"
    assert f.target == "/tmp/chaos_artifacts/immutable.dat"
    assert f.evidence["attributes"] == "----i-----------"


def test_sem_imutavel_nenhum_finding(monkeypatch):
    monkeypatch.setattr(
        "src.collectors.process_tree._immutable_files_in",
        lambda *_a, **_k: [])
    assert pers._collect_immutable_files() == []


def test_o_coletor_entra_na_composicao_de_persistencia():
    """A busca de imutavel tem que estar entre os coletores executados."""
    import inspect
    fonte = inspect.getsource(pers.collect_persistence)
    assert "_collect_immutable_files" in fonte


def test_a_tecnica_tem_verbete():
    assert "T1222.002" in TECHNIQUES


def test_uma_falha_no_coletor_nao_derruba_os_demais(monkeypatch):
    """
    collect_persistence isola cada coletor: se a busca de imutavel falhar, os
    outros achados (cron, systemd) continuam. Sem isso, um erro no scanner
    perderia a captura inteira.
    """
    def _explode(*_a, **_k):
        raise RuntimeError("scanner quebrou")
    monkeypatch.setattr(
        "src.collectors.process_tree._immutable_files_in", _explode)
    # Nao deve levantar: collect_persistence engole a falha por coletor.
    findings = pers.collect_persistence()
    assert isinstance(findings, list)
