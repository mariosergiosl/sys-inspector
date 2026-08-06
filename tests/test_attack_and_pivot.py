# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_attack_and_pivot.py
# DESCRIPTION: Testa a legenda MITRE ATT&CK e o pivo do achado para o processo
#              em execucao.
#
#              Achados de persistencia apontam para ARQUIVOS, nao para PIDs. O
#              pivo so faz sentido quando o caminho denunciado esta de fato
#              sendo executado; nesse caso a persistencia deixa de ser teorica.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core.attack import describe, technique_url, used_techniques, TECHNIQUES
from src.collectors.manager import correlate_findings_with_processes
from src.exporters.html_report import render_attack_panel, render_findings_panel
from src.core.findings import Finding, SEV_CRITICAL, SRC_PERSISTENCE


def _finding(related_pids=None, **kw):
    """
    Cria um achado serializado. 'related_pids' nao e campo do Finding: ele e
    acrescentado ao dict pela correlacao com os processos, ja depois da
    serializacao, e por isso e tratado aqui da mesma forma.
    """
    base = dict(title="t", severity=SEV_CRITICAL, source=SRC_PERSISTENCE)
    base.update(kw)
    data = Finding(**base).to_dict()
    if related_pids:
        data["related_pids"] = related_pids
    return data


# ------------------------------------------------------------------------------
# Catalogo ATT&CK
# ------------------------------------------------------------------------------
def test_catalogue_covers_every_technique_the_tool_emits():
    """
    Toda tecnica citada pelos coletores precisa ter legenda, senao o laudo
    mostra um codigo sem significado.
    """
    import re
    import io
    src = io.open("src/collectors/persistence.py", encoding="utf-8").read()
    emitted = set(re.findall(r'technique="([^"]+)"', src))
    faltando = emitted - set(TECHNIQUES)
    assert not faltando, "sem legenda: %s" % faltando


def test_describe_returns_name_tactic_and_description():
    """A legenda traz nome, tatica e explicacao."""
    name, tactic, desc = describe("T1053.003")
    assert "Cron" in name
    assert "Persistence" in tactic
    assert len(desc) > 20


def test_describe_is_safe_for_unknown_ids():
    """Identificador desconhecido nao levanta excecao."""
    assert describe("T9999") is None
    assert describe("") is None
    assert describe(None) is None


def test_subtechnique_url_uses_slash():
    """Sub-tecnica vira T1053/003 na URL do MITRE."""
    assert technique_url("T1053.003").endswith("/techniques/T1053/003/")
    assert technique_url("T1547").endswith("/techniques/T1547/")


def test_used_techniques_are_unique_and_sorted():
    """A legenda lista cada tecnica uma vez."""
    items = [_finding(technique="T1547"), _finding(technique="T1037"),
             _finding(technique="T1547")]
    assert used_techniques(items) == ["T1037", "T1547"]


# ------------------------------------------------------------------------------
# Painel ATT&CK
# ------------------------------------------------------------------------------
def test_attack_panel_explains_the_technique():
    """O painel mostra o codigo, o nome e a descricao."""
    html = render_attack_panel([_finding(technique="T1574.006")])
    assert "T1574.006" in html
    assert "Dynamic Linker Hijacking" in html
    assert "attack.mitre.org" in html


def test_attack_panel_without_techniques():
    """Captura sem tecnicas nao quebra o painel."""
    assert "No ATT&amp;CK techniques" in render_attack_panel([])


# ------------------------------------------------------------------------------
# Correlacao achado -> processo
# ------------------------------------------------------------------------------
def test_correlates_finding_to_running_process():
    """
    O cron aponta para /dev/shm/miner.sh e existe um processo executando esse
    caminho: a persistencia esta ativa agora.
    """
    findings = [_finding(evidence={"reference": "/dev/shm/miner.sh"})]
    processes = {"4242": {"exe_path": "/dev/shm/miner.sh", "cmd": "/dev/shm/miner.sh"}}
    correlate_findings_with_processes(findings, processes)
    assert findings[0]["related_pids"] == [4242]


def test_no_correlation_leaves_finding_without_pids():
    """Sem processo correspondente, nenhum pivo e criado (nada de link morto)."""
    findings = [_finding(evidence={"reference": "/dev/shm/miner.sh"})]
    processes = {"1": {"exe_path": "/usr/lib/systemd/systemd", "cmd": "systemd"}}
    correlate_findings_with_processes(findings, processes)
    assert "related_pids" not in findings[0]


def test_correlation_handles_missing_data():
    """Entrada vazia nao quebra a correlacao."""
    assert correlate_findings_with_processes([], {}) == []
    assert correlate_findings_with_processes(None, None) is None


def test_correlation_finds_multiple_processes():
    """Varios processos do mesmo caminho sao todos reportados."""
    findings = [_finding(evidence={"reference": "/tmp/implant.sh"})]
    processes = {"10": {"exe_path": "/tmp/implant.sh", "cmd": "x"},
                 "11": {"exe_path": "/tmp/implant.sh", "cmd": "x"}}
    correlate_findings_with_processes(findings, processes)
    assert findings[0]["related_pids"] == [10, 11]


# ------------------------------------------------------------------------------
# Botao de pivo na interface
# ------------------------------------------------------------------------------
def test_pivot_button_appears_only_when_correlated():
    """O botao so existe quando ha processo correspondente."""
    com = render_findings_panel([_finding(related_pids=[4242])])
    sem = render_findings_panel([_finding()])
    assert "pivotToProcess" in com
    assert "4242" in com
    assert "pivotToProcess" not in sem


def test_technique_badge_carries_the_legend_in_the_tooltip():
    """O badge da tecnica explica o que ela significa ao passar o mouse."""
    html = render_findings_panel([_finding(technique="T1543.002")])
    assert "Systemd Service" in html
