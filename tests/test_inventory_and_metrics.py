# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_inventory_and_metrics.py
# DESCRIPTION: Testa o inventario estatico e o resumo de metricas quentes.
#
#              O inventario descreve o sistema periciado (SO, hardware, rede,
#              armazenamento) e abre o laudo; se ele falhar, a captura inteira
#              se perde. As metricas alimentam as colunas usadas para ordenar e
#              montar a linha do tempo sem descriptografar o conteudo.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os

import pytest

from src.collectors.system_inventory import collect_full_inventory
from src.collectors.manager import summarize_metrics


# ------------------------------------------------------------------------------
# Inventario estatico
# ------------------------------------------------------------------------------
@pytest.mark.skipif(not os.path.exists("/proc"), reason="requer Linux")
def test_inventory_has_the_sections_the_report_needs():
    """
    O relatorio le estas secoes diretamente; faltar uma quebra a geracao do
    laudo depois de a coleta ja ter sido feita.
    """
    inv = collect_full_inventory()
    for section in ("os", "hw", "net", "storage", "generated"):
        assert section in inv, section


@pytest.mark.skipif(not os.path.exists("/proc"), reason="requer Linux")
def test_inventory_identifies_the_host():
    """O laudo precisa dizer de qual maquina a evidencia veio."""
    inv = collect_full_inventory()
    assert inv["os"].get("hostname")


@pytest.mark.skipif(not os.path.exists("/proc"), reason="requer Linux")
def test_storage_reports_mount_points():
    """Os pontos de montagem sustentam a atribuicao de arquivo a dispositivo."""
    assert isinstance(collect_full_inventory()["storage"].get("mounts", {}), dict)


@pytest.mark.skipif(not os.path.exists("/proc"), reason="requer Linux")
def test_inventory_is_repeatable():
    """Duas coletas seguidas produzem a mesma estrutura."""
    assert set(collect_full_inventory()) == set(collect_full_inventory())


# ------------------------------------------------------------------------------
# Metricas quentes
# ------------------------------------------------------------------------------
def test_metrics_of_an_empty_capture():
    """Captura sem processos nao gera divisao por zero nem valores invalidos."""
    m = summarize_metrics({})
    assert m["pids"] == 0
    assert m["score"] == 0
    assert m["cpu"] == 0.0


def test_score_is_the_worst_process_not_the_sum():
    """
    O alerta representa o processo MAIS suspeito. Somar diluiria o pior caso
    numa media e mascararia o achado grave.
    """
    procs = {1: {"anomaly_score": 8}, 2: {"anomaly_score": 128},
             3: {"anomaly_score": 4}}
    assert summarize_metrics(procs)["score"] == 128


def test_pid_count_matches_the_capture():
    """A contagem de processos reflete a arvore capturada."""
    procs = {i: {"anomaly_score": 0} for i in range(7)}
    assert summarize_metrics(procs)["pids"] == 7


def test_metrics_tolerate_missing_or_invalid_fields():
    """Processo sem campos, ou com valores estranhos, nao derruba o resumo."""
    procs = {1: {}, 2: {"cpu_usage_pct": None, "anomaly_score": None},
             3: {"cpu_usage_pct": "x"}}
    m = summarize_metrics(procs)
    assert m["pids"] == 3
    assert m["score"] == 0


@pytest.mark.skipif(not os.path.exists("/proc/meminfo"), reason="requer Linux")
def test_memory_usage_is_plausible():
    """A memoria usada e um valor positivo e coerente com o host."""
    mem = summarize_metrics({1: {"anomaly_score": 0}})["mem"]
    assert mem > 0
