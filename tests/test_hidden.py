# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_hidden.py
# DESCRIPTION: Deteccao de processo escondido do proprio sistema.
#
#              Um rootkit de espaco de usuario nao apaga o processo: apaga a
#              resposta que as ferramentas dao sobre ele. A deteccao aqui nao
#              confia numa unica resposta, pergunta a mesma coisa por caminhos
#              independentes e trata a divergencia como o achado.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import errno

import pytest

from src.collectors import hidden
from src.core.findings import SEV_HIGH, SEV_MEDIUM


def _preparar(monkeypatch, listados, vivos):
    monkeypatch.setattr(hidden, "_tarefas_conhecidas", lambda: set(listados))
    monkeypatch.setattr(hidden, "_pid_existe", lambda pid: pid in vivos)


# ------------------------------------------------------------------------------
# DIVERGENCIA ENTRE OS DOIS CAMINHOS
# ------------------------------------------------------------------------------
def test_process_alive_but_absent_from_the_listing_is_flagged(monkeypatch):
    """
    O kernel escalona o processo e /proc nao o mostra. Nao ha configuracao
    legitima que produza esse estado.
    """
    _preparar(monkeypatch, listados=[1, 2], vivos={1, 2, 1337})
    assert hidden.find_hidden_pids(pid_max=2000) == [1337]


def test_consistent_system_produces_nothing(monkeypatch):
    """Host integro nao pode gerar alarme: o falso positivo custa a confianca."""
    _preparar(monkeypatch, listados=[1, 2, 3], vivos={1, 2, 3})
    assert hidden.find_hidden_pids(pid_max=2000) == []


def test_process_that_died_between_reads_is_not_reported(monkeypatch):
    """
    Um processo de vida curta diverge uma vez de forma legitima. Reportar isso
    encheria o laudo de ruido em qualquer host movimentado.
    """
    estados = [{1, 999}, {1}]

    monkeypatch.setattr(hidden, "_tarefas_conhecidas", lambda: {1})
    monkeypatch.setattr(hidden, "_pid_existe",
                        lambda pid: pid in (estados.pop(0) if estados else {1}))

    assert hidden.find_hidden_pids(pid_max=2000, confirmacoes=2) == []


def test_persistent_divergence_survives_confirmation(monkeypatch):
    """O que esconde continua escondido; e essa persistencia que confirma."""
    _preparar(monkeypatch, listados=[1], vivos={1, 4242})
    assert hidden.find_hidden_pids(pid_max=5000, confirmacoes=3) == [4242]


def test_confirmation_rechecks_only_the_suspects(monkeypatch):
    """
    Revarrer a faixa inteira a cada rodada multiplicaria o custo no host
    inspecionado, que e onde a ferramenta deve pesar o minimo.
    """
    consultados = []

    monkeypatch.setattr(hidden, "_tarefas_conhecidas", lambda: {1})

    def _existe(pid):
        consultados.append(pid)
        return pid in (1, 777)
    monkeypatch.setattr(hidden, "_pid_existe", _existe)

    hidden.find_hidden_pids(pid_max=1000, confirmacoes=2)
    # A primeira rodada testa os 999 PIDs que a listagem nao cobre (o PID 1 esta
    # listado e nem chega a ser consultado); a segunda re-testa so o suspeito.
    assert len(consultados) == 1000


# ------------------------------------------------------------------------------
# EXISTENCIA VIA SINAL
# ------------------------------------------------------------------------------
def test_threads_are_not_mistaken_for_hidden_processes(monkeypatch, tmp_path):
    """
    O kernel responde a sinal para uma thread, mas /proc so lista no topo o
    lider do grupo. Sem contar as threads como conhecidas, cada processo
    multithread virava uma acusacao falsa, e um host integro aparecia com
    dezenas de "processos ocultos".
    """
    raiz = tmp_path / "proc"
    (raiz / "10" / "task" / "10").mkdir(parents=True)
    (raiz / "10" / "task" / "11").mkdir()

    monkeypatch.setattr(hidden, "PROC", str(raiz))
    monkeypatch.setattr(hidden, "_pids_listados", lambda: {10})

    assert hidden._tarefas_conhecidas() == {10, 11}


def test_permission_denied_still_means_the_process_exists(monkeypatch):
    """
    Um processo de outro usuario existe mesmo sem poder ser sinalizado. Tratar
    EPERM como inexistencia deixaria passar justamente o processo privilegiado.
    """
    def _kill(pid, sig):
        raise OSError(errno.EPERM, "Operation not permitted")
    monkeypatch.setattr(hidden.os, "kill", _kill)

    assert hidden._pid_existe(4242) is True


def test_no_such_process_means_absent(monkeypatch):
    def _kill(pid, sig):
        raise OSError(errno.ESRCH, "No such process")
    monkeypatch.setattr(hidden.os, "kill", _kill)

    assert hidden._pid_existe(4242) is False


# ------------------------------------------------------------------------------
# THREADS
# ------------------------------------------------------------------------------
def test_thread_count_mismatch_is_reported(monkeypatch, tmp_path):
    """
    Esconder uma thread custa menos que esconder o processo e escapa de qualquer
    ferramenta que so conte processos.
    """
    raiz = tmp_path / "proc"
    (raiz / "10" / "task" / "10").mkdir(parents=True)
    (raiz / "10" / "status").write_text("Name:\tx\nThreads:\t4\n")

    monkeypatch.setattr(hidden, "PROC", str(raiz))
    monkeypatch.setattr(hidden, "_pids_listados", lambda: {10})

    resultado = hidden.find_hidden_threads()
    assert resultado == [{"pid": 10, "declared": 4, "listed": 1}]


def test_matching_thread_count_is_silent(monkeypatch, tmp_path):
    raiz = tmp_path / "proc"
    (raiz / "10" / "task" / "10").mkdir(parents=True)
    (raiz / "10" / "status").write_text("Threads:\t1\n")

    monkeypatch.setattr(hidden, "PROC", str(raiz))
    monkeypatch.setattr(hidden, "_pids_listados", lambda: {10})

    assert hidden.find_hidden_threads() == []


def test_process_that_vanished_mid_read_does_not_break(monkeypatch, tmp_path):
    """Ler um processo que acabou de morrer nao pode derrubar a captura."""
    monkeypatch.setattr(hidden, "PROC", str(tmp_path / "proc"))
    monkeypatch.setattr(hidden, "_pids_listados", lambda: {999})

    assert hidden.find_hidden_threads() == []


# ------------------------------------------------------------------------------
# ACHADOS
# ------------------------------------------------------------------------------
def test_hidden_pid_becomes_a_high_severity_finding(monkeypatch):
    monkeypatch.setattr(hidden, "find_hidden_pids", lambda: [1337])
    monkeypatch.setattr(hidden, "find_hidden_threads", lambda: [])
    monkeypatch.setattr(hidden, "_detalhe", lambda pid: {"pid": pid})

    achado = hidden.collect_hidden()[0]
    assert achado.severity == SEV_HIGH
    assert achado.technique == "T1014"
    assert "1337" in achado.target


def test_thread_mismatch_is_not_treated_as_certainty(monkeypatch):
    """
    Uma corrida de leitura ainda explica a divergencia de threads. Dar a ela a
    mesma gravidade de um PID oculto gastaria a atencao do analista.
    """
    monkeypatch.setattr(hidden, "find_hidden_pids", lambda: [])
    monkeypatch.setattr(hidden, "find_hidden_threads",
                        lambda: [{"pid": 5, "declared": 3, "listed": 2}])

    assert hidden.collect_hidden()[0].severity == SEV_MEDIUM


def test_finding_tells_the_analyst_to_preserve_memory_first(monkeypatch):
    """
    Matar o processo destroi a evidencia. A recomendacao existe para evitar que
    a primeira reacao apague o que se queria provar.
    """
    monkeypatch.setattr(hidden, "find_hidden_pids", lambda: [1337])
    monkeypatch.setattr(hidden, "find_hidden_threads", lambda: [])
    monkeypatch.setattr(hidden, "_detalhe", lambda pid: {"pid": pid})

    assert "memoria" in hidden.collect_hidden()[0].recommendation.lower()


def test_a_broken_scan_never_costs_the_capture(monkeypatch):
    """
    A captura inteira vale mais que este coletor. Uma falha aqui nao pode
    derrubar o que ja foi coletado.
    """
    def _explode():
        raise RuntimeError("proc indisponivel")
    monkeypatch.setattr(hidden, "find_hidden_pids", _explode)
    monkeypatch.setattr(hidden, "find_hidden_threads", lambda: [])

    assert hidden.collect_hidden() == []


def test_collector_is_wired_into_the_capture():
    """Um coletor que ninguem chama nao protege ninguem."""
    import io
    import os
    fonte = io.open(os.path.join("src", "collectors", "manager.py"),
                    encoding="utf-8").read()
    assert "collect_hidden" in fonte
