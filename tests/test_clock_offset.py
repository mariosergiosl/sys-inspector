# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_clock_offset.py
# DESCRIPTION: Medicao do desvio de relogio do host (para a timeline entre hosts).
#
# WHY:         O evento ja carregava clock_offset e o corrected_ts ja o usava,
#              mas o agente gravava 0.0 FIXO -- e 0.0 assumido e chute, nao fato
#              (D-019). Agora o agente MEDE via chronyc e distingue medido de nao
#              medido. Doze segundos de defasagem invertem a ordem entre hosts, e
#              sequencia errada num laudo e pior que ausencia dela.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.core import clock


class _FakeProc(object):
    def __init__(self, saida):
        self._saida = saida

    def communicate(self, timeout=None):
        return (self._saida, "")

    def kill(self):
        pass


def _com_chronyc(monkeypatch, saida):
    monkeypatch.setattr(clock.shutil, "which", lambda _n: "/usr/bin/chronyc")
    monkeypatch.setattr(clock.subprocess, "Popen",
                        lambda *_a, **_k: _FakeProc(saida))


# ------------------------------------------------------------------------------
# SINAL E MEDICAO
# ------------------------------------------------------------------------------
def test_relogio_adiantado_da_offset_positivo(monkeypatch):
    """'fast of NTP time' e desvio positivo: o carimbo esta alto."""
    _com_chronyc(monkeypatch, "Reference ID : 0A\n"
                 "System time     : 0.012500000 seconds fast of NTP time\n"
                 "Last offset     : +0.000001 seconds\n")
    r = clock.measure_offset()
    assert r["measured"] is True
    assert r["source"] == "chrony"
    assert abs(r["offset"] - 0.0125) < 1e-9


def test_relogio_atrasado_da_offset_negativo(monkeypatch):
    _com_chronyc(monkeypatch,
                 "System time     : 3.500000000 seconds slow of NTP time\n")
    r = clock.measure_offset()
    assert r["measured"] is True
    assert abs(r["offset"] + 3.5) < 1e-9


def test_zero_medido_afirma_sincronia(monkeypatch):
    """0.0 MEDIDO nao e o mesmo que 0.0 assumido: measured=True."""
    _com_chronyc(monkeypatch,
                 "System time     : 0.000000000 seconds fast of NTP time\n")
    r = clock.measure_offset()
    assert r["offset"] == 0.0
    assert r["measured"] is True


# ------------------------------------------------------------------------------
# AUSENCIA DE FONTE = NAO MEDIDO (nao afirma nada)
# ------------------------------------------------------------------------------
def test_sem_chronyc_e_nao_medido(monkeypatch):
    monkeypatch.setattr(clock.shutil, "which", lambda _n: None)
    r = clock.measure_offset()
    assert r["measured"] is False
    assert r["offset"] == 0.0
    assert r["source"] == "unavailable"


def test_saida_sem_a_linha_e_nao_medido(monkeypatch):
    _com_chronyc(monkeypatch, "Reference ID : 0A\nStratum : 3\n")
    r = clock.measure_offset()
    assert r["measured"] is False


def test_timeout_do_chronyc_e_nao_medido(monkeypatch):
    monkeypatch.setattr(clock.shutil, "which", lambda _n: "/usr/bin/chronyc")

    class _Trava(object):
        def communicate(self, timeout=None):
            raise clock.subprocess.TimeoutExpired("chronyc", timeout)
        def kill(self):
            pass
    monkeypatch.setattr(clock.subprocess, "Popen", lambda *_a, **_k: _Trava())
    assert clock.measure_offset()["measured"] is False


# ------------------------------------------------------------------------------
# O OFFSET CORRIGE A ORDEM ENTRE HOSTS
# ------------------------------------------------------------------------------
def test_o_offset_medido_corrige_a_ordem_entre_hosts():
    """
    O fim pratico: dois eventos, um host adiantado 12s. Pelo carimbo bruto a
    ordem inverte; com o offset medido, corrected_ts poe na ordem certa.
    """
    from src.core.events import make_event, corrected_ts, EV_PROCESS_START

    adiantado = make_event(1012, EV_PROCESS_START, "a", clock_offset=12.0)
    normal = make_event(1005, EV_PROCESS_START, "b", clock_offset=0.0)

    assert adiantado["ts"] > normal["ts"]                  # bruto: inverte
    assert corrected_ts(adiantado) < corrected_ts(normal)  # corrigido: certo


# ------------------------------------------------------------------------------
# O BLOCO HOST DO AGENTE CARREGA O OFFSET
# ------------------------------------------------------------------------------
def test_o_host_identity_inclui_o_offset_medido():
    import inspect
    from src.core.outbox import Outbox
    fonte = inspect.getsource(Outbox._host_identity)
    assert "clock_offset" in fonte
    assert "clock_measured" in fonte
    assert "measure_offset" in fonte
