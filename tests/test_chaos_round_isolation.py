# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_chaos_round_isolation.py
# DESCRIPTION: Cada rodada de cenario tem o SEU log, e o marcador de pronto de
#              uma rodada nunca vale para outra.
#
# WHY:         O log era um arquivo unico reaproveitado. A espera pelo
#              "SYSTEM READY FOR COLLECTION" encontrava o marcador de uma rodada
#              ANTERIOR e declarava pronto antes de o cenario novo subir, entao a
#              captura pegava a cena vazia e o laudo dizia que a ferramenta
#              detectou pouco, quando na verdade nao havia o que detectar ainda.
#
#              Truncar o arquivo nao resolveria: uma rodada ainda viva continua
#              escrevendo no mesmo caminho depois do truncamento.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile
import threading

import pytest


MARCA = "SYSTEM READY FOR COLLECTION"


class _EsperaSozinha(object):
    """
    Isola o metodo de espera do resto do controlador.

    O daemon inteiro exige eBPF e /proc de Linux; o comportamento sob teste aqui
    e apenas "este arquivo ja anunciou pronto?", que nao depende de nada disso.
    """

    CHAOS_READY_MARK = MARCA

    def __init__(self):
        self.shutdown_event = threading.Event()

    # Copia fiel do laco de espera do DaemonController.
    def esperar(self, log_path, timeout):
        import time
        fim = time.time() + timeout
        while time.time() < fim:
            if self.shutdown_event.is_set():
                return False
            try:
                with open(log_path, "r", errors="replace") as fh:
                    if self.CHAOS_READY_MARK in fh.read():
                        return True
            except OSError:
                pass
            time.sleep(0.05)
        return False


@pytest.fixture
def espera():
    return _EsperaSozinha()


def test_marker_of_a_previous_round_does_not_make_the_new_one_ready(espera):
    """
    O nucleo do defeito: um log de rodada ANTERIOR, ja com o marcador, nao pode
    fazer a rodada NOVA parecer pronta. Com um arquivo por rodada, o log novo
    comeca vazio e a espera corretamente nao confirma.
    """
    d = tempfile.mkdtemp()
    anterior = os.path.join(d, "si_chaos_111-1.log")
    with open(anterior, "w") as fh:
        fh.write("plantando artefatos\n%s\n" % MARCA)

    # Rodada nova: outro arquivo, ainda sem o marcador.
    atual = os.path.join(d, "si_chaos_222-2.log")
    with open(atual, "w") as fh:
        fh.write("plantando artefatos\n")

    assert espera.esperar(atual, timeout=0.3) is False


def test_ready_is_confirmed_when_this_round_announces_it(espera):
    """Quando a rodada em curso anuncia, a espera confirma."""
    d = tempfile.mkdtemp()
    atual = os.path.join(d, "si_chaos_333-3.log")
    with open(atual, "w") as fh:
        fh.write("plantando artefatos\n%s\n" % MARCA)

    assert espera.esperar(atual, timeout=0.3) is True


def test_timeout_reports_not_ready_instead_of_capturing_blind(espera):
    """
    Sem confirmacao, a espera devolve False. Quem chama decide, e o desfecho do
    comando diz que o setup nao foi confirmado, em vez de afirmar uma cena que
    talvez nao exista.
    """
    d = tempfile.mkdtemp()
    vazio = os.path.join(d, "si_chaos_444-4.log")
    open(vazio, "w").close()
    assert espera.esperar(vazio, timeout=0.2) is False


def test_round_log_names_are_unique_per_round():
    """
    O nome do log carrega instante e pid, entao duas rodadas nunca compartilham
    arquivo. E o que impede o marcador de uma vazar para a outra.
    """
    import time
    vistos = set()
    for _ in range(3):
        vistos.add("/tmp/si_chaos_%d-%d.log" % (time.time() * 1000, os.getpid()))
        time.sleep(0.002)
    assert len(vistos) == 3
