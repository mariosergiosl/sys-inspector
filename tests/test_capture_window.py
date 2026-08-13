# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_capture_window.py
# DESCRIPTION: Cada captura descreve a janela dela, nao a soma do que ja passou.
#
#              Observado em campo: um agente rodando havia horas produzia
#              capturas em que NENHUM processo desaparecia e a contagem so
#              crescia (614 -> 615 -> ...). O motor e reaproveitado entre ciclos
#              para nao recompilar os probes, mas a arvore que ele carrega nunca
#              era esvaziada, e cada ciclo apenas ACRESCENTAVA ao que ja estava
#              la.
#
#              O prejuizo e antes de tudo forense: o laudo afirmava que um
#              processo existia quando ele terminara horas antes, e a comparacao
#              entre capturas jamais acusava desaparecimento, escondendo
#              exatamente o artefato que se apaga depois de agir.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

from src.collectors.process_tree import ProcessTree


def _arvore_com(pids):
    arvore = ProcessTree()
    for pid in pids:
        arvore.add_or_update(pid, 1, "proc-%d" % pid, 0, 120)
    return arvore


def test_reset_empties_the_tree():
    arvore = _arvore_com([10, 11, 12])
    assert len(arvore.nodes) == 3

    arvore.reset()
    assert arvore.nodes == {}


def test_a_process_that_ended_does_not_survive_into_the_next_capture():
    """
    O caso que motivou a correcao: sem limpar, o processo morto reaparecia em
    todas as capturas seguintes como se ainda estivesse vivo.
    """
    arvore = _arvore_com([10, 11])
    arvore.reset()
    arvore.add_or_update(10, 1, "proc-10", 0, 120)

    assert set(arvore.nodes) == {10}


def test_reset_clears_the_incremental_counters():
    """
    Contadores que comparam com a leitura anterior nao podem atravessar a
    fronteira da captura: o delta ficaria calculado contra uma janela que nao
    existe mais.
    """
    arvore = _arvore_com([10])
    arvore.prev_udp_out = 500
    arvore.first_scan = False

    arvore.reset()
    assert arvore.prev_udp_out == 0
    assert arvore.first_scan is True


def test_boot_time_survives_the_reset():
    """
    O momento de boot descreve o HOST, nao a captura. Recalcula-lo a cada ciclo
    so introduziria imprecisao nos horarios absolutos do laudo.
    """
    arvore = _arvore_com([10])
    antes = arvore.boot_time

    arvore.reset()
    assert arvore.boot_time == antes


def test_daemon_resets_before_every_capture():
    """
    Um metodo de limpeza que ninguem chama nao corrige nada. Este teste existe
    porque o defeito original era exatamente a ausencia da chamada.
    """
    fonte = io.open(os.path.join("src", "controllers", "daemon_controller.py"),
                    encoding="utf-8").read()
    bloco = fonte.split("def collect_and_store")[1][:1200]
    assert "engine.tree.reset()" in bloco
    assert bloco.index("engine.tree.reset()") < bloco.index("engine.start()")
