# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_chaos_ready_wait.py
# DESCRIPTION: O comando de chaos ESPERA o cenario ficar pronto antes de capturar.
#
# WHY:         O Mario notou em campo: rodar o chaos_maker a mao e pedir a captura
#              logo depois do "SYSTEM READY FOR COLLECTION" pegava TODOS os
#              eventos, enquanto a captura automatica logo apos o comando parecia
#              nao detectar. A causa: o chaos_maker roda em background e leva
#              segundos para montar os artefatos (compila C, planta arquivos, sobe
#              processos); capturar no instante em que ele e LANCADO pega a cena
#              vazia. A captura tem que esperar o marcador de pronto.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import threading

import pytest

from src.controllers.daemon_controller import DaemonController


class _Stub(object):
    """Objeto minimo com o que _esperar_chaos_pronto usa."""
    CHAOS_READY_MARK = DaemonController.CHAOS_READY_MARK
    _esperar_chaos_pronto = DaemonController._esperar_chaos_pronto

    def __init__(self):
        self.shutdown_event = threading.Event()


def test_espera_ate_o_marcador_de_pronto(tmp_path):
    log = tmp_path / "chaos.log"
    log.write_text("linha 1\n>>> SYSTEM READY FOR COLLECTION (start now) <<<\n")
    stub = _Stub()
    assert stub._esperar_chaos_pronto(str(log), timeout=2) is True


def test_timeout_quando_o_marcador_nao_aparece(tmp_path):
    log = tmp_path / "chaos.log"
    log.write_text("preparando ambiente...\ninjetando rede...\n")
    stub = _Stub()
    # Sem o marcador, retorna False no teto de tempo (a captura ainda ocorre).
    assert stub._esperar_chaos_pronto(str(log), timeout=1) is False


def test_log_ausente_nao_quebra(tmp_path):
    stub = _Stub()
    assert stub._esperar_chaos_pronto(str(tmp_path / "nao_existe.log"),
                                      timeout=1) is False


def test_shutdown_interrompe_a_espera(tmp_path):
    log = tmp_path / "chaos.log"
    log.write_text("ainda montando\n")
    stub = _Stub()
    stub.shutdown_event.set()
    # Com shutdown pedido, nao fica preso ate o timeout.
    assert stub._esperar_chaos_pronto(str(log), timeout=30) is False


def test_o_comando_de_chaos_captura_apos_esperar():
    """
    O handler do comando chama _run_chaos (que espera o pronto) e SO ENTAO
    collect_and_store. A ordem e o que garante que a captura pega o cenario de
    pe, e nao a cena vazia.
    """
    import inspect
    fonte = inspect.getsource(DaemonController._handle_commands)
    idx_chaos = fonte.find("_run_chaos")
    idx_collect = fonte.find("collect_and_store", idx_chaos)
    assert idx_chaos != -1 and idx_collect != -1
    assert idx_chaos < idx_collect
