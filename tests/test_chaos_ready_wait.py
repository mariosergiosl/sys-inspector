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

from src.controllers.daemon_controller import DaemonController


class _Stub(object):
    """Objeto minimo com o que _esperar_chaos_pronto usa."""
    CHAOS_READY_MARK = DaemonController.CHAOS_READY_MARK
    _esperar_chaos_pronto = DaemonController._esperar_chaos_pronto
    _log_tem_marcador = DaemonController._log_tem_marcador

    def __init__(self):
        self.shutdown_event = threading.Event()


class _ProcessoFalso(object):
    """Popen minimo: `codigo` None enquanto vivo, inteiro depois de morrer."""

    def __init__(self, codigo=None):
        self.returncode = codigo

    def poll(self):
        return self.returncode


def test_espera_ate_o_marcador_de_pronto(tmp_path):
    log = tmp_path / "chaos.log"
    log.write_text("linha 1\n>>> SYSTEM READY FOR COLLECTION (start now) <<<\n")
    stub = _Stub()
    assert stub._esperar_chaos_pronto(str(log), timeout=2) is True


def test_timeout_quando_o_marcador_nao_aparece(tmp_path):
    log = tmp_path / "chaos.log"
    log.write_text("preparando ambiente...\ninjetando rede...\n")
    stub = _Stub()
    # Sem o marcador, False no teto de tempo. Quem chama TRANSFORMA isso em
    # falha do comando: capturar uma cena que nao subiu produz uma captura de
    # aparencia normal que nega deteccao que funciona.
    assert stub._esperar_chaos_pronto(str(log), timeout=1) is False


def test_desiste_cedo_quando_o_processo_do_chaos_morre(tmp_path):
    """
    Script que morre nao vai imprimir marcador nenhum, e esperar o teto inteiro
    so atrasa a ma noticia. Este e o caso REAL de 2026-08-20: o chaos_maker
    estava com CRLF e morria no primeiro `{`, sem executar uma linha.
    """
    import time

    log = tmp_path / "chaos.log"
    log.write_text("chaos_maker.sh: line 81: syntax error near `{'\n")
    stub = _Stub()
    inicio = time.time()
    pronto = stub._esperar_chaos_pronto(str(log), timeout=30,
                                        processo=_ProcessoFalso(codigo=2))
    assert pronto is False
    assert time.time() - inicio < 5, (
        "esperou o teto inteiro por um processo que ja tinha morrido")


def test_processo_morto_com_marcador_presente_conta_como_pronto(tmp_path):
    """
    Um cenario pode montar tudo, imprimir o marcador e SO ENTAO terminar.
    Tratar "processo morreu" como falha sem reler o log reprovaria uma rodada
    boa e curta.
    """
    log = tmp_path / "chaos.log"
    log.write_text("montado\n>>> SYSTEM READY FOR COLLECTION (start now) <<<\n")
    stub = _Stub()
    assert stub._esperar_chaos_pronto(str(log), timeout=5,
                                      processo=_ProcessoFalso(codigo=0)) is True


def test_processo_vivo_sem_marcador_continua_esperando(tmp_path):
    """Processo de pe e cena por montar: nao desiste, espera o teto."""
    log = tmp_path / "chaos.log"
    log.write_text("compilando artefatos...\n")
    stub = _Stub()
    assert stub._esperar_chaos_pronto(str(log), timeout=1,
                                      processo=_ProcessoFalso(codigo=None)) is False


def test_sem_processo_o_comportamento_antigo_e_preservado(tmp_path):
    """Chamada sem o Popen (codigo antigo e testes) continua valendo."""
    log = tmp_path / "chaos.log"
    log.write_text(">>> SYSTEM READY FOR COLLECTION (start now) <<<\n")
    stub = _Stub()
    assert stub._esperar_chaos_pronto(str(log), timeout=2) is True


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
