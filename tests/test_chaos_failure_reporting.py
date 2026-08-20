# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_chaos_failure_reporting.py
# DESCRIPTION: Cenario que nao sobe FALHA o comando, em vez de virar captura.
#
# WHY:         2026-08-20, achado em campo. O chaos_maker.sh chegou na VM com
#              CRLF e morreu no primeiro `{`, sem executar uma linha. O daemon
#              nunca conferia se o processo continuava vivo: esperava o teto de
#              tempo, respondia "setup nao confirmado (capturando mesmo assim)"
#              e capturava. O resultado era uma captura de aparencia normal, com
#              nada detectado, e a leitura obvia disso e "a ferramenta nao
#              detecta" -- quando a verdade e que a cena nunca existiu.
#
#              Capturar o nada e PIOR que nao capturar: nega deteccao que
#              funciona, e desmente a regua (D-025). Por isso o desfecho correto
#              e falhar alto, dizendo por que.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import subprocess
import threading

import pytest

from src.controllers.daemon_controller import DaemonController


class _ProcessoMorto(object):
    """Popen de um script que ja terminou."""

    def __init__(self, codigo=2):
        self.returncode = codigo

    def poll(self):
        return self.returncode


class _ProcessoVivo(object):
    """Popen de um script que segue rodando e nunca confirma nada."""

    returncode = None

    def poll(self):
        return None


class _Daemon(object):
    """Minimo de DaemonController para exercitar _run_chaos."""

    CHAOS_READY_MARK = DaemonController.CHAOS_READY_MARK
    CHAOS_SETUP_TIMEOUT = 2
    CHAOS_LOGS_MANTIDOS = DaemonController.CHAOS_LOGS_MANTIDOS
    _run_chaos = DaemonController._run_chaos
    _esperar_chaos_pronto = DaemonController._esperar_chaos_pronto
    _log_tem_marcador = DaemonController._log_tem_marcador
    # staticmethod: sem reembrulhar, copiar a funcao para a classe do stub a
    # transforma em metodo de instancia, e `self` entraria como o caminho do log.
    _final_do_log = staticmethod(DaemonController._final_do_log)

    def __init__(self):
        self.shutdown_event = threading.Event()

    def _limpar_logs_de_chaos_antigos(self):
        pass


def _popen_falso(saida, processo):
    """
    Substitui o Popen: escreve `saida` no log que o daemon abriu e devolve
    `processo`. Nao roda o chaos_maker de verdade -- este teste e sobre o
    DESFECHO do comando, e plantar artefato no host que roda os testes seria
    justamente o que a ferramenta promete nunca fazer.
    """
    def _fabrica(args, stdout=None, stderr=None, start_new_session=None,
                 env=None):
        if stdout is not None:
            stdout.write(saida)
            stdout.flush()
        return processo
    return _fabrica


def test_script_que_morre_faz_o_comando_falhar(monkeypatch):
    """O caso real: erro de sintaxe, processo morto, nenhum marcador."""
    daemon = _Daemon()
    erro = ("chaos_maker.sh: line 81: syntax error near unexpected token "
            "`$'{\\r''\n")
    monkeypatch.setattr(subprocess, "Popen",
                        _popen_falso(erro, _ProcessoMorto(codigo=2)))

    with pytest.raises(RuntimeError) as exc:
        daemon._run_chaos({"duration": 30})

    msg = str(exc.value)
    assert "codigo 2" in msg, "a mensagem nao diz com que codigo o script morreu"
    assert "nao vale" in msg, (
        "a mensagem precisa dizer que a CAPTURA nao vale: sem isso o operador "
        "le a captura vazia como ausencia de ameaca")


def test_a_falha_carrega_o_final_do_log(monkeypatch):
    """
    O erro tem que DIZER o motivo. Sem o log na mensagem, o operador recebe
    "o cenario nao subiu" e precisa entrar no host para descobrir por que.
    """
    daemon = _Daemon()
    monkeypatch.setattr(
        subprocess, "Popen",
        _popen_falso("bash: linha 81: syntax error near `{'\n",
                     _ProcessoMorto(codigo=2)))

    with pytest.raises(RuntimeError) as exc:
        daemon._run_chaos({"duration": 30})

    assert "syntax error" in str(exc.value), (
        "o erro do script nao chegou na mensagem do comando")


def test_processo_vivo_sem_confirmar_tambem_falha(monkeypatch):
    """
    Cenario pela metade e tao ruim quanto cenario nenhum: o laudo mediria uma
    cena incompleta e o numero sairia errado para menos, sem ninguem saber.
    """
    daemon = _Daemon()
    monkeypatch.setattr(subprocess, "Popen",
                        _popen_falso("compilando...\n", _ProcessoVivo()))

    with pytest.raises(RuntimeError) as exc:
        daemon._run_chaos({"duration": 30})

    assert "segue rodando" in str(exc.value)


def test_cenario_que_sobe_devolve_sucesso(monkeypatch):
    """A contraprova: com o marcador no log, o comando conclui normalmente."""
    daemon = _Daemon()
    saida = "montando\n%s\n" % DaemonController.CHAOS_READY_MARK
    monkeypatch.setattr(subprocess, "Popen",
                        _popen_falso(saida, _ProcessoVivo()))

    resultado = daemon._run_chaos({"duration": 30})
    assert "pronto para captura" in resultado
    assert "log /tmp/si_chaos_" in resultado


def test_marcador_impresso_e_processo_encerrado_ainda_e_sucesso(monkeypatch):
    """
    Rodada curta e valida: monta tudo, imprime o marcador, termina. Tratar
    "processo morreu" como falha sem reler o log reprovaria uma rodada boa.
    """
    daemon = _Daemon()
    saida = "%s\n" % DaemonController.CHAOS_READY_MARK
    monkeypatch.setattr(subprocess, "Popen",
                        _popen_falso(saida, _ProcessoMorto(codigo=0)))

    assert "pronto para captura" in daemon._run_chaos({"duration": 30})


def test_final_do_log_sem_arquivo():
    assert "ilegivel" in DaemonController._final_do_log("/nao/existe/x.log")


def test_final_do_log_vazio(tmp_path):
    log = tmp_path / "vazio.log"
    log.write_text("")
    assert "vazio" in DaemonController._final_do_log(str(log))


def test_final_do_log_traz_o_fim_e_nao_o_comeco(tmp_path):
    """
    O erro fica no FIM do log. Truncar pelo comeco entregaria o cabecalho do
    script e esconderia exatamente a linha que interessa.
    """
    log = tmp_path / "grande.log"
    log.write_text("inicio\n" + ("ruido\n" * 500) + "ERRO FINAL AQUI\n")
    rabo = DaemonController._final_do_log(str(log), limite=100)
    assert "ERRO FINAL AQUI" in rabo
    assert "inicio" not in rabo


def test_run_chaos_falha_explicito_se_o_script_nao_existe(monkeypatch):
    """Script ausente ja falhava alto; garantir que continua falhando."""
    daemon = _Daemon()
    monkeypatch.setattr(os.path, "exists", lambda p: False)

    with pytest.raises(RuntimeError) as exc:
        daemon._run_chaos({"duration": 30})
    assert "not installed" in str(exc.value)
