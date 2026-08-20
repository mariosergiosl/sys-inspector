# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_run_once.py
# DESCRIPTION: Guarda a flag --once do agente (C-134).
#
# WHY:         A remocao dos modos snapshot, live e local-live tirou junto o
#              primeiro uso em UMA LINHA:
#
#                  sudo sys-inspector --mode snapshot --interval 20
#
#              Sem ele, experimentar a ferramenta passaria a exigir chaves,
#              token, server_ip e dois processos. O --once devolve a linha unica
#              sem trazer de volta um segundo caminho de coleta: e o MESMO
#              agente, parando depois de um ciclo. Essa distincao e o ponto
#              inteiro da decisao, e e o que estes testes protegem -- se alguem
#              transformar o --once num caminho proprio, a divergencia que a
#              C-134 dissolveu volta pela porta dos fundos.
#
#              O defeito que o primeiro teste pega nao levanta excecao: um laco
#              que nao quebra simplesmente NAO VOLTA. Sem prazo, um teste
#              travado e indistinguivel de um teste lento.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import importlib.util
import io
import os
import threading

import pytest

# daemon_controller importa o motor, que importa BCC. Os tres testes que rodam
# o laco de verdade dependem disso; os que leem a FONTE valem em qualquer
# plataforma, e por isso a guarda e por teste e nao no modulo inteiro -- pular o
# arquivo todo no Windows esconderia as travas que nao precisam de kernel.
SEM_BCC = importlib.util.find_spec("bcc") is None
precisa_bcc = pytest.mark.skipif(SEM_BCC, reason="requer BCC (Linux com eBPF)")


def _com_prazo(segundos, funcao, *args, **kwargs):
    """Roda `funcao` numa thread e cobra que ela TERMINE dentro do prazo."""
    resultado = {}

    def alvo():
        try:
            resultado["valor"] = funcao(*args, **kwargs)
        except Exception as exc:            # pragma: no cover - so em falha
            resultado["erro"] = exc

    t = threading.Thread(target=alvo)
    t.daemon = True
    t.start()
    t.join(segundos)
    assert not t.is_alive(), (
        "run() nao retornou em %ss: o --once nao quebrou o laco, que e "
        "exatamente o defeito que este teste guarda" % segundos)
    if "erro" in resultado:
        raise resultado["erro"]
    return resultado["valor"]


class _EngineFalso(object):
    """Motor que nao toca no kernel: aqui se testa o LACO, nao a coleta."""


def _controlador(run_once, ciclos_registrados):
    """
    Monta um DaemonController REAL com as partes caras neutralizadas.

    Nao e um imitacao do controlador inteiro: e a classe de verdade, com a coleta
    e a criacao do motor trocadas. O que se afere e a unica coisa que o --once
    muda, que e QUANDO o laco termina.
    """
    from src.controllers.daemon_controller import DaemonController

    ctrl = DaemonController.__new__(DaemonController)
    ctrl.run_once = run_once
    ctrl.agent_uuid = "teste-agente"
    ctrl.shutdown_event = threading.Event()
    ctrl.interval = 0.05
    ctrl.capture_duration = 0
    ctrl.logger = __import__("logging").getLogger("TesteDaemon")
    ctrl.config = {}

    def coleta(engine, ciclo):
        ciclos_registrados.append(ciclo)
        # Sem o --once, o laco so para por fora: o proprio teste sinaliza a
        # parada depois de alguns ciclos, para nao rodar para sempre.
        if not run_once and len(ciclos_registrados) >= 3:
            ctrl.shutdown_event.set()

    ctrl.collect_and_store = coleta
    ctrl.reload_config_if_changed = lambda: None

    class _OutboxFalso(object):
        enabled = False

        def deliver_once(self):
            pass

        def check_in(self):
            return []

    ctrl.outbox = _OutboxFalso()
    ctrl._handle_commands = lambda engine, cmds: None
    return ctrl


def _roda(ctrl, monkeypatch):
    """Roda ctrl.run() com o motor eBPF substituido por um objeto inerte."""
    import src.controllers.daemon_controller as mod
    monkeypatch.setattr(mod, "SysInspectorEngine", lambda cfg: _EngineFalso())
    return _com_prazo(10, ctrl.run)


# ------------------------------------------------------------------------------
# O QUE O --once MUDA: QUANDO O LACO TERMINA
# ------------------------------------------------------------------------------
@precisa_bcc
def test_com_once_o_agente_roda_um_ciclo_e_sai(monkeypatch):
    ciclos = []
    _roda(_controlador(True, ciclos), monkeypatch)
    assert ciclos == [1], "um ciclo, e so um: %s" % ciclos


@precisa_bcc
def test_sem_once_o_agente_continua_no_laco(monkeypatch):
    """
    A contrapartida. Se o laco parasse sempre, o agente deixaria de ser agente,
    e o defeito seria muito pior que o inverso: um host que capturou uma vez e
    emudeceu parece um host saudavel.
    """
    ciclos = []
    _roda(_controlador(False, ciclos), monkeypatch)
    assert len(ciclos) >= 3, "o laco tinha que continuar: %s" % ciclos


@precisa_bcc
def test_o_once_sai_depois_da_entrega_e_nao_antes(monkeypatch):
    """
    A ordem importa numa execucao pontual COM servidor configurado: sair logo
    apos a captura deixaria a evidencia presa no banco local, e o operador
    concluiria que o agente nao entregou.
    """
    import src.controllers.daemon_controller as mod

    ordem = []
    ciclos = []
    ctrl = _controlador(True, ciclos)

    coleta_original = ctrl.collect_and_store

    def coleta(engine, ciclo):
        ordem.append("captura")
        coleta_original(engine, ciclo)

    class _OutboxQueRegistra(object):
        enabled = True

        def deliver_once(self):
            ordem.append("entrega")

        def check_in(self):
            return []

    ctrl.collect_and_store = coleta
    ctrl.outbox = _OutboxQueRegistra()

    monkeypatch.setattr(mod, "SysInspectorEngine", lambda cfg: _EngineFalso())
    _com_prazo(10, ctrl.run)

    assert ordem == ["captura", "entrega"], ordem


# ------------------------------------------------------------------------------
# O --once NAO PODE VIRAR UM CAMINHO DE COLETA PROPRIO
# ------------------------------------------------------------------------------
def test_o_once_usa_o_mesmo_collect_and_store_do_agente():
    """
    A trava contra o retorno da divergencia. A C-134 removeu tres coletas
    paralelas; se o --once ganhar rotina propria, o problema volta com outro
    nome. O codigo do laco so pode ter UMA chamada de coleta.
    """
    fonte = io.open(os.path.join("src", "controllers", "daemon_controller.py"),
                    encoding="utf-8").read()
    inicio = fonte.index("def run(self")
    # Recorta ATE O PROXIMO METODO. Ir ate o fim do arquivo pegaria a propria
    # definicao de collect_and_store e as chamadas de outros metodos, e o teste
    # passaria a medir outra coisa.
    fim = fonte.index("\n    def ", inicio + 1)
    corpo = fonte[inicio:fim]
    assert corpo.count("self.collect_and_store(") == 1, (
        "o laco do agente passou a ter mais de um caminho de coleta")


def test_a_flag_existe_na_linha_de_comando():
    """
    Cobra o argumento no parser, e nao so o parametro do controlador: uma flag
    que existe no codigo e nao na linha de comando nao devolve o primeiro uso
    em uma linha, que e a razao de ela existir.
    """
    fonte = io.open("main.py", encoding="utf-8").read()
    assert '"--once"' in fonte
    assert "run_once=args.once" in fonte


def test_os_modos_removidos_nao_voltam_pelo_parser():
    """
    Guarda da propria C-134: snapshot, live e local-live nao podem reaparecer
    como opcao aceita, nem por engano de merge.
    """
    fonte = io.open("main.py", encoding="utf-8").read()
    inicio = fonte.index('parser.add_argument("--mode"')
    trecho = fonte[inicio:inicio + 300]
    for modo in ("'snapshot'", "'live'", "'local-live'"):
        assert modo not in trecho, modo
    assert "'daemon'" in trecho and "'server'" in trecho
