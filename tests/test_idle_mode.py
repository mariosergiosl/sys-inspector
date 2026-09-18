# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_idle_mode.py
# DESCRIPTION: O modo ocioso do agente (C-105): a captura pesada deixa de ser
#              obrigatoria em todo ciclo e passa a acontecer por motivo.
#
# WHY:         Ate a v1.2.0 o daemon nao era ocioso coisa nenhuma. Rodava
#              collect_and_store (eBPF, inventario, achados, cifra) a TODO
#              ciclo e so depois falava com o servidor. Num parque real isso e
#              pagar o custo da pericia o tempo inteiro em maquinas onde nada
#              aconteceu.
#
# O QUE PROVA: a decisao de capturar, que e o coracao do item, sem subir eBPF.
#              A funcao que decide e pura: olha configuracao e relogio, e
#              devolve o motivo ou None. Testa-la isolada e o que permite cobrir
#              o caso ruim (o agente que NAO captura) sem um kernel por perto.
#
#              O caso ruim e o que importa aqui. Um agente que captura de menos
#              nao levanta alarme nenhum: ele simplesmente fica quieto, e quieto
#              e exatamente o que se espera dele. Por isso cada caso abaixo
#              confere tambem que a AUSENCIA de captura vem acompanhada da
#              explicacao (D-020).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import time

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fonte(caminho):
    """Le um arquivo do projeto como texto, tolerando byte estranho."""
    with io.open(os.path.join(RAIZ, caminho), encoding="utf-8",
                 errors="replace") as fh:
        return fh.read()


def _agente(idle_mode=True, capture_every=3600, ultima=None):
    """
    Um portador com o minimo que a decisao usa, sem construir o controlador.

    O DaemonController real carrega chave publica, abre banco e instancia a
    outbox no __init__. Nada disso participa da decisao de capturar, e exigir
    tudo isso tornaria o teste dependente do laboratorio justamente no ponto que
    precisa ser barato de exercitar.
    """
    mod = pytest.importorskip(
        "src.controllers.daemon_controller",
        reason="o controlador importa o coletor, que exige pwd (Linux)")

    class _Portador(object):
        _motivo_para_capturar = mod.DaemonController._motivo_para_capturar
        _porque_nao_capturou = mod.DaemonController._porque_nao_capturou

    portador = _Portador()
    portador.idle_mode = idle_mode
    portador.capture_every = capture_every
    portador._ultima_captura = ultima
    return portador


# ==============================================================================
# O PADRAO NAO MUDA PARA QUEM NAO PEDIU
# ==============================================================================

def test_com_o_modo_desligado_captura_em_todo_ciclo():
    """
    PERDA DE FUNCIONALIDADE que este item nao pode causar. Com idle_mode
    desligado, que e o padrao, o comportamento e exatamente o de antes: captura
    a todo ciclo, sempre.
    """
    agente = _agente(idle_mode=False, ultima=time.time())
    assert agente._motivo_para_capturar() == "mode-off"


def test_o_modo_nasce_desligado_na_configuracao():
    """
    Ligar muda o que um agente em campo faz. Isso e decisao de quem opera, e
    nao efeito colateral de atualizar a ferramenta, pelo mesmo criterio ja
    aplicado a aquisicao dirigida.
    """
    cfg = _fonte("conf/config.yaml")
    assert "idle_mode: false" in cfg, (
        "o modo ocioso passou a nascer LIGADO na configuracao (C-105)")


def test_o_padrao_do_codigo_tambem_e_desligado():
    """
    Uma configuracao antiga, sem a chave nova, nao pode herdar o modo ligado. O
    agente que ninguem tocou tem que continuar se comportando como antes.
    """
    src = _fonte("src/controllers/daemon_controller.py")
    assert "get('idle_mode', False)" in src, (
        "o padrao do modo ocioso deixou de ser desligado no codigo (C-105)")


# ==============================================================================
# QUANDO A CAPTURA ACONTECE
# ==============================================================================

def test_a_primeira_captura_sai_no_primeiro_ciclo():
    """
    Sem isto, um agente recem instalado ficaria invisivel no painel ate a
    primeira cadencia vencer, e quem instalou concluiria que a instalacao
    falhou. "Nunca capturou" e diferente de "faz muito tempo".
    """
    assert _agente(ultima=None)._motivo_para_capturar() == "first"


def test_a_cadencia_vencida_dispara_a_captura():
    """E o que mantem a serie historica viva num host onde nada acontece."""
    agente = _agente(capture_every=60, ultima=time.time() - 61)
    assert agente._motivo_para_capturar() == "schedule"


def test_a_cadencia_no_limite_exato_dispara():
    """
    O limite e inclusivo. Um ciclo que cai exatamente sobre a cadencia tem que
    capturar, senao a captura escorrega um ciclo inteiro a cada volta e a serie
    desliza para tras sem ninguem perceber.
    """
    agente = _agente(capture_every=60, ultima=time.time() - 60)
    assert agente._motivo_para_capturar() == "schedule"


def test_dentro_da_cadencia_nao_captura():
    """
    REPROVA A VERSAO COM DEFEITO: antes do C-105 nao havia decisao nenhuma, a
    captura pesada rodava em todo ciclo.
    """
    agente = _agente(capture_every=3600, ultima=time.time() - 10)
    assert agente._motivo_para_capturar() is None


def test_cadencia_zero_deixa_a_captura_so_por_comando():
    """
    CENARIO DECLARADO: com capture_every=0 o agente so captura quando o
    analista pede. E uma escolha legitima para um parque grande, e precisa
    funcionar sem virar "nunca mais captura" por acidente.
    """
    agente = _agente(capture_every=0, ultima=time.time())
    assert agente._motivo_para_capturar() is None


# ==============================================================================
# O AGENTE QUE NAO CAPTURA PRECISA DIZER POR QUE
# ==============================================================================

def test_ciclo_sem_captura_explica_quanto_falta():
    """
    D-020 aplicada ao log. Um agente ocioso que nao registra nada e
    indistinguivel de um agente travado, e quem olha o log as tres da manha nao
    tem como saber a diferenca.
    """
    agente = _agente(capture_every=600, ultima=time.time() - 100)
    frase = agente._porque_nao_capturou()
    assert "proxima captura" in frase
    assert "600" in frase, "a frase nao diz qual e a cadencia configurada"


def test_a_conta_do_tempo_que_falta_nunca_e_negativa():
    """
    CENARIO ADVERSO: o relogio do host pode andar para tras, e um agente
    dizendo que a proxima captura sai em menos vinte segundos e pior que um
    agente calado, porque parece defeito onde ha so relogio.
    """
    agente = _agente(capture_every=60, ultima=time.time() - 9999)
    assert "-" not in agente._porque_nao_capturou()


def test_cadencia_desligada_diz_que_esta_desligada():
    """
    "Nunca vai capturar sozinho" e uma informacao importante demais para ficar
    implicita num numero.
    """
    frase = _agente(capture_every=0, ultima=time.time())._porque_nao_capturou()
    assert "cadencia desligada" in frase
    assert "comando do analista" in frase


def test_o_laco_registra_a_ausencia_de_captura():
    """
    Existir a frase nao basta: o laco tem que escreve-la.
    """
    src = _fonte("src/controllers/daemon_controller.py")
    assert "self._porque_nao_capturou()" in src, (
        "o laco parou de registrar por que nao capturou (C-105)")
    assert "[IDLE]" in src


# ==============================================================================
# COLISAO COM O QUE JA EXISTIA
# ==============================================================================

def test_a_captura_sob_demanda_reinicia_a_cadencia():
    """
    COLISAO com o comando do analista: sem reiniciar a cadencia, uma captura
    pedida seria seguida, segundos depois, de outra por agendamento. Duas
    capturas quase identicas na serie, e o custo que o modo existe para evitar
    pago em dobro justo quando alguem esta olhando.
    """
    src = _fonte("src/controllers/daemon_controller.py")
    inicio = src.index("if nome == CMD_COLLECT:")
    bloco = src[inicio:inicio + 900]
    assert "self._ultima_captura = time.time()" in bloco, (
        "a captura sob demanda nao reinicia mais a cadencia (C-105)")


def test_a_captura_de_cenario_tambem_reinicia_a_cadencia():
    """Mesma razao, pelo caminho do cenario de caos."""
    src = _fonte("src/controllers/daemon_controller.py")
    inicio = src.index("elif nome == CMD_CHAOS_COLLECT:")
    bloco = src[inicio:inicio + 900]
    assert "self._ultima_captura = time.time()" in bloco


def test_o_ciclo_unico_captura_mesmo_com_o_modo_ligado():
    """
    COLISAO com --once: uma execucao pontual tem que capturar, e com o modo
    ligado ela cai no caso "first", porque nunca houve captura nesta execucao.
    Se este caso quebrar, `--mode daemon --once` vira um comando que nao faz
    nada, o que e a pior falha possivel para um uso pontual.
    """
    assert _agente(idle_mode=True, ultima=None)._motivo_para_capturar() == "first"


def test_o_laco_so_marca_a_captura_quando_ela_ocorreu():
    """
    O carimbo de ultima captura entra DEPOIS de collect_and_store, e nao antes.
    Marcando antes, uma captura que falhasse adiaria a proxima pela cadencia
    inteira, e o agente passaria uma hora sem capturar por causa de um erro que
    durou um segundo.
    """
    src = _fonte("src/controllers/daemon_controller.py")
    inicio = src.index("motivo = self._motivo_para_capturar()")
    bloco = src[inicio:inicio + 700]
    pos_coleta = bloco.index("self.collect_and_store(engine, cycle_count)")
    pos_marca = bloco.index("self._ultima_captura = time.time()")
    assert pos_coleta < pos_marca, (
        "o carimbo da ultima captura passou para ANTES da captura (C-105)")
