# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_rootkit.py
# DESCRIPTION: Guarda as cinco camadas do coletor de rootkit (C-037).
#
# WHY:         Este e o coletor cujo caminho POSITIVO nao se prova no host de
#              quem roda os testes. Provar de verdade que "um modulo escondido e
#              detectado" exigiria um modulo escondido de verdade rodando no
#              kernel da maquina de teste -- ou seja, escrever e carregar um
#              rootkit para rodar `pytest`.
#
#              A saida e a que a D-025 ja previa: caminho SINTETICO. O coletor
#              foi escrito para ler de um prefixo de caminho, entao aqui se monta
#              uma arvore /proc + /sys falsa, com a divergencia exata que um
#              rootkit produz, e se cobra o achado. O que isso prova e a LOGICA
#              da deteccao; o que ele nao prova e que o /proc real de um host
#              comprometido tem essa forma -- e para isso existe o modulo
#              didatico em tools/rootkit_demo/, exercitado pelo chaos_maker.
#
#              A outra metade do trabalho destes testes e igualmente importante:
#              um host SAUDAVEL nao pode produzir achado. Detector que grita
#              sempre deixa de ser lido, e isso e pior do que nao ter detector,
#              porque cria a impressao de cobertura.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

from src.collectors.rootkit import (collect_rootkit, modulos_em_proc,
                                    modulos_em_sysfs, modulos_em_kallsyms,
                                    taint_flags, FOLGA_DE_BOOT_S)

BOOT = 1700000000


def _escreve(caminho, conteudo):
    pasta = os.path.dirname(caminho)
    if not os.path.isdir(pasta):
        os.makedirs(pasta)
    with io.open(caminho, "w", encoding="utf-8") as fh:
        fh.write(conteudo)


def _host(tmpdir, proc_modules=None, sysfs=None, kallsyms=None, tainted=0,
          preload=None, btime=BOOT):
    """
    Monta uma arvore /proc + /sys sintetica.

    PARAMETER sysfs: dict nome -> (initstate, instante_da_carga).
    """
    raiz = str(tmpdir)
    _escreve(os.path.join(raiz, "proc", "stat"),
             "cpu 1 2 3\nbtime %d\nprocesses 100\n" % btime)
    _escreve(os.path.join(raiz, "proc", "modules"), proc_modules or "")
    _escreve(os.path.join(raiz, "proc", "kallsyms"), kallsyms or "")
    _escreve(os.path.join(raiz, "proc", "sys", "kernel", "tainted"),
             "%d\n" % tainted)
    for nome, (estado, carga) in (sysfs or {}).items():
        alvo = os.path.join(raiz, "sys", "module", nome, "initstate")
        _escreve(alvo, estado + "\n")
        os.utime(os.path.join(raiz, "sys", "module", nome), (carga, carga))
    if preload is not None:
        _escreve(os.path.join(raiz, "etc", "ld.so.preload"), preload)
    return raiz


def _linha_modulo(nome, tamanho=16384):
    return "%s %d 0 - Live 0xffffffffc0000000\n" % (nome, tamanho)


# ------------------------------------------------------------------------------
# O HOST SAUDAVEL NAO PRODUZ ACHADO
# ------------------------------------------------------------------------------
def test_host_saudavel_nao_gera_achado_nenhum(tmpdir):
    """
    A metade mais facil de esquecer. As tres fontes concordam, tudo carregou no
    boot, sem taint e sem preload: o coletor tem que ficar calado.
    """
    raiz = _host(
        tmpdir,
        proc_modules=_linha_modulo("xfs") + _linha_modulo("e1000"),
        sysfs={"xfs": ("live", BOOT + 10), "e1000": ("live", BOOT + 12)},
        kallsyms="ffffffffc0001000 t xfs_init\t[xfs]\n")
    assert collect_rootkit(raiz, agora=BOOT + 10000) == []


def test_modulo_embutido_no_kernel_nao_conta_como_divergencia(tmpdir):
    """
    Regressao contra o detector que grita sempre.

    /sys/module lista tambem os modulos COMPILADOS DENTRO do kernel, que existem
    ali so para expor parametros e nunca aparecem em /proc/modules. Sem o filtro
    por `initstate`, um host saudavel produziria dezenas de "modulos escondidos"
    e o achado real ficaria enterrado no meio deles.
    """
    raiz = _host(tmpdir, proc_modules=_linha_modulo("xfs"),
                 sysfs={"xfs": ("live", BOOT + 10)})
    # kvm sem initstate: embutido, e nao deve virar achado.
    _escreve(os.path.join(raiz, "sys", "module", "kvm", "parameters", "nested"),
             "Y\n")
    assert collect_rootkit(raiz, agora=BOOT + 10000) == []


# ------------------------------------------------------------------------------
# S5: A DIVERGENCIA (o indicio mais forte)
# ------------------------------------------------------------------------------
def test_modulo_que_sumiu_da_lista_mas_esta_no_sysfs_e_denunciado(tmpdir):
    """
    O caso classico: o rootkit se remove de /proc/modules (a lista que o
    administrador ve com lsmod) e esquece, ou nao consegue, remover o objeto
    correspondente em /sys/module.
    """
    raiz = _host(tmpdir, proc_modules=_linha_modulo("xfs"),
                 sysfs={"xfs": ("live", BOOT + 10),
                        "diamorphine": ("live", BOOT + 20)})
    achados = collect_rootkit(raiz, agora=BOOT + 10000)
    titulos = [a.title for a in achados]
    assert any("diamorphine" in t and "ausente da lista" in t for t in titulos), titulos
    escondido = [a for a in achados if "diamorphine" in a.title][0]
    assert escondido.severity == "Critical"
    assert escondido.technique == "T1014"


def test_simbolo_orfao_no_kallsyms_tambem_denuncia(tmpdir):
    """
    A segunda via da mesma deteccao, e a que pega o rootkit mais caprichado:
    ele se remove das DUAS listas de modulos, mas os simbolos dele continuam na
    tabela do kernel, porque apaga-los quebraria o proprio codigo.
    """
    raiz = _host(
        tmpdir,
        proc_modules=_linha_modulo("xfs"),
        sysfs={"xfs": ("live", BOOT + 10)},
        kallsyms=("ffffffffc0001000 t xfs_init\t[xfs]\n"
                  "ffffffffc0009000 t hook_getdents\t[oculto]\n"))
    achados = collect_rootkit(raiz, agora=BOOT + 10000)
    assert any("oculto" in a.title for a in achados), [a.title for a in achados]


def test_divergencia_traz_encaminhamento_a_bancada(tmpdir):
    """
    D-028/C-044: no nivel do kernel a ferramenta chega ao limite dela, e e
    justamente por isso que o encaminhamento tem que estar la. Um achado que
    conclui "o kernel mente" e nao diz quem resolve deixa o operador parado.
    """
    raiz = _host(tmpdir, proc_modules="",
                 sysfs={"diamorphine": ("live", BOOT + 20)})
    achados = collect_rootkit(raiz, agora=BOOT + 10000)
    escondido = [a for a in achados if "diamorphine" in a.title][0]
    assert escondido.referral.get("analysis")
    assert escondido.referral.get("reason")
    assert "diamorphine" in escondido.referral.get("object", "")


def test_o_achado_avisa_que_o_proprio_agente_deixa_de_ser_confiavel(tmpdir):
    """
    Ressalva pericial que nao pode faltar: se o kernel esta comprometido, TODAS
    as respostas deste host sao suspeitas, inclusive as desta ferramenta, que
    tambem pergunta ao mesmo kernel. Omitir isso seria a ferramenta se creditar
    uma confianca que ela nao tem naquele host.
    """
    raiz = _host(tmpdir, proc_modules="",
                 sysfs={"rk": ("live", BOOT + 20)})
    achado = [a for a in collect_rootkit(raiz, agora=BOOT + 10000)
              if "rk" in a.title][0]
    assert "desta ferramenta" in achado.recommendation


# ------------------------------------------------------------------------------
# S1: CARGA FORA DO BOOT
# ------------------------------------------------------------------------------
def test_modulo_carregado_fora_do_boot_aparece(tmpdir):
    raiz = _host(tmpdir,
                 proc_modules=_linha_modulo("xfs") + _linha_modulo("tarde"),
                 sysfs={"xfs": ("live", BOOT + 10),
                        "tarde": ("live", BOOT + 90000)})
    achados = collect_rootkit(raiz, agora=BOOT + 100000)
    fora = [a for a in achados if "fora do boot" in a.title]
    assert len(fora) == 1
    assert "tarde" in fora[0].title
    assert fora[0].evidence["seconds_after_boot"] == 90000


def test_carga_dentro_da_folga_de_boot_nao_e_achado(tmpdir):
    """
    A inicializacao nao termina no segundo zero: udev e systemd seguem
    carregando modulo depois. Sem a folga, todo host produziria achado a cada
    boot, que e o mesmo que nao produzir nenhum.
    """
    raiz = _host(tmpdir,
                 proc_modules=_linha_modulo("xfs"),
                 sysfs={"xfs": ("live", BOOT + FOLGA_DE_BOOT_S - 1)})
    assert [a for a in collect_rootkit(raiz, agora=BOOT + 99999)
            if "fora do boot" in a.title] == []


# ------------------------------------------------------------------------------
# S3: SEQUESTRO NO ESPACO DE USUARIO
# ------------------------------------------------------------------------------
def test_ld_so_preload_com_biblioteca_vira_achado(tmpdir):
    raiz = _host(tmpdir, proc_modules=_linha_modulo("xfs"),
                 sysfs={"xfs": ("live", BOOT + 10)},
                 preload="/usr/local/lib/libchaos.so\n")
    achados = [a for a in collect_rootkit(raiz, agora=BOOT + 10000)
               if a.technique == "T1574.006"]
    assert len(achados) == 1
    assert "libchaos.so" in achados[0].target


def test_preload_vazio_ou_so_comentario_nao_acusa_nada(tmpdir):
    """Arquivo existente e vazio e comum apos limpeza; nao e indicio."""
    raiz = _host(tmpdir, proc_modules="", sysfs={}, preload="# nada aqui\n")
    assert [a for a in collect_rootkit(raiz, agora=BOOT + 10) if a.technique
            == "T1574.006"] == []


def test_preload_apontando_para_arquivo_inexistente_sobe_a_confianca(tmpdir):
    """
    Preload apontando para arquivo que nao existe e, na pratica, resto de
    limpeza malfeita: o fato e verificavel (o arquivo REALMENTE nao esta la),
    entao o achado vira confirmado em vez de provavel.
    """
    raiz = _host(tmpdir, proc_modules="", sysfs={},
                 preload="/tmp/sumiu.so\n")
    achado = [a for a in collect_rootkit(raiz, agora=BOOT + 10)
              if a.technique == "T1574.006"][0]
    assert achado.confidence == "confirmed"
    assert achado.evidence["library_exists"] is False


# ------------------------------------------------------------------------------
# S4: TAINT DO KERNEL
# ------------------------------------------------------------------------------
def test_modulo_nao_assinado_tinge_o_kernel_e_vira_achado(tmpdir):
    raiz = _host(tmpdir, proc_modules="", sysfs={}, tainted=(1 << 13))
    achados = [a for a in collect_rootkit(raiz, agora=BOOT + 10)
               if "tingido" in a.title]
    assert len(achados) == 1
    assert achados[0].severity == "High"


def test_taint_apenas_proprietario_nao_gera_achado(tmpdir):
    """
    O bit de driver proprietario sobe em qualquer host com nvidia ou
    VirtualBox. Trata-lo como indicio faria a ferramenta acusar metade das
    estacoes de trabalho do mundo.
    """
    raiz = _host(tmpdir, proc_modules="", sysfs={}, tainted=(1 << 0))
    assert [a for a in collect_rootkit(raiz, agora=BOOT + 10)
            if "tingido" in a.title] == []


def test_taint_cumulativo_e_declarado_como_tal(tmpdir):
    """
    O que so esta camada enxerga: um modulo que entrou, fez o que veio fazer e
    saiu nao aparece em lista de modulos nenhuma, mas o bit de taint fica.
    """
    raiz = _host(tmpdir, proc_modules="", sysfs={},
                 tainted=(1 << 12) | (1 << 13))
    achado = [a for a in collect_rootkit(raiz, agora=BOOT + 10)
              if "tingido" in a.title][0]
    assert "CUMULATIVO" in achado.description
    assert len(achado.evidence["taint_bits"]) == 2


# ------------------------------------------------------------------------------
# AS FONTES, ISOLADAS
# ------------------------------------------------------------------------------
def test_as_tres_fontes_leem_o_que_deveriam(tmpdir):
    raiz = _host(tmpdir,
                 proc_modules=_linha_modulo("xfs", 999424),
                 sysfs={"xfs": ("live", BOOT + 10)},
                 kallsyms="ffffffffc0001000 t xfs_init\t[xfs]\n")
    assert modulos_em_proc(raiz)["xfs"]["size"] == 999424
    assert modulos_em_sysfs(raiz)["xfs"]["initstate"] == "live"
    assert modulos_em_kallsyms(raiz) == {"xfs"}
    assert taint_flags(raiz) == []


def test_fonte_ausente_devolve_vazio_em_vez_de_explodir(tmpdir):
    """
    Kernel sem /proc/kallsyms legivel (kptr_restrict) e caso real. Tem que
    reduzir a cobertura, nunca derrubar a captura inteira.
    """
    raiz = str(tmpdir)
    assert modulos_em_proc(raiz) == {}
    assert modulos_em_sysfs(raiz) == {}
    assert modulos_em_kallsyms(raiz) == set()
    assert taint_flags(raiz) == []
    assert collect_rootkit(raiz, agora=BOOT) == []
