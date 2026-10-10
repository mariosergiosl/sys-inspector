# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_kernel_tingido_diz_os_modulos.py
# DESCRIPTION: Trava o achado "Kernel tingido" dizendo QUAIS modulos levam a
#              marca (F-267), e a evidencia legivel em todo achado.
#
# WHY:         O Mario em 2026-10-10, olhando o achado na .161: "como isso foi
#              identificado? nao existe nenhum processo atrelado? ... parece que
#              ele nao da muita informacao para a investigacao posterior". O
#              achado lia so /proc/sys/kernel/tainted e mandava o analista
#              "levantar quais modulos" a mao, quando o kernel diz, modulo a
#              modulo, em /sys/module/<nome>/taint. Medido: vboxguest e vboxsf,
#              "OE", fora de qualquer pacote. E a evidencia aparecia como
#              repr() do Python.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

from src.collectors.rootkit import collect_rootkit, modulos_tingidos

BOOT = 1700000000


def _escreve(caminho, conteudo):
    pasta = os.path.dirname(caminho)
    if not os.path.isdir(pasta):
        os.makedirs(pasta)
    with io.open(caminho, "w", encoding="utf-8") as fh:
        fh.write(conteudo)


def _host(tmpdir, tainted, taint_por_modulo):
    """Arvore sintetica: o numero global e a marca de cada modulo."""
    raiz = str(tmpdir)
    _escreve(os.path.join(raiz, "proc", "stat"), "btime %d\n" % BOOT)
    _escreve(os.path.join(raiz, "proc", "modules"), "")
    _escreve(os.path.join(raiz, "proc", "kallsyms"), "")
    _escreve(os.path.join(raiz, "proc", "sys", "kernel", "tainted"),
             "%d\n" % tainted)
    for nome, letras in taint_por_modulo.items():
        _escreve(os.path.join(raiz, "sys", "module", nome, "taint"),
                 letras + "\n")
    return raiz


def _achado(raiz):
    return [a for a in collect_rootkit(raiz, agora=BOOT + 10)
            if "tingido" in a.title][0]


def test_le_a_marca_de_cada_modulo(tmpdir):
    """Forma medida na .161: 'OEn' nos dois modulos do VirtualBox, vazio nos
    demais (e o 'n', que esta analise nao interpreta, fica de fora)."""
    raiz = _host(tmpdir, (1 << 12) | (1 << 13),
                 {"vboxguest": "OEn", "vboxsf": "OEn", "efi_pstore": "n",
                  "ext4": ""})
    assert modulos_tingidos(raiz) == [("vboxguest", "OE"), ("vboxsf", "OE")]


def test_o_achado_nomeia_os_modulos(tmpdir):
    """REPROVA A VERSAO ANTERIOR: o achado nao dizia modulo nenhum."""
    raiz = _host(tmpdir, (1 << 12) | (1 << 13),
                 {"vboxguest": "OEn", "vboxsf": "OEn"})
    a = _achado(raiz)
    assert "vboxguest, vboxsf" in a.description
    assert a.evidence["modulos_com_a_marca"] == ["vboxguest [O, E]",
                                                 "vboxsf [O, E]"]
    assert "Confirmar a procedencia de vboxguest, vboxsf" in a.recommendation


def test_marca_sem_modulo_carregado_diz_que_o_responsavel_saiu(tmpdir):
    """O caso mais grave: a marca existe e nenhum modulo carregado a tem."""
    raiz = _host(tmpdir, (1 << 13), {"ext4": "", "xfs": ""})
    a = _achado(raiz)
    assert "NENHUM modulo carregado agora leva essa marca" in a.description
    assert "journalctl -k" in a.recommendation
    assert a.evidence["modulos_com_a_marca"] == [
        "nenhum modulo carregado agora leva a marca"]


def test_modulo_com_outra_marca_nao_e_apontado(tmpdir):
    """So entra quem leva uma das marcas que acenderam o achado."""
    raiz = _host(tmpdir, (1 << 12), {"nvidia": "P", "zfs": "O"})
    a = _achado(raiz)
    assert a.evidence["modulos_com_a_marca"] == ["zfs [O]"]


def test_evidencia_legivel_e_nao_repr():
    """REPROVA A VERSAO ANTERIOR: lista de dicionarios saia como repr()."""
    from src.exporters.html_report import _texto_evidencia
    texto = _texto_evidencia([{"bit": 12, "flag": "O"},
                              {"bit": 13, "flag": "E"}])
    assert texto == "bit: 12, flag: O\nbit: 13, flag: E"
    assert "{" not in texto and "'" not in texto
    assert _texto_evidencia("ja e texto") == "ja e texto"
    assert _texto_evidencia(42) == "42"
