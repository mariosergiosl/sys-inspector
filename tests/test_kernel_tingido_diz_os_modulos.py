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
    linhas = a.evidence["modulos_com_a_marca"]
    esperado = ["vboxguest [O, E]", "vboxsf [O, E]"]
    assert [ln.split(";")[0] for ln in linhas] == esperado
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
    linhas = a.evidence["modulos_com_a_marca"]
    assert [ln.split(";")[0] for ln in linhas] == ["zfs [O]"]


def test_evidencia_legivel_e_nao_repr():
    """REPROVA A VERSAO ANTERIOR: lista de dicionarios saia como repr()."""
    from src.exporters.html_report import _texto_evidencia
    texto = _texto_evidencia([{"bit": 12, "flag": "O"},
                              {"bit": 13, "flag": "E"}])
    assert texto == "bit: 12, flag: O\nbit: 13, flag: E"
    assert "{" not in texto and "'" not in texto
    assert _texto_evidencia("ja e texto") == "ja e texto"
    assert _texto_evidencia(42) == "42"


def test_instante_de_carga_relativo_ao_boot(tmpdir):
    """Para a pos-analise: carregado no boot ou depois, e quando."""
    raiz = _host(tmpdir, (1 << 12), {"no_boot": "O", "depois": "O"})
    for nome, carga in (("no_boot", BOOT + 20), ("depois", BOOT + 7200)):
        _escreve(os.path.join(raiz, "sys", "module", nome, "initstate"),
                 "live\n")
        os.utime(os.path.join(raiz, "sys", "module", nome), (carga, carga))
    linhas = _achado(raiz).evidence["modulos_com_a_marca"]
    assert "carregado DEPOIS do boot" in linhas[0] and "2.0h" in linhas[0]
    assert "carregado no boot" in linhas[1] and "+20s" in linhas[1]


def _modinfo_falso(tabela):
    def _f(campo, alvo):
        return tabela.get((campo, alvo))
    return _f


def test_arquivo_do_modulo_e_o_carregado_e_conferido(tmpdir, monkeypatch):
    """REPROVA A PRIMEIRA VERSAO DESTA CORRECAO: na gwlocal o achado apontava
    o vboxguest da distribuicao (pacote do kernel), e o carregado era o de
    misc/, sem pacote. O arquivo vem do modinfo e e conferido pelo srcversion
    da memoria."""
    from src.collectors import rootkit
    raiz = str(tmpdir)
    _escreve(os.path.join(raiz, "sys", "module", "vboxguest", "srcversion"),
             "146BF037A6FCEF06C0A6A2A\n")
    misc = "/lib/modules/x/misc/vboxguest.ko"
    monkeypatch.setattr(rootkit, "_modinfo", _modinfo_falso({
        ("filename", "vboxguest"): misc,
        ("srcversion", misc): "146BF037A6FCEF06C0A6A2A"}))
    assert rootkit.arquivo_do_modulo("vboxguest", raiz) == (misc, True)


def test_arquivo_em_disco_diferente_da_memoria_e_dito(tmpdir, monkeypatch):
    """Arquivo em disco que nao e o carregado e, por si, indicio."""
    from src.collectors import rootkit
    raiz = str(tmpdir)
    _escreve(os.path.join(raiz, "sys", "module", "m", "srcversion"),
             "AAAA\n")
    monkeypatch.setattr(rootkit, "_modinfo", _modinfo_falso({
        ("filename", "m"): "/x/m.ko", ("srcversion", "/x/m.ko"): "BBBB"}))
    assert rootkit.arquivo_do_modulo("m", raiz) == ("/x/m.ko", False)


def test_descricao_completa_para_pos_analise(tmpdir, monkeypatch):
    """Arquivo, conferencia, sha256, pacote e assinatura na mesma linha."""
    from src.collectors import rootkit
    ko = os.path.join(str(tmpdir), "vboxsf.ko")
    _escreve(ko, "conteudo")
    monkeypatch.setattr(rootkit, "arquivo_do_modulo",
                        lambda nome, raiz="": (ko, True))
    monkeypatch.setattr(rootkit, "_pacote_dono", lambda c: False)
    monkeypatch.setattr(rootkit, "_modinfo", lambda campo, alvo: "")
    monkeypatch.setattr(rootkit, "_quando_carregou",
                        lambda nome, raiz="": "carregado no boot")
    linha = rootkit._descreve_modulo("vboxsf", "OE")
    assert "arquivo %s" % ko in linha
    assert "confere com o modulo na memoria" in linha
    assert "sha256 " in linha and len(linha.split("sha256 ")[1][:64]) == 64
    assert "pacote: nenhum pacote o possui" in linha
    assert "assinatura: sem assinatura" in linha
