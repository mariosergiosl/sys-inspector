# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_exe_provenance.py
# DESCRIPTION: Testa a proveniencia do executavel e a cadeia de ancestrais no
#              painel de detalhe.
#
#              Regressao real: a deteccao de binario apagado procurava
#              "(deleted)" na LINHA DE COMANDO, onde esse sufixo nunca aparece;
#              ele vem do alvo do link /proc/PID/exe. A tag DELETED existia no
#              codigo mas nunca era produzida.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import time

from src.exporters.html_report import (_render_exe_provenance, _render_ancestry,
                                       _fmt_epoch)
from src.collectors.process_tree import ProcessTree, ProcessNode


def _node(pid=100, ppid=1, cmd="proc"):
    return ProcessNode(pid, ppid, cmd, 0)


# ------------------------------------------------------------------------------
# Proveniencia do executavel
# ------------------------------------------------------------------------------
def test_block_still_shows_when_exe_is_unknown():
    """
    [2026-08-20] Premissa INVERTIDA por decisao do Mario: "mesmo nao tendo
    informacao, tudo tem que ficar visivel sempre". Um processo de kernel nao
    tem binario em disco, e isso e uma RESPOSTA. Omitir o bloco deixava o
    analista sem saber se o processo nao tem executavel ou se a ferramenta nao
    conseguiu ler o caminho, que sao coisas diferentes num laudo (D-020).
    """
    node = ProcessNode(1, 0, "kthreadd", 0)
    node.exe_path = ""
    html = _render_exe_provenance(node)
    assert "Executable Provenance" in html, "o bloco sumiu de novo (D-020)"
    assert "sem binario em disco" in html, (
        "o bloco aparece mas nao diz POR QUE esta vazio")


def test_shows_path_and_mac_times():
    """Caminho, tamanho e MAC times aparecem para sustentar a analise temporal."""
    n = _node()
    n.exe_path = "/usr/bin/sshd"
    n.exe_size = 900000
    n.exe_mtime = time.time()
    html = _render_exe_provenance(n)
    assert "/usr/bin/sshd" in html
    assert "Modified (mtime)" in html
    assert "Changed (ctime)" in html
    assert "Accessed (atime)" in html


def test_deleted_binary_is_flagged():
    """Binario apagado em execucao recebe destaque explicito (anti-forense)."""
    n = _node()
    n.exe_path = "/tmp/implant"
    n.exe_deleted = True
    html = _render_exe_provenance(n)
    assert "DELETED FROM DISK" in html


def test_fileless_execution_is_flagged():
    """Execucao apenas em memoria (memfd) e sinalizada."""
    n = _node()
    n.exe_path = "/memfd:payload"
    n.exe_memfd = True
    html = _render_exe_provenance(n)
    assert "FILELESS" in html


def test_exe_path_is_escaped():
    """O caminho vem do host analisado e nao pode injetar marcacao."""
    n = _node()
    n.exe_path = "/tmp/<script>alert(1)</script>"
    html = _render_exe_provenance(n)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_epoch_formatting_handles_missing_values():
    """Timestamp ausente ou invalido nao quebra o laudo."""
    assert _fmt_epoch(0) == "-"
    assert _fmt_epoch(None) == "-"
    assert _fmt_epoch("abc") == "-"
    assert "20" in _fmt_epoch(time.time())


# ------------------------------------------------------------------------------
# Cadeia de ancestrais
# ------------------------------------------------------------------------------
def _tree_with_chain():
    """systemd -> cron -> bash -> implant, uma cadeia tipica de intrusao."""
    tree = ProcessTree()
    for pid, ppid, cmd in ((1, 0, "/usr/lib/systemd/systemd"),
                           (50, 1, "/usr/sbin/cron"),
                           (80, 50, "/bin/bash"),
                           (99, 80, "/tmp/implant.sh")):
        tree.nodes[pid] = ProcessNode(pid, ppid, cmd, 0)
    return tree


def test_ancestry_shows_full_chain_in_order():
    """A cadeia vai do ancestral mais antigo ate o processo analisado."""
    tree = _tree_with_chain()
    html = _render_ancestry(tree.nodes[99], tree)
    assert html.index("systemd") < html.index("cron") < html.index("bash") < html.index("implant")


def test_ancestry_still_shows_for_root_process():
    """
    [2026-08-20] A premissa deste teste foi INVERTIDA por decisao do Mario:
    "mesmo nao tendo informacao, tudo tem que ficar visivel sempre". Antes o
    bloco era omitido para um processo sem cadeia, e o analista ficava sem saber
    se aquele processo nao TEM ancestral ou se a ferramenta nao COLETOU a
    arvore. Numa peca forense essas duas respostas sao muito diferentes, e e o
    que a D-020 fixa: todo campo visivel, em um de tres estados.

    O teste passa a exigir o contrario: o bloco aparece, dizendo por que esta
    vazio.
    """
    tree = ProcessTree()
    tree.nodes[1] = ProcessNode(1, 0, "init", 0)
    html = _render_ancestry(tree.nodes[1], tree)
    assert "Process Ancestry" in html, "o bloco sumiu de novo (D-020)"
    assert "sem ancestral capturado" in html, (
        "o bloco aparece mas nao diz POR QUE esta vazio")


def test_ancestry_survives_a_cycle():
    """Ciclo de PPID nao pode gerar laco infinito."""
    tree = ProcessTree()
    tree.nodes[10] = ProcessNode(10, 11, "a", 0)
    tree.nodes[11] = ProcessNode(11, 10, "b", 0)
    html = _render_ancestry(tree.nodes[10], tree)
    assert "a" in html and "b" in html


def test_ancestry_escapes_command_lines():
    """Comandos na cadeia sao escapados."""
    tree = ProcessTree()
    tree.nodes[1] = ProcessNode(1, 0, 'evil"><img src=x>', 0)
    tree.nodes[2] = ProcessNode(2, 1, "child", 0)
    html = _render_ancestry(tree.nodes[2], tree)
    assert "<img" not in html
    assert "&lt;img" in html
