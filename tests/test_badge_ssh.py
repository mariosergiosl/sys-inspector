# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_badge_ssh.py
# DESCRIPTION: Trava a regra unica do badge de SSH (F-206).
#
# WHY:         Anotado pelo Mario testando a interface em 2026-08-20 ("alerta de
#              conexao SSH sem os dados") e diagnosticado depois: a mesma regra
#              vivia em TRES lugares. O badge acendia por `"ssh" in cmd` (duas
#              copias em process_tree.py) e o detalhe decidia por
#              `"sshd" in cmd`. Para `/usr/bin/ssh-agent /usr/bin/gpg-agent`
#              o badge acendia e o detalhe dizia SSH:No; e a legenda promete
#              "Sessao SSH ativa", que ssh-agent nao e.
#
#              As linhas de comando abaixo foram MEDIDAS na .161 e na gwlocal
#              em 2026-10-09, inclusive o curl de alerta de login que cita
#              "sshd" no texto da mensagem.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

pt = pytest.importorskip(
    "src.collectors.process_tree",
    reason="process_tree importa pwd, que so existe em Linux")

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SESSOES = [
    "sshd: root [priv]",
    "sshd: root@notty",
    "sshd: mario@pts/0",
    "ssh -q root@192.168.56.161",
    "/usr/bin/ssh -q -o LogLevel=ERROR root@192.168.56.200 uptime",
]

NAO_SESSOES = [
    "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
    "/usr/sbin/sshd -D",
    "/usr/bin/ssh-agent /usr/bin/gpg-agent --sh --daemon",
    "ssh-keygen -t ed25519",
    "sshfs root@host:/srv /mnt",
    "/usr/lib/ssh/sftp-server",
    "/usr/bin/curl -s -X POST https://api.example/sendMessage "
    "-d text=Servico: sshd",
    "bash -c ssh_wrapper.sh",
    "",
]


@pytest.mark.parametrize("cmd", SESSOES)
def test_sessao_ssh_acende(cmd):
    assert pt._eh_sessao_ssh(cmd), "deveria ser sessao SSH: %r" % cmd


@pytest.mark.parametrize("cmd", NAO_SESSOES)
def test_o_que_nao_e_sessao_nao_acende(cmd):
    """REPROVA A VERSAO ANTERIOR: a substring "ssh" acendia todos estes."""
    assert not pt._eh_sessao_ssh(cmd), "nao e sessao SSH: %r" % cmd


def test_badge_da_arvore_usa_a_regra_unica():
    """A montagem da arvore (add_or_update) acende o badge pela regra unica."""
    tree = pt.ProcessTree()
    agente = tree.add_or_update(4242, 1, "/usr/bin/ssh-agent /usr/bin/gpg-agent",
                                0, 120)
    sessao = tree.add_or_update(4243, 1, "sshd: root@pts/0", 0, 120)
    assert "SSH" not in agente.context_tags
    assert "SSH" in sessao.context_tags


def test_nenhuma_copia_da_regra_antiga_sobrou():
    """Colisao: as duas montagens da arvore e o detalhe leem a MESMA decisao."""
    with io.open(os.path.join(RAIZ, "src/collectors/process_tree.py"),
                 encoding="utf-8") as fh:
        arvore = fh.read()
    with io.open(os.path.join(RAIZ, "src/exporters/html_report.py"),
                 encoding="utf-8") as fh:
        laudo = fh.read()
    assert '"ssh" in cmd_lower' not in arvore
    assert arvore.count("_eh_sessao_ssh(") >= 3, (
        "a definicao e as duas montagens da arvore tem que usar a regra unica")
    assert '"sshd" in node.cmd' not in laudo
    assert '"SSH" in (getattr(node, "context_tags"' in laudo, (
        "o detalhe deixou de ler a decisao do badge")


def test_detalhe_concorda_com_o_badge():
    """REPROVA A VERSAO ANTERIOR: badge aceso e detalhe dizendo SSH:No."""
    from src.exporters.html_report import _get_details_html
    tree = pt.ProcessTree()
    sessao = tree.add_or_update(5151, 1, "ssh -q root@host", 0, 120)
    assert "SSH" in sessao.context_tags
    html = _get_details_html(sessao, [], tree)
    assert "SSH:Yes" in html
