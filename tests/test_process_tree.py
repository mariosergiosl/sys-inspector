# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_process_tree.py
# DESCRIPTION: Testa a agregacao de deteccao do ProcessTree. Guarda em especial
#              a correcao do item 1: threads de kernel (PID 2 e subarvore) nao
#              podem receber NET ERR mesmo com contadores TCP, pois drops/retrans
#              em softirq sao cobrados ao thread de kernel em execucao, nao ao
#              dono do socket.
#
# NOTA: process_tree importa pwd/grp; roda em Linux (VM/CI), nao no Windows.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.collectors.process_tree import (ProcessTree, ProcessNode,
                                          SCORE_NET_ISSUE)


def _add(tree, pid, ppid, cmd="proc", uid=0):
    """Cria um ProcessNode e o registra na arvore."""
    node = ProcessNode(pid, ppid, cmd, uid)
    tree.nodes[pid] = node
    return node


def test_userspace_process_gets_net_err():
    """Processo de userspace com retransmissoes recebe NET ERR e score."""
    tree = ProcessTree()
    _add(tree, 1, 0, "systemd")
    proc = _add(tree, 100, 1, "artifact_net")
    proc.tcp_retrans = 5
    tree.aggregate_stats()
    assert "NET ERR" in tree.nodes[100].tags_accumulated
    assert tree.nodes[100].anomaly_score >= SCORE_NET_ISSUE


def test_kernel_thread_excluded_from_net_err():
    """Item 1: thread de kernel (sob PID 2) nao recebe NET ERR nem score."""
    tree = ProcessTree()
    _add(tree, 1, 0, "systemd")
    _add(tree, 2, 0, "kthreadd")
    ksoft = _add(tree, 50, 2, "ksoftirqd/0")
    ksoft.tcp_retrans = 999  # drops/retrans cobrados em softirq
    tree.aggregate_stats()
    assert "NET ERR" not in tree.nodes[50].tags_accumulated
    assert not (tree.nodes[50].anomaly_score & SCORE_NET_ISSUE)


def test_kernel_pids_set_covers_subtree():
    """kernel_pids abrange PID 2 e toda a sua subarvore."""
    tree = ProcessTree()
    _add(tree, 2, 0, "kthreadd")
    _add(tree, 50, 2, "ksoftirqd/0")
    _add(tree, 51, 50, "sub_kthread")
    tree.aggregate_stats()
    assert {2, 50, 51}.issubset(tree.kernel_pids)


def test_pre_existing_net_err_tag_discarded_on_kernel_thread():
    """Tag NET ERR pre-existente em thread de kernel e descartada (item 1)."""
    tree = ProcessTree()
    _add(tree, 2, 0, "kthreadd")
    kthread = _add(tree, 60, 2, "kworker")
    kthread.context_tags = ["NET ERR"]
    kthread.tcp_drops = 10
    tree.aggregate_stats()
    assert "NET ERR" not in tree.nodes[60].tags_accumulated
