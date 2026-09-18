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

from src.core import badges as badges_reg
from src.collectors.process_tree import (
    ProcessTree, ProcessNode, SCORE_NET_ISSUE, TAGS_QUE_SOBEM_NA_ARVORE,
    SCORE_CRED_CHANGE, SCORE_KMOD_LOAD, SCORE_NEW_LISTENER,
    SCORE_ACCEPTED_CONN, SCORE_MEM_ACCESS, SCORE_MEMFD_CREATE,
    SCORE_EXEC_MEM_GRANT, SCORE_BPF_USE, SCORE_FILE_DELETED,
    SCORE_FILE_RENAMED, SCORE_NS_CHANGE, SCORE_KEXEC_LOAD, SCORE_DNS_QUERY)


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


# ------------------------------------------------------------------------------
# F-201: SINAIS DAS 18 SONDAS DE 2026-08-17
# ------------------------------------------------------------------------------
# Campo do Node (populado pelas sondas via engine.py) -> (tag esperada, bit
# esperado, atributo de exemplo para popular o campo com dado).
_CAMPOS_COM_SINAL = (
    ("cred_changes", "CRED_CHANGE", SCORE_CRED_CHANGE, ["1000->0"]),
    ("kernel_module_loads", "KMOD_LOAD", SCORE_KMOD_LOAD, 1),
    ("listening", "NEW_LISTENER", SCORE_NEW_LISTENER, ["IPv4 0.0.0.0:4444"]),
    ("accepted", "ACCEPTED_CONN", SCORE_ACCEPTED_CONN, ["aceita de 1.2.3.4 na porta 22"]),
    ("mem_access", "MEM_ACCESS", SCORE_MEM_ACCESS, ["ptrace -> pid 200"]),
    ("memfd_created", "MEMFD_CREATE", SCORE_MEMFD_CREATE, 1),
    ("exec_mem_grants", "EXEC_MEM_GRANT", SCORE_EXEC_MEM_GRANT, 1),
    ("bpf_calls", "BPF_USE", SCORE_BPF_USE, 1),
    ("files_deleted", "FILE_DELETED", SCORE_FILE_DELETED, 1),
    ("files_renamed", "FILE_RENAMED", SCORE_FILE_RENAMED, 1),
    ("ns_changes", "NS_CHANGE", SCORE_NS_CHANGE, 1),
    ("kexec_calls", "KEXEC_LOAD", SCORE_KEXEC_LOAD, 1),
    ("dns_queries", "DNS_QUERY", SCORE_DNS_QUERY, ["exfil.example.com"]),
)


def test_cada_sonda_nova_vira_tag_e_bit_quando_tem_dado():
    """
    Cada um dos 13 campos das sondas novas, quando populado, produz a tag e o
    bit correspondente (F-201). Campo vazio nao produz nada (D-020: silencio
    e "olhou e nao havia", nao omissao).
    """
    for campo, tag, bit, valor_exemplo in _CAMPOS_COM_SINAL:
        tree = ProcessTree()
        proc = _add(tree, 100, 1, "proc")
        setattr(proc, campo, valor_exemplo)
        tree.aggregate_stats()
        node = tree.nodes[100]
        assert tag in node.tags_accumulated, campo
        assert node.anomaly_score & bit, campo


def test_sonda_sem_dado_nao_produz_tag_nem_bit():
    """Campo no valor padrao (lista vazia / contador zero) nao gera sinal."""
    tree = ProcessTree()
    _add(tree, 100, 1, "proc")
    tree.aggregate_stats()
    node = tree.nodes[100]
    for _campo, tag, bit, _valor in _CAMPOS_COM_SINAL:
        assert tag not in node.tags_accumulated
        assert not (node.anomaly_score & bit)


def test_tags_das_sondas_novas_nao_duplicam_entre_ciclos():
    """
    aggregate_stats roda a cada captura; a tag nao pode ser adicionada de novo
    a cada ciclo, o que inflaria context_tags sem limite num agente de longa
    duracao.
    """
    tree = ProcessTree()
    proc = _add(tree, 100, 1, "proc")
    proc.cred_changes = ["1000->0"]
    tree.aggregate_stats()
    tree.aggregate_stats()
    tree.aggregate_stats()
    node = tree.nodes[100]
    assert node.context_tags.count("CRED_CHANGE") == 1


def test_connections_aceita_append_como_o_engine_faz():
    """
    Regressao: connections era set() no __init__, mas engine.py grava com
    .append() dentro de um try/except que engolia o AttributeError em
    silencio (src/core/engine.py:247-249). Toda conexao TCP capturada pela
    sonda eBPF (v4 e v6) nunca era gravada de fato.
    """
    node = ProcessNode(100, 1, "proc", 0)
    node.connections.append("IPv4 -> 10.0.0.1:443")
    node.connections.append("IPv6 -> [::1]:443")
    assert node.connections == ["IPv4 -> 10.0.0.1:443", "IPv6 -> [::1]:443"]


def test_tcp_v6_connect_e_sched_process_exit_nao_geram_score():
    """
    As duas sondas sem bit proprio (dado renderizado em outro lugar do
    laudo) nao podem, por engano, somar anomaly_score.
    """
    tree = ProcessTree()
    proc = _add(tree, 100, 1, "proc")
    proc.connections = ["IPv6 -> [::1]:443"]
    proc.exited = True
    proc.exit_code = 1
    tree.aggregate_stats()
    assert tree.nodes[100].anomaly_score == 0


# ------------------------------------------------------------------------------
# ACUMULO DE BADGES NA ARVORE (achado do Mario, 2026-08-18, print/PDF)
# ------------------------------------------------------------------------------
# A raiz de uma arvore com centenas de processos so mostra o pior severidade
# (numero) por padrao; o BADGE que nomeia aquele sinal so aparece se o
# processo folha ficar expandido. Existia uma terceira lista de tags escrita
# a mao, dentro de accumulate_recursive, controlando quais badges sobem: nao
# tinha nenhum dos 13 sinais do F-201, nem DELETED/IMMUTABLE (que ja
# ficavam de fora antes do F-201). O efeito: a raiz mostrava o score maximo
# certo, mas sem o icone que o explica -- exatamente "achado sem explicacao"
# que o Mario reportou.
def test_todo_badge_do_registro_sobe_da_folha_para_a_raiz():
    """
    Cada tag de badges.TAG_MAP, aplicada a um processo folha, aparece
    tambem no tags_accumulated do processo raiz (PID 1) apos aggregate_stats.
    Testa contra o REGISTRO, nao uma copia manual, para nunca mais haver uma
    tag com badge e sem acumulo.
    """
    for tag in badges_reg.TAG_MAP:
        tree = ProcessTree()
        _add(tree, 1, 0, "systemd")
        folha = _add(tree, 100, 1, "proc")
        folha.context_tags = [tag]
        tree.aggregate_stats()
        assert tag in tree.nodes[1].tags_accumulated, (
            "%s tem badge mas nao sobe ate a raiz da arvore" % tag)


def test_lista_de_acumulo_e_o_registro_de_badges_mais_os_marcadores_internos():
    """
    Trava a composicao de TAGS_QUE_SOBEM_NA_ARVORE: registro de badges mais os
    quatro marcadores que tem renderizacao propria (nao sao chave de TAG_MAP).
    Se um novo marcador interno for criado sem entrar aqui, este teste avisa
    em vez de deixar o badge sumir na raiz em silencio.
    """
    esperado = set(badges_reg.TAG_MAP.keys()) | {"NET ERR", "NEW", "WARN", "🧊"}
    assert TAGS_QUE_SOBEM_NA_ARVORE == esperado
