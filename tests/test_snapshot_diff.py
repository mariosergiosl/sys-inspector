# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_snapshot_diff.py
# DESCRIPTION: Comparacao entre duas capturas do mesmo host.
#
#              Uma captura responde "como o host esta"; a investigacao pergunta
#              "o que mudou". Num host com centenas de processos essa diferenca
#              e invisivel a olho nu, e e nela que aparece o processo plantado
#              entre uma coleta e a seguinte.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core.snapshot_diff import diff_snapshots, has_changes


def _proc(pid, name="bash", cmdline=None, start=100, **extra):
    # Os nomes seguem ProcessNode: a linha de comando e `cmd` e o risco e
    # `anomaly_score`. Usar nomes inventados aqui deixaria o teste passar
    # enquanto a tela real ficaria vazia, que foi o que aconteceu em campo.
    base = {"pid": pid, "ppid": 1, "cmd": cmdline or name,
            "start_time": start, "uid": 0, "exe_path": "/bin/" + name,
            "username": "root", "anomaly_score": 0}
    base.update(extra)
    return base


def _captura(procs, findings=None):
    return {"processes": dict((p["pid"], p) for p in procs),
            "findings": findings or []}


# ------------------------------------------------------------------------------
# PROCESSOS
# ------------------------------------------------------------------------------
def test_new_process_is_reported():
    """O processo que nao existia antes e o que a investigacao procura."""
    antes = _captura([_proc(1, "systemd")])
    depois = _captura([_proc(1, "systemd"), _proc(42, "miner")])

    r = diff_snapshots(antes, depois)
    assert [p["cmd"] for p in r["processes"]["appeared"]] == ["miner"]
    assert r["summary"]["appeared"] == 1


def test_process_that_vanished_is_reported():
    """
    Um processo que sumiu importa tanto quanto um que surgiu: pode ser o
    artefato que se apagou depois de agir.
    """
    antes = _captura([_proc(1, "systemd"), _proc(42, "miner")])
    depois = _captura([_proc(1, "systemd")])

    r = diff_snapshots(antes, depois)
    assert [p["cmd"] for p in r["processes"]["disappeared"]] == ["miner"]


def test_unchanged_process_is_not_noise():
    """Repetir o que nao mudou afogaria o que mudou."""
    antes = _captura([_proc(1, "systemd")])
    depois = _captura([_proc(1, "systemd")])

    r = diff_snapshots(antes, depois)
    assert r["summary"]["appeared"] == 0
    assert r["summary"]["disappeared"] == 0
    assert r["summary"]["changed"] == 0
    assert not has_changes(r)


def test_pid_reuse_is_not_read_as_continuity():
    """
    O kernel reaproveita PID. Tratar o mesmo numero como o mesmo processo
    esconderia justamente a troca: um programa saiu e outro entrou no lugar.
    """
    antes = _captura([_proc(500, "nginx", start=100)])
    depois = _captura([_proc(500, "nc", start=999)])

    r = diff_snapshots(antes, depois)
    assert [p["cmd"] for p in r["processes"]["appeared"]] == ["nc"]
    assert [p["cmd"] for p in r["processes"]["disappeared"]] == ["nginx"]
    assert r["summary"]["changed"] == 0


def test_changed_binary_of_a_living_process_is_flagged():
    """
    Mesmo processo, executavel diferente: e um sinal forte e passaria batido se
    so se comparasse quem entrou e quem saiu.
    """
    antes = _captura([_proc(7, "sshd", exe_path="/usr/sbin/sshd")])
    depois = _captura([_proc(7, "sshd", exe_path="/tmp/sshd")])

    r = diff_snapshots(antes, depois)
    mudanca = r["processes"]["changed"][0]["changes"]["exe_path"]
    assert mudanca["antes"] == "/usr/sbin/sshd"
    assert mudanca["depois"] == "/tmp/sshd"


def test_volatile_metrics_do_not_count_as_change():
    """
    CPU e memoria oscilam a cada ciclo. Se contassem como mudanca, todo processo
    vivo apareceria na lista e o painel perderia a serventia.
    """
    antes = _captura([_proc(7, "sshd", cpu_usage_pct=1.0, rss=100)])
    depois = _captura([_proc(7, "sshd", cpu_usage_pct=90.0, rss=900)])

    assert diff_snapshots(antes, depois)["summary"]["changed"] == 0


def test_riskiest_new_process_comes_first():
    """Quem abre a tela precisa ver primeiro o que merece atencao."""
    antes = _captura([])
    depois = _captura([_proc(10, "calc", anomaly_score=1),
                       _proc(11, "backdoor", anomaly_score=90)])

    r = diff_snapshots(antes, depois)
    assert r["processes"]["appeared"][0]["cmd"] == "backdoor"


# ------------------------------------------------------------------------------
# ACHADOS
# ------------------------------------------------------------------------------
def test_new_finding_is_reported():
    antes = _captura([], findings=[{"fingerprint": "a", "title": "velho"}])
    depois = _captura([], findings=[{"fingerprint": "a", "title": "velho"},
                                    {"fingerprint": "b", "title": "novo"}])

    r = diff_snapshots(antes, depois)
    assert [f["title"] for f in r["findings"]["new"]] == ["novo"]


def test_finding_that_disappeared_is_reported_as_gone():
    """
    Um achado que sumiu nao equivale a problema resolvido: o artefato pode ter
    sido apagado para encobrir rastro. O painel relata o fato, sem concluir.
    """
    antes = _captura([], findings=[{"fingerprint": "a", "title": "persistencia"}])
    depois = _captura([], findings=[])

    r = diff_snapshots(antes, depois)
    assert [f["title"] for f in r["findings"]["gone"]] == ["persistencia"]


def test_finding_identity_survives_a_reworded_description():
    """
    A impressao digital e o campo estavel. Comparar pelo texto faria qualquer
    ajuste de redacao virar um achado novo.
    """
    antes = _captura([], findings=[{"fingerprint": "a", "title": "texto antigo"}])
    depois = _captura([], findings=[{"fingerprint": "a", "title": "texto novo"}])

    r = diff_snapshots(antes, depois)
    assert r["summary"]["findings_new"] == 0
    assert r["summary"]["findings_gone"] == 0


# ------------------------------------------------------------------------------
# ROBUSTEZ
# ------------------------------------------------------------------------------
def test_empty_snapshots_do_not_break():
    """Captura vazia ou corrompida nao pode derrubar a tela de comparacao."""
    r = diff_snapshots({}, {})
    assert r["summary"]["appeared"] == 0
    assert not has_changes(r)


def test_missing_keys_do_not_break():
    r = diff_snapshots(None, {"processes": {"1": {"pid": 1}}})
    assert r["summary"]["appeared"] == 1


# ------------------------------------------------------------------------------
# AS TELAS
# ------------------------------------------------------------------------------
import io
import os

import pytest

FONTE = os.path.join("src", "controllers", "server_controller.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


def test_server_exposes_history_and_diff(codigo):
    assert "'/history/'" in codigo
    assert "'/diff/'" in codigo


def test_comparison_runs_on_the_server(codigo):
    """
    O laudo completo passa de 10MB. Mandar duas capturas para o navegador
    comparar inviabilizaria a tela justamente nos hosts mais movimentados, que
    sao os que mais interessam.
    """
    assert "diff_snapshots" in codigo


def test_diff_output_is_escaped(codigo):
    """
    A linha de comando vem do host inspecionado, que pode estar comprometido.
    Sem escapar, um processo com nome malicioso injetaria HTML na tela de quem
    esta investigando justamente aquele host.
    """
    bloco = codigo.split("def _serve_diff")[1].split("def _serve_command_log")[0]
    assert "_esc(p.get(\"cmd\")" in bloco
    assert "_esc(p.get(\"user\")" in bloco


def test_diff_reads_the_real_field_names():
    """
    Ler um campo que nao existe devolve vazio em silencio. Foi o que derrubou a
    primeira versao da tela: a comparacao funcionava, mas cada linha mostrava so
    o numero do PID, sem dizer de que processo se tratava.
    """
    from src.collectors.process_tree import ProcessNode
    from src.core.snapshot_diff import _resumo

    node = ProcessNode(42, 1, "/usr/bin/nc -l 4444", 0)
    node.anomaly_score = 90
    resumo = _resumo(vars(node))

    assert resumo["cmd"] == "/usr/bin/nc -l 4444"
    assert resumo["alert_score"] == 90


def test_every_section_is_shown_even_when_empty(codigo):
    """
    Omitir a secao vazia deixava o analista sem saber se nada desapareceu ou se
    a tela nem trata desaparecimento. Numa ferramenta forense, "verifiquei e nao
    ha" e uma resposta diferente de silencio.
    """
    bloco = codigo.split("def _serve_diff")[1].split("def _serve_command_log")[0]
    assert "Nenhum." in bloco
    assert "Processos que sumiram" in bloco


def test_diff_shows_when_each_capture_was_taken(codigo):
    """
    "#467 para #469" nao diz nada sobre o intervalo, e o intervalo e o que da
    sentido a diferenca observada.
    """
    bloco = codigo.split("def _serve_diff")[1].split("def _serve_command_log")[0]
    assert "_fmt_ts(ts_a)" in bloco


def test_history_is_reachable_from_the_fleet(codigo):
    assert "/history/{uuid}" in codigo


def test_diff_requires_both_captures(codigo):
    """Sem os dois lados nao ha comparacao; responder 400 evita tela quebrada."""
    bloco = codigo.split("def _serve_diff")[1].split("def _serve_command_log")[0]
    assert "status=400" in bloco
