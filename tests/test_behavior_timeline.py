# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_behavior_timeline.py
# DESCRIPTION: Comportamento ao longo do tempo, nao o retrato de um instante.
#
#              Uma captura responde "isto estava rodando". A pergunta que decide
#              a resposta a um incidente e outra: "isto rodou uma vez ou roda
#              sempre?". Um artefato que reaparece a cada poucos minutos tem
#              persistencia ativa e vai voltar depois de morto; um que apareceu
#              uma unica vez pode ter sido acao manual. Sao incidentes
#              diferentes, e a diferenca so aparece olhando varias capturas.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

from src.core.snapshot_diff import (build_timeline, classify, summarize_risk,
                                    LIMIAR_CRITICO, ROTULO_CRITICO,
                                    ROTULO_REDE, ROTULO_ROOT, ROTULO_ORFAO)

FONTE = os.path.join("src", "controllers", "server_controller.py")


def _captura(cmds):
    return {"processes": dict(
        (i, {"pid": 100 + i, "cmd": c, "anomaly_score": 0})
        for i, c in enumerate(cmds))}


# ------------------------------------------------------------------------------
# RECORRENCIA
# ------------------------------------------------------------------------------
def test_a_command_seen_in_every_capture_is_counted():
    """
    O caso que motivou a tela: saber que o mesmo artefato rodou varias vezes ao
    longo do tempo, e nao apenas que existia num instante.
    """
    capturas = [_captura(["miner"]), _captura(["miner"]), _captura(["miner"])]
    linha = build_timeline(capturas)[0]

    assert linha["cmd"] == "miner"
    assert linha["count"] == 3


def test_a_one_off_command_is_not_listed():
    """
    Aparecer uma unica vez nao caracteriza comportamento. Lista-lo encheria a
    tela com o sistema inteiro e esconderia o que de fato se repete.
    """
    capturas = [_captura(["bash", "efemero"]), _captura(["bash"])]
    assert [r["cmd"] for r in build_timeline(capturas)] == ["bash"]


def test_which_captures_contained_it_are_recorded():
    """
    Saber QUANTAS vezes nao basta: a distribuicao no tempo distingue algo
    constante de algo que voltou depois de sumir.
    """
    capturas = [_captura(["miner"]), _captura([]), _captura(["miner"])]
    assert build_timeline(capturas)[0]["captures"] == [0, 2]


def test_the_same_command_twice_in_one_capture_counts_once():
    """
    Um comando com varias instancias simultaneas nao rodou varias VEZES: a
    coluna mede presenca ao longo do tempo, nao quantidade.
    """
    payload = {"processes": {1: {"pid": 1, "cmd": "miner"},
                             2: {"pid": 2, "cmd": "miner"}}}
    assert build_timeline([payload, payload])[0]["count"] == 2


def test_the_riskiest_recurring_command_comes_first():
    """Persistencia ativa e a combinacao de repetir muito com risco alto."""
    def _cap(score):
        return {"processes": {1: {"pid": 1, "cmd": "banal", "anomaly_score": 0},
                              2: {"pid": 2, "cmd": "miner",
                                  "anomaly_score": score}}}
    linhas = build_timeline([_cap(90), _cap(90)])
    assert linhas[0]["cmd"] == "miner"


def test_the_highest_score_ever_seen_is_kept():
    """
    Um artefato pode passar despercebido numa captura e ser pego na seguinte.
    Guardar o maior risco ja observado evita que a leitura mais recente, e
    possivelmente incompleta, apague o que ja se sabia.
    """
    baixo = {"processes": {1: {"pid": 1, "cmd": "x", "anomaly_score": 5}}}
    alto = {"processes": {1: {"pid": 1, "cmd": "x", "anomaly_score": 95}}}
    assert build_timeline([alto, baixo])[0]["max_score"] == 95


def test_empty_history_does_not_break():
    assert build_timeline([]) == []
    assert build_timeline([None, {}]) == []


# ------------------------------------------------------------------------------
# LEITURA DE CADA PROCESSO
# ------------------------------------------------------------------------------
def test_high_risk_is_labelled():
    assert ROTULO_CRITICO in classify({"alert_score": LIMIAR_CRITICO})


def test_a_quiet_process_gets_no_labels():
    """Rotular tudo equivale a nao rotular nada."""
    assert classify({"pid": 5, "ppid": 4, "uid": 1000}) == []


def test_network_activity_is_labelled():
    """
    "Nasceu de forma estranha" quase sempre passa por rede: um processo novo com
    conexao ativa e outra coisa que um utilitario local.
    """
    assert ROTULO_REDE in classify({"connections": ["10.0.0.1:4444"]})


def test_running_as_root_is_labelled():
    assert ROTULO_ROOT in classify({"uid": 0})


def test_a_reparented_process_is_labelled():
    """
    Pai igual a init significa que quem o criou ja morreu: a cadeia que
    explicaria a origem se perdeu, e isso e informacao.
    """
    assert ROTULO_ORFAO in classify({"pid": 900, "ppid": 1})


def test_init_itself_is_not_called_reparented():
    assert ROTULO_ORFAO not in classify({"pid": 1, "ppid": 1})


def test_risk_summary_counts_what_needs_attention():
    itens = [{"alert_score": 90}, {"alert_score": 10}, {"alert_score": 75}]
    assert summarize_risk(itens) == 2


# ------------------------------------------------------------------------------
# A TELA
# ------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


def test_history_shows_the_timeline(codigo):
    assert "_render_timeline" in codigo
    assert "build_timeline" in codigo


def test_timeline_window_is_bounded(codigo):
    """
    Cada captura da linha do tempo exige decifrar um laudo inteiro. Sem limite,
    abrir a pagina viraria trabalho pesado no servidor.
    """
    assert "JANELA_TIMELINE" in codigo


def test_diff_labels_each_process(codigo):
    """A tela precisa responder "algum destes e critico?" sem abrir o laudo."""
    bloco = codigo.split("def _linha_proc")[1].split("def _secao")[0]
    assert "classify(p)" in bloco


def test_diff_shows_where_a_new_process_came_from(codigo):
    """
    Um processo novo importa menos por si do que por quem o criou: um shell
    nascido de um servidor web nao e o mesmo que um shell nascido de um login.
    """
    bloco = codigo.split("def _linha_proc")[1].split("def _secao")[0]
    assert "criado por" in bloco


def test_diff_says_when_the_parent_is_missing(codigo):
    """Nao encontrar o pai e um fato relevante, nao um campo em branco."""
    bloco = codigo.split("def _linha_proc")[1].split("def _secao")[0]
    assert "origem se" in bloco
