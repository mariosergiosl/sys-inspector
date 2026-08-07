# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_capabilities.py
# DESCRIPTION: O que cada host consegue medir, e o que consegue exercitar.
#
#              Sem esta resposta, "o agente X nao acusou o cenario Y" e ambiguo
#              entre duas coisas OPOSTAS: a deteccao falhou, ou o host nunca
#              teve como gerar aquele cenario. As duas produzem exatamente o
#              mesmo resultado visivel, e foi essa ambiguidade que consumiu um
#              diagnostico inteiro no laboratorio antes de se descobrir que uma
#              das maquinas simplesmente nao tinha compilador.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

from src.core.capabilities import (describe_host, detection_capabilities,
                                   generation_capabilities, missing_for_scenarios,
                                   summarize, FERRAMENTAS_DE_CENARIO)

FONTE = os.path.join("src", "controllers", "server_controller.py")


# ------------------------------------------------------------------------------
# AS DUAS PERGUNTAS
# ------------------------------------------------------------------------------
def test_the_two_sides_stay_separate():
    """
    Juntar deteccao e geracao faria perder a distincao entre "nao vi" e "nao
    havia como ver", que e justamente o que este modulo existe para preservar.
    """
    retrato = describe_host()
    assert "detect" in retrato
    assert "generate" in retrato


def test_detection_reports_whether_ebpf_is_available():
    """
    Sem eBPF a captura se reduz ao que /proc mostra. Isso precisa estar dito e
    nao suposto por quem le o laudo.
    """
    assert "ebpf" in detection_capabilities()


def test_detection_reports_privilege():
    """
    Um agente sem root produz laudo incompleto SEM erro aparente, que e o modo
    de falha que este projeto mais evita.
    """
    assert "root" in detection_capabilities()


def test_generation_covers_every_tool_the_scenario_uses():
    """
    Uma ferramenta ausente desta lista nunca seria reportada, e a lacuna que ela
    causa no cenario ficaria sem explicacao.
    """
    gerar = generation_capabilities()
    for ferramenta in ("gcc", "podman", "tc", "iptables"):
        assert ferramenta in gerar
    assert set(gerar) == set(FERRAMENTAS_DE_CENARIO)


# ------------------------------------------------------------------------------
# A LEITURA
# ------------------------------------------------------------------------------
def test_missing_tools_are_named():
    """Dizer "limitado" sem dizer o que falta nao ajuda ninguem a agir."""
    caps = {"generate": {"gcc": False, "podman": False, "tc": True}}
    assert missing_for_scenarios(caps) == ["gcc", "podman"]


def test_a_complete_host_lists_nothing_missing():
    caps = {"generate": {"gcc": True, "podman": True}}
    assert missing_for_scenarios(caps) == []


def test_the_summary_warns_when_ebpf_is_absent():
    """
    E a informacao mais importante da linha: muda quanto vale tudo que aquele
    agente produz.
    """
    resumo = summarize({"detect": {"ebpf": False, "root": True}, "generate": {}})
    assert "SEM eBPF" in resumo


def test_the_summary_warns_when_running_without_privilege():
    resumo = summarize({"detect": {"ebpf": True, "root": False}, "generate": {}})
    assert "SEM root" in resumo


def test_an_agent_that_never_reported_is_not_treated_as_incapable():
    """
    Agente anterior a esta versao nao envia capacidades. Exibi-lo como incapaz
    seria acusar de ausencia o que e apenas silencio de protocolo.
    """
    assert "desconhecidas" in summarize({})


# ------------------------------------------------------------------------------
# O CAMINHO ATE A TELA
# ------------------------------------------------------------------------------
def test_the_agent_sends_capabilities_in_the_check_in():
    fonte = io.open(os.path.join("src", "core", "outbox.py"),
                    encoding="utf-8").read()
    assert "capabilities" in fonte
    assert "describe_host" in fonte


def test_the_server_stores_what_it_receives():
    fonte = io.open(os.path.join("src", "core", "database.py"),
                    encoding="utf-8").read()
    assert "def set_capabilities" in fonte
    assert "def get_capabilities" in fonte


def test_the_server_exposes_the_screen():
    codigo = io.open(FONTE, encoding="utf-8").read()
    assert "'/capabilities'" in codigo
    assert "_serve_capabilities" in codigo


def test_the_screen_explains_why_limited_is_not_failure():
    """
    Sem essa frase o analista deduz, e deduzir errado aqui leva a tratar host
    saudavel como comprometido, ou o contrario.
    """
    codigo = io.open(FONTE, encoding="utf-8").read()
    bloco = codigo.split("def _serve_capabilities")[1].split("def _serve_queue")[0]
    assert "nao acusa menos por" in bloco
    assert "nao tem como gerar" in bloco
