# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_host_names.py
# DESCRIPTION: Coleta e exibicao dos nomes do host.
#
#              Um host raramente tem um nome so: existe o nome curto, o FQDN,
#              os aliases de /etc/hosts e os nomes que o DNS reverso devolve
#              para cada interface. Numa pericia isso importa porque o mesmo
#              host aparece com nomes diferentes nos logs de sistemas
#              diferentes, e correlacionar esses registros exige conhecer todos.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import socket

import pytest

from src.collectors.system_inventory import collect_host_names
from src.exporters.html_report import render_os_block


def test_returns_a_primary_and_a_list():
    """Ha um nome principal e a lista completa."""
    principal, todos = collect_host_names()
    assert isinstance(principal, str)
    assert isinstance(todos, list)


def test_short_hostname_is_always_included():
    """O nome curto do host nunca fica de fora."""
    _, todos = collect_host_names()
    assert socket.gethostname() in todos


def test_primary_is_among_the_names():
    """O principal e um dos nomes listados, nao um valor a parte."""
    principal, todos = collect_host_names()
    assert principal in todos


def test_names_are_unique_and_sorted():
    """A lista nao repete nomes e tem ordem estavel entre execucoes."""
    _, todos = collect_host_names()
    assert len(todos) == len(set(todos))
    assert todos == sorted(todos)


def test_localhost_is_not_reported_as_a_host_name():
    """"localhost" identifica qualquer maquina, entao nao identifica nenhuma."""
    _, todos = collect_host_names()
    assert "localhost" not in todos


def test_collection_never_raises():
    """DNS indisponivel ou /etc/hosts ilegivel nao pode derrubar a coleta."""
    for _ in range(2):
        collect_host_names()


# ------------------------------------------------------------------------------
# Exibicao no laudo
# ------------------------------------------------------------------------------
def test_report_shows_the_fqdn():
    """O FQDN aparece no bloco SYSTEM."""
    html = render_os_block({"hostname": "web01", "fqdn": "web01.lab.local",
                            "hostnames": ["web01", "web01.lab.local"]}, {})
    assert "FQDN" in html
    assert "web01.lab.local" in html


def test_report_lists_the_other_names():
    """Aliases adicionais tambem sao mostrados."""
    html = render_os_block({"hostname": "web01", "fqdn": "web01.lab.local",
                            "hostnames": ["web01", "web01.lab.local",
                                          "www.lab.local", "intranet.lab.local"]}, {})
    assert "Other names" in html
    assert "www.lab.local" in html
    assert "intranet.lab.local" in html


def test_redundant_names_still_show_their_line():
    """
    A regra anterior omitia a linha do FQDN quando ele repetia o nome curto,
    para nao repetir informacao. D-020 inverteu esse criterio: um campo que
    desaparece obriga o leitor a deduzir se o host nao tinha ou se a ferramenta
    nao olhou, e repetir um nome custa uma linha, enquanto deduzir errado
    invalida a conclusao tirada da ausencia.

    Os nomes ADICIONAIS continuam sem repetir o que ja foi mostrado: ali nao ha
    ambiguidade, porque a linha "Other names" permanece na tela declarando que
    nao havia outros.
    """
    html = render_os_block({"hostname": "web01", "fqdn": "web01",
                            "hostnames": ["web01"]}, {})
    assert "FQDN" in html
    assert "Other names" in html
    # Nenhum alias alem do proprio nome: o campo diz que olhou e nao havia.
    assert "nao havia valor" in html


def test_report_survives_missing_name_data():
    """Captura antiga, sem os campos novos, continua renderizando."""
    html = render_os_block({"hostname": "web01"}, {})
    assert "web01" in html


def test_names_are_escaped():
    """Nome vindo do host analisado nao pode injetar marcacao."""
    html = render_os_block({"hostname": "a", "fqdn": "<script>x</script>",
                            "hostnames": ["a", "<script>x</script>"]}, {})
    assert "<script>" not in html
