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


def test_report_omits_redundant_names():
    """Quando o FQDN e igual ao nome curto, nao se repete a mesma informacao."""
    html = render_os_block({"hostname": "web01", "fqdn": "web01",
                            "hostnames": ["web01"]}, {})
    assert "FQDN" not in html
    assert "Other names" not in html


def test_report_survives_missing_name_data():
    """Captura antiga, sem os campos novos, continua renderizando."""
    html = render_os_block({"hostname": "web01"}, {})
    assert "web01" in html


def test_names_are_escaped():
    """Nome vindo do host analisado nao pode injetar marcacao."""
    html = render_os_block({"hostname": "a", "fqdn": "<script>x</script>",
                            "hostnames": ["a", "<script>x</script>"]}, {})
    assert "<script>" not in html
