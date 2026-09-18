# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_eventfmt.py
# DESCRIPTION: Guarda a traducao dos eventos das sondas novas (IPv6, escuta,
#              codigo de saida) contra regressao.
#
# WHY:         Estas conversoes viviam dentro do laco de eventos do engine, que
#              importa BCC no topo, entao nao eram testaveis fora de um host com
#              eBPF e, na pratica, nunca foram testadas. Sao justamente o ponto
#              onde um sinal coletado corretamente pode chegar errado a tela, que
#              e a classe de falha que este projeto ja pagou duas vezes (o
#              anomaly_score lido como magnitude e o DELETED descartado na
#              renderizacao).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import socket
import struct

from src.core.eventfmt import (formata_conexao, formata_escuta,
                               decodifica_saida)

VAZIO6 = bytearray(16)


def _v4(texto):
    return struct.unpack("I", socket.inet_pton(socket.AF_INET, texto))[0]


def _v6(texto):
    return bytearray(socket.inet_pton(socket.AF_INET6, texto))


def _porta(n):
    return socket.htons(n)


# ------------------------------------------------------------------------------
# Conexao de saida
# ------------------------------------------------------------------------------
def test_ipv4_connection_keeps_the_previous_format():
    """O formato IPv4 nao pode mudar: telas e diffs antigos dependem dele."""
    assert formata_conexao(4, _v4("10.0.0.5"), VAZIO6,
                           _porta(443)) == "IPv4 -> 10.0.0.5:443"


def test_ipv6_connection_is_rendered_in_full():
    """
    O endereco v6 aparece INTEIRO. Se fosse lido pelos 4 primeiros bytes, como
    aconteceria reaproveitando o campo v4, sairia um IPv4 inventado.
    """
    assert formata_conexao(6, 0, _v6("2001:db8::1"),
                           _porta(443)) == "IPv6 -> [2001:db8::1]:443"


def test_ipv6_address_is_bracketed():
    """
    Colchetes nao sao enfeite: sem eles o dois-pontos do endereco se confunde
    com o separador da porta e a linha fica ambigua para quem le.
    """
    saida = formata_conexao(6, 0, _v6("fe80::1"), _porta(22))
    assert saida.endswith("]:22") and "[fe80::1]" in saida


def test_event_without_family_is_read_as_ipv4():
    """
    Familia zero e evento anterior a existencia da sonda v6. Tratado como IPv4,
    que era o unico caso possivel na epoca, em vez de descartado.
    """
    assert formata_conexao(0, _v4("192.168.0.1"), VAZIO6,
                           _porta(80)) == "IPv4 -> 192.168.0.1:80"


# ------------------------------------------------------------------------------
# Socket passando a escutar
# ------------------------------------------------------------------------------
def test_listening_socket_ipv4():
    assert formata_escuta(4, _v4("0.0.0.0"), VAZIO6,
                          _porta(8080)) == "IPv4 0.0.0.0:8080"


def test_listening_socket_ipv6():
    assert formata_escuta(6, 0, _v6("::"), _porta(8080)) == "IPv6 [::]:8080"


def test_unix_socket_bind_is_reported_not_invented():
    """
    Bind em socket de dominio unix e legitimo e nao tem endereco de rede. Dizer
    isso e melhor do que inventar um endereco ou omitir o evento: omitir faria a
    escuta desaparecer, e inventar poria um IP falso no laudo.
    """
    assert formata_escuta(0, 0, VAZIO6, 0) == "local (nao IP)"


# ------------------------------------------------------------------------------
# Codigo de saida
# ------------------------------------------------------------------------------
def test_clean_exit_is_zero():
    """Saida limpa e zero, nao um numero grande vindo do formato do kernel."""
    assert decodifica_saida(0) == 0


def test_exit_status_is_shifted_out_of_the_kernel_format():
    """
    O kernel guarda o status deslocado em 8 bits. Publicar o valor bruto faria
    'exit 1' aparecer como 256 no laudo.
    """
    assert decodifica_saida(256) == 1
    assert decodifica_saida(512) == 2


def test_missing_exit_code_does_not_raise():
    """Evento sem o campo nao pode quebrar a captura."""
    assert decodifica_saida(None) == 0
