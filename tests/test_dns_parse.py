# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_dns_parse.py
# DESCRIPTION: Guarda a extracao do nome consultado em DNS.
#
# WHY:         A ferramenta enxerga o IP de toda conexao e nao enxerga o dominio,
#              e inteligencia de ameaca casa por NOME: sem o dominio, "conectou em
#              185.x.x.x" nao cruza com nada.
#
#              O parse vive AQUI, no espaco de usuario, e nao no programa eBPF
#              (D-030). Um datagrama truncado ou malformado precisa resultar em
#              None, nunca em laco preso nem em excecao subindo para o laco de
#              eventos do agente.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import struct

from src.core.eventfmt import nome_dns


def _consulta(nome, qr=0, qdcount=1):
    """Monta um datagrama DNS de consulta, como o resolvedor envia."""
    flags = 0x8000 if qr else 0x0100
    cab = struct.pack(">HHHHHH", 0x1234, flags, qdcount, 0, 0, 0)
    corpo = b""
    for rotulo in nome.split("."):
        corpo += bytes(bytearray([len(rotulo)])) + rotulo.encode("ascii")
    corpo += b"\x00" + struct.pack(">HH", 1, 1)   # QTYPE=A, QCLASS=IN
    return cab + corpo


def test_simple_query_yields_the_name():
    assert nome_dns(_consulta("exemplo.com")) == "exemplo.com"


def test_subdomain_is_preserved_whole():
    """Subdominio importa: e nele que costuma estar o canal de C2."""
    assert nome_dns(_consulta("a.b.evil.example")) == "a.b.evil.example"


def test_answer_is_ignored():
    """So a PERGUNTA interessa; resposta nao e coletada."""
    assert nome_dns(_consulta("exemplo.com", qr=1)) is None


def test_query_without_question_section_is_ignored():
    assert nome_dns(_consulta("exemplo.com", qdcount=0)) is None


def test_truncated_datagram_returns_none():
    """
    A sonda copia um pedaco de TAMANHO FIXO: um nome longo chega cortado. Isso
    devolve None, e nao um nome pela metade que pareceria legitimo no laudo.
    """
    inteiro = _consulta("um.nome.bastante.comprido.para.exemplo.interno")
    assert nome_dns(inteiro[:20]) is None


def test_compression_pointer_is_refused():
    """Ponteiro de compressao nao ocorre em pergunta; se vier, e recusado."""
    cab = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    assert nome_dns(cab + b"\xc0\x0c") is None


def test_garbage_never_raises():
    """Entrada arbitraria nao pode derrubar o laco de eventos do agente."""
    for lixo in (b"", b"\x00", b"\xff" * 64, None, bytearray(64)):
        assert nome_dns(lixo) is None or isinstance(nome_dns(lixo), str)


def test_label_ceiling_stops_a_hostile_datagram():
    """
    Nome com rotulos demais para no teto, em vez de percorrer o pacote inteiro.
    O laco nunca depende do conteudo recebido.
    """
    cab = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    corpo = (b"\x01a" * 200) + b"\x00"
    assert nome_dns(cab + corpo) is None


def test_size_limit_is_honoured():
    """Quando o tamanho real e informado, o resto do buffer e ignorado."""
    pacote = _consulta("exemplo.com")
    preenchido = pacote + b"\xff" * 40
    assert nome_dns(preenchido, tamanho=len(pacote)) == "exemplo.com"
