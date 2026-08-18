# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/eventfmt.py
# DESCRIPTION: Formatacao dos eventos de rede vindos das sondas eBPF.
#
# WHY:         Estas funcoes viviam dentro do laco de eventos do engine, que
#              importa BCC no topo do modulo. Isso tornava impossivel testa-las
#              fora de um host com eBPF: para conferir se um endereco IPv6 e
#              formatado certo era preciso um kernel, um agente rodando e um
#              cenario. Na pratica, nao eram testadas.
#
#              A decisao de projeto e simples: o que TRADUZ dado nao precisa
#              saber de onde o dado veio. Aqui entra bytes e sai texto, sem
#              kernel, sem socket aberto, sem BCC.
#
# NOTES:       Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import socket
import struct


def _ipv4(bruto):
    """Endereco IPv4 de 32 bits, na ordem em que o kernel entrega."""
    return socket.inet_ntop(socket.AF_INET, struct.pack("I", bruto))


def _ipv6(bruto):
    """Endereco IPv6 de 16 bytes."""
    return socket.inet_ntop(socket.AF_INET6, bytes(bytearray(bruto)))


def formata_conexao(ip_ver, daddr, daddr6, dport_rede):
    """
    Descreve uma conexao de SAIDA.

    O endereco v6 vai entre colchetes porque contem dois-pontos: sem eles nao ha
    como separar o endereco da porta na leitura.

    Familia zero significa evento anterior a existencia da sonda IPv6, e e lido
    como IPv4, que era o unico caso possivel na epoca.
    """
    porta = socket.ntohs(dport_rede)
    if int(ip_ver or 4) == 6:
        return "IPv6 -> [%s]:%d" % (_ipv6(daddr6), porta)
    return "IPv4 -> %s:%d" % (_ipv4(daddr), porta)


def formata_escuta(ip_ver, daddr, daddr6, dport_rede):
    """
    Descreve um socket que passou a ESCUTAR.

    Familia desconhecida nao e erro: um bind em socket de dominio unix e
    legitimo e nao tem endereco de rede. Dizer isso e melhor do que inventar um
    endereco ou omitir o evento.
    """
    porta = socket.ntohs(dport_rede)
    familia = int(ip_ver or 0)
    if familia == 6:
        return "IPv6 [%s]:%d" % (_ipv6(daddr6), porta)
    if familia == 4:
        return "IPv4 %s:%d" % (_ipv4(daddr), porta)
    return "local (nao IP)"


def decodifica_saida(exit_code_bruto):
    """
    Codigo de saida do processo.

    O kernel guarda o valor deslocado em oito bits, junto com o sinal que
    encerrou o processo. Publicar o numero bruto faria uma saida limpa aparecer
    como um codigo enorme e sem sentido no laudo.
    """
    return int(exit_code_bruto or 0) >> 8
