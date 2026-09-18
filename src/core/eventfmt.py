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


# ------------------------------------------------------------------------------
# DNS
# ------------------------------------------------------------------------------
# Cabecalho DNS: 12 bytes antes da primeira pergunta.
_DNS_CABECALHO = 12
# Teto de rotulos por nome. Existe para o laco nunca depender do conteudo do
# pacote: um datagrama truncado ou malformado nao pode prender o agente.
_MAX_ROTULOS = 40


def nome_dns(payload, tamanho=None):
    """
    Extrai o nome consultado de um datagrama DNS.

    Recebe o pedaco BRUTO copiado pela sonda e devolve o nome, ou None quando o
    pacote nao e uma consulta legivel. E aqui que o parse acontece, e nao no eBPF:
    no espaco de usuario nao ha verificador limitando laco, e um nome truncado
    resulta em None em vez de travar o kernel (D-030).

    So le a secao de PERGUNTA, onde o nome aparece sem compressao. A compressao de
    rotulos so ocorre nas respostas, que nao sao coletadas.
    """
    if not payload:
        return None
    dados = bytes(bytearray(payload))
    if tamanho:
        dados = dados[:int(tamanho)]
    if len(dados) <= _DNS_CABECALHO:
        return None

    # QR=0 indica consulta; resposta nao interessa aqui.
    flags = (dados[2] << 8) | dados[3]
    if flags & 0x8000:
        return None
    # QDCOUNT: sem pergunta nao ha nome a extrair.
    if ((dados[4] << 8) | dados[5]) < 1:
        return None

    partes = []
    i = _DNS_CABECALHO
    for _ in range(_MAX_ROTULOS):
        if i >= len(dados):
            return None            # datagrama cortado antes do fim do nome
        tam = dados[i]
        if tam == 0:
            break                  # fim do nome
        if tam & 0xC0:
            return None            # ponteiro de compressao: nao ocorre em pergunta
        i += 1
        if i + tam > len(dados):
            return None
        try:
            partes.append(dados[i:i + tam].decode("idna"))
        except Exception:
            try:
                partes.append(dados[i:i + tam].decode("ascii", "replace"))
            except Exception:
                return None
        i += tam
    else:
        return None                # excedeu o teto de rotulos

    return ".".join(partes) if partes else None


# ------------------------------------------------------------------------------
# TLS / SNI
# ------------------------------------------------------------------------------
# O ClientHello e uma sequencia de campos de tamanho variavel, cada um precedido
# do proprio tamanho. Nao ha deslocamento fixo para o SNI: e preciso caminhar.
# Por isso o parse vive AQUI e nao no eBPF (D-030) -- caminhar por campos de
# tamanho variavel dentro do verificador do kernel e caro e limitado, e aqui um
# ClientHello cortado simplesmente devolve None.
_TLS_HANDSHAKE = 0x16      # tipo de registro: handshake
_TLS_CLIENT_HELLO = 0x01   # tipo de mensagem de handshake
_EXT_SERVER_NAME = 0x0000  # extensao server_name (RFC 6066)
_SNI_HOST_NAME = 0x00      # unico tipo de nome definido na extensao
# Teto de extensoes percorridas. Mesma razao do teto de rotulos do DNS: o laco
# nunca pode depender do conteudo do pacote.
_MAX_EXTENSOES = 64


# Bytes que um nome de servidor pode conter. Deliberadamente estreito: letras,
# digitos, ponto, hifen e sublinhado (que aparece em nome de servico interno).
# Um SNI legitimo, inclusive internacionalizado, chega aqui ja em punycode
# ("xn--..."), que cabe inteiro neste conjunto.
_HOSTNAME_OK = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")


def _hostname_valido(bruto):
    """
    Se estes bytes podem ser um nome de servidor.

    Existe por causa de um caso achado em teste: com a decodificacao tolerante
    ("replace"), um nome cortado no meio de um byte invalido virava
    "exemplo.co�" -- uma string que PARECE um dominio, entra no laudo como
    fato observado, e nunca cruza com lista de ameaca nenhuma porque nao existe.
    Recusar e melhor: nome ausente e uma resposta honesta, nome inventado nao.
    """
    if not bruto:
        return False
    return all(b in _HOSTNAME_OK for b in bytearray(bruto))


def _u16(dados, i):
    """Inteiro de 16 bits em ordem de rede, ou None se nao couber."""
    if i + 2 > len(dados):
        return None
    return (dados[i] << 8) | dados[i + 1]


def nome_sni(payload, tamanho=None):
    """
    Extrai o SNI (nome do servidor) de um ClientHello TLS.

    Recebe o pedaco BRUTO copiado pela sonda e devolve o nome, ou None quando os
    bytes nao sao um ClientHello legivel ou quando o nome ficou fora do trecho
    copiado. None nao e erro: e a resposta "estes bytes nao carregam nome".

    O SNI viaja EM CLARO, antes de qualquer cifragem: ele existe justamente para
    o servidor saber qual certificado apresentar. Por isso e METADADO ("com
    quem"), nao conteudo, e permanece no escopo depois da D-029.

    Nao ha aqui nenhuma tentativa de decifrar coisa alguma, e nem seria possivel:
    o que vem depois do ClientHello ja esta cifrado e a ferramenta nao o coleta.
    """
    if not payload:
        return None
    dados = bytes(bytearray(payload))
    if tamanho:
        dados = dados[:int(tamanho)]

    # Cabecalho de registro (5) + cabecalho de handshake (4) + versao (2) +
    # random (32) + tamanho do session_id (1) = 44 bytes minimos.
    if len(dados) < 44:
        return None
    if dados[0] != _TLS_HANDSHAKE or dados[1] != 0x03:
        return None            # nao e registro de handshake TLS 1.x
    if dados[5] != _TLS_CLIENT_HELLO:
        return None            # e handshake, mas nao e o Hello do cliente

    # 5 registro + 4 handshake + 2 versao + 32 random.
    i = 43
    id_sessao = dados[i]
    i += 1 + id_sessao

    n = _u16(dados, i)         # lista de cifras
    if n is None:
        return None
    i += 2 + n

    if i >= len(dados):
        return None
    i += 1 + dados[i]          # metodos de compressao

    total_ext = _u16(dados, i)  # tamanho total do bloco de extensoes
    if total_ext is None:
        return None
    i += 2
    fim = min(len(dados), i + total_ext)

    for _ in range(_MAX_EXTENSOES):
        if i + 4 > fim:
            return None        # acabaram as extensoes sem server_name
        tipo = _u16(dados, i)
        tam = _u16(dados, i + 2)
        if tipo is None or tam is None:
            return None
        i += 4
        if tipo != _EXT_SERVER_NAME:
            i += tam
            continue

        # Dentro da extensao: tamanho da lista (2), tipo do nome (1),
        # tamanho do nome (2), o nome.
        j = i + 2
        if j + 3 > len(dados):
            return None
        if dados[j] != _SNI_HOST_NAME:
            return None
        tam_nome = _u16(dados, j + 1)
        if tam_nome is None:
            return None
        j += 3
        if tam_nome <= 0 or j + tam_nome > len(dados):
            # O nome comecou dentro do trecho copiado e terminou fora dele.
            # Devolver o pedaco seria pior que devolver nada: um dominio
            # truncado parece um dominio valido e entra no laudo como fato.
            return None
        bruto = dados[j:j + tam_nome]
        if not _hostname_valido(bruto):
            return None
        return bruto.decode("ascii")
    return None
