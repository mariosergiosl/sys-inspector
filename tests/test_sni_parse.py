# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_sni_parse.py
# DESCRIPTION: Guarda a extracao do SNI do ClientHello TLS (C-022).
#
# WHY:         O DNS entrega o nome quando o processo RESOLVE. Isso deixa dois
#              buracos: quem resolve por cache, por endereco fixo ou por DoH
#              nunca gera consulta, e num host com varios servicos nao ha como
#              amarrar a resolucao que aconteceu antes ao fluxo que aconteceu
#              depois. O SNI viaja dentro do proprio ClientHello, no socket da
#              conexao, e por isso e o nome dito PELA conexao.
#
#              Como no DNS, o parse vive aqui e nao no eBPF (D-030): o
#              ClientHello e um encadeamento de campos de tamanho variavel, e
#              caminhar por ele dentro do verificador do kernel e caro.
#
#              O caso que estes testes mais protegem e o TRUNCADO. A sonda copia
#              um pedaco limitado do envio; um nome que comeca dentro do pedaco e
#              termina fora dele produziria um dominio que PARECE valido e entra
#              no laudo como fato. Nome cortado tem que virar None.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import struct

from src.core.eventfmt import nome_sni


def _client_hello(nome, com_sni=True, extensoes_antes=0, tipo_registro=0x16,
                  tipo_handshake=0x01, id_sessao=32):
    """
    Monta um ClientHello TLS como um cliente real envia.

    PARAMETER nome: dominio que vai na extensao server_name.
    PARAMETER extensoes_antes: quantas extensoes irrelevantes vem ANTES do SNI.
              Serve para provar que o parser CAMINHA pelas extensoes em vez de
              supor que server_name e sempre a primeira.
    """
    exts = b""
    for i in range(extensoes_antes):
        # Extensao qualquer, com carga de 4 bytes, so para ocupar espaco.
        exts += struct.pack(">HH", 0x1000 + i, 4) + b"\x00\x00\x00\x00"

    if com_sni:
        alvo = nome.encode("ascii")
        lista = b"\x00" + struct.pack(">H", len(alvo)) + alvo   # tipo host_name
        corpo_sni = struct.pack(">H", len(lista)) + lista
        exts += struct.pack(">HH", 0x0000, len(corpo_sni)) + corpo_sni

    corpo = b"\x03\x03"                       # versao legada (TLS 1.2)
    corpo += b"\xAA" * 32                     # random
    corpo += bytes(bytearray([id_sessao])) + b"\xBB" * id_sessao
    corpo += struct.pack(">H", 4) + b"\x13\x01\x13\x02"   # 2 cifras
    corpo += b"\x01\x00"                      # 1 metodo de compressao (null)
    corpo += struct.pack(">H", len(exts)) + exts

    handshake = (bytes(bytearray([tipo_handshake]))
                 + struct.pack(">I", len(corpo))[1:] + corpo)   # tamanho de 3 bytes
    registro = (bytes(bytearray([tipo_registro])) + b"\x03\x01"
                + struct.pack(">H", len(handshake)) + handshake)
    return registro


# ------------------------------------------------------------------------------
# O CAMINHO FELIZ
# ------------------------------------------------------------------------------
def test_client_hello_simples_entrega_o_nome():
    assert nome_sni(_client_hello("exemplo.com")) == "exemplo.com"


def test_subdominio_e_preservado_inteiro():
    """Mesma razao do DNS: o canal de C2 costuma estar no subdominio."""
    assert nome_sni(_client_hello("a.b.evil.example")) == "a.b.evil.example"


def test_sni_e_encontrado_mesmo_quando_nao_e_a_primeira_extensao():
    """
    Cliente nenhum garante a ordem das extensoes. Um parser que supusesse
    server_name em primeiro lugar funcionaria com openssl e falharia com um
    navegador, que e justamente o trafego mais interessante de nomear.
    """
    hello = _client_hello("tardia.example", extensoes_antes=5)
    assert nome_sni(hello) == "tardia.example"


def test_session_id_vazio_tambem_e_lido():
    """TLS 1.3 manda 32 bytes de session_id legado, mas zero e valido."""
    assert nome_sni(_client_hello("curto.example", id_sessao=0)) == "curto.example"


# ------------------------------------------------------------------------------
# O QUE NAO E CLIENTHELLO
# ------------------------------------------------------------------------------
def test_registro_que_nao_e_handshake_e_ignorado():
    """Dado ja cifrado (tipo 0x17) e a maior parte do trafego de uma conexao."""
    assert nome_sni(_client_hello("x.example", tipo_registro=0x17)) is None


def test_handshake_que_nao_e_client_hello_e_ignorado():
    """ServerHello e os demais passos do handshake nao carregam SNI."""
    assert nome_sni(_client_hello("x.example", tipo_handshake=0x02)) is None


def test_client_hello_sem_extensao_server_name():
    """Conexao por IP nao manda SNI. Ausencia e resposta, nao falha."""
    assert nome_sni(_client_hello("x.example", com_sni=False)) is None


def test_bytes_vazios_ou_curtos_demais():
    assert nome_sni(b"") is None
    assert nome_sni(None) is None
    assert nome_sni(b"\x16\x03\x01\x00\x10") is None


# ------------------------------------------------------------------------------
# TRUNCAGEM: O CASO QUE MAIS IMPORTA
# ------------------------------------------------------------------------------
def test_nome_cortado_ao_meio_devolve_none_em_vez_de_dominio_falso():
    """
    O defeito que este teste impede e o pior tipo: silencioso e plausivel.

    A sonda copia um pedaco limitado do envio. Se o nome comeca dentro do pedaco
    e termina fora, devolver o prefixo produziria "evil.exa" -- que parece um
    dominio e entraria no laudo como fato observado. Melhor nao dizer nada.
    """
    hello = _client_hello("dominio-bem-longo.exemplo.com")
    cortado = hello[:len(hello) - 8]
    assert nome_sni(cortado) is None


def test_tamanho_declarado_menor_que_o_buffer_e_respeitado():
    """
    A sonda entrega buffer de tamanho fixo e o tamanho REAL em separado. Ler
    alem do tamanho declarado seria ler lixo da area nao preenchida.
    """
    hello = _client_hello("exemplo.com")
    buffer_cheio = hello + b"\x00" * 200
    assert nome_sni(buffer_cheio, len(hello)) == "exemplo.com"


def test_nome_com_byte_invalido_nao_vira_dominio_plausivel():
    """
    Achado ao escrever este arquivo, e a razao de o parser recusar em vez de
    decodificar com tolerancia: corrompendo o ULTIMO byte do nome, a versao
    original devolvia "exemplo.co�". Isso passa por dominio numa leitura
    rapida, entra no laudo como fato, e nao existe. Um nome que a ferramenta
    nao consegue ler tem que sumir, nao virar quase-nome.
    """
    hello = bytearray(_client_hello("exemplo.com"))
    hello[-1] = 0xFF
    assert nome_sni(bytes(hello)) is None


def test_extensao_mentindo_o_proprio_tamanho_nao_trava_nem_estoura():
    """Pacote malformado nao pode virar excecao subindo para o laco de eventos."""
    hello = bytearray(_client_hello("exemplo.com"))
    # Corrompe o tamanho DECLARADO do bloco de extensoes para um valor enorme:
    # os dois bytes que precedem o bloco, logo apos os metodos de compressao.
    i = 43 + 1 + 32 + 2 + 4 + 2
    hello[i] = 0xFF
    # O parser LIMITA o bloco pelo tamanho real dos bytes que recebeu, entao um
    # tamanho declarado absurdo nao o leva para fora do buffer: ele ou acha a
    # extensao verdadeira, ou desiste. O que nao pode e levantar excecao dentro
    # do laco de eventos do agente, nem devolver um nome que nao estava ali.
    assert nome_sni(bytes(hello)) in (None, "exemplo.com")


def test_lista_de_cifras_gigante_nao_leva_o_parser_para_fora_do_buffer():
    hello = bytearray(_client_hello("exemplo.com"))
    hello[43 + 1 + 32] = 0xFF      # primeiro byte do tamanho da lista de cifras
    assert nome_sni(bytes(hello)) is None
