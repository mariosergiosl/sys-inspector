# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_server_tls.py
# DESCRIPTION: TLS no modo servidor.
#
#              As capturas ja viajam cifradas com a chave do analista, mas o
#              TLS protege o que esta ao redor: o token de ingestao, os
#              metadados que trafegam em claro (hostname, endereco, contagem de
#              achados) e o painel, que expoe a situacao da frota inteira.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import ssl
import tempfile

import pytest

from src.core.tls import ensure_self_signed_cert

FONTE = os.path.join("src", "controllers", "server_controller.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


def test_nao_existe_caminho_de_texto_claro(codigo):
    """
    [2026-08-20, D-033] INVERSAO DELIBERADA. Este teste dizia o contrario:
    "TLS fica desligado por padrao, porque instalacoes existentes ja apontam
    agentes para HTTP e nao podem parar de reportar por uma atualizacao".

    O argumento era real e o custo dele era maior: o painel servia evidencia
    forense em texto claro, e o agente entregava a captura junto do cabecalho
    Authorization com o token de ingestao da frota. Compatibilidade nao paga
    esse preco numa ferramenta forense.

    A opcao nao foi invertida, foi REMOVIDA: sem ramo de texto claro no codigo,
    nao ha configuracao errada possivel nem degradacao silenciosa depois.
    """
    assert "tls_enabled" not in codigo, (
        "a opcao de desligar o TLS voltou ao servidor")
    assert 'scheme = "http"' not in codigo
    assert "https" in codigo


def test_tls_indisponivel_derruba_o_servidor_em_vez_de_servir_em_claro(codigo):
    """
    O pior desfecho possivel nao e falhar, e falhar PARECENDO que deu certo.

    Se o TLS nao pode ser ativado e o servidor cai para texto claro, todo mundo
    passa a acreditar que a evidencia viaja protegida quando ela nao viaja. Um
    servidor que nao sobe e um problema visivel em trinta segundos; um que serve
    em claro acreditando-se cifrado pode durar meses.
    """
    assert "raise RuntimeError" in codigo
    assert "nao sobe em claro" in codigo


def test_socket_is_wrapped_server_side(codigo):
    """A porta do servidor e envolvida em TLS, nao apenas anunciada."""
    assert "wrap_socket" in codigo
    assert "server_side=True" in codigo


def test_certificate_is_created_when_absent(codigo):
    """Um autoassinado e gerado, para nao exigir PKI antes do primeiro uso."""
    assert "ensure_self_signed_cert" in codigo


def test_tls_failure_does_not_silence_the_server(codigo):
    """
    Se o TLS falhar, o servidor volta a HTTP e avisa. Ficar mudo deixaria a
    frota inteira sem destino sem ninguem perceber.
    """
    inicio = codigo.index("def _wrap_tls")
    trecho = codigo[inicio:inicio + 1500]
    assert "except Exception" in trecho
    assert "serving plain HTTP" in trecho


def test_self_signed_certificate_is_usable():
    """O certificado gerado carrega num contexto TLS real."""
    d = tempfile.mkdtemp()
    cert = os.path.join(d, "cert.pem")
    key = os.path.join(d, "key.pem")
    ensure_self_signed_cert(cert, key)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    assert os.path.exists(cert) and os.path.exists(key)


def test_generated_key_is_not_world_readable():
    """A chave privada do servidor nao pode ser legivel por outros usuarios."""
    d = tempfile.mkdtemp()
    cert = os.path.join(d, "c.pem")
    key = os.path.join(d, "k.pem")
    ensure_self_signed_cert(cert, key)
    if os.name != "nt":
        assert (os.stat(key).st_mode & 0o077) == 0
