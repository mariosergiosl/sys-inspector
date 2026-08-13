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


def test_tls_is_opt_in(codigo):
    """
    TLS fica desligado por padrao: instalacoes existentes ja apontam agentes
    para HTTP e nao podem parar de reportar por uma atualizacao.
    """
    assert "tls_enabled" in codigo
    assert "get('tls_enabled', False)" in codigo


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
