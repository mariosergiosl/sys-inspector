# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_agent_key_safety.py
# DESCRIPTION: Protege a chave publica do analista contra sobrescrita pelo
#              agente, e garante que a frota consiga identificar cada host.
#
#              Regressao real, encontrada no primeiro teste distribuido: o
#              agente que possuia SOMENTE a chave publica do analista (a
#              implantacao correta em campo) tinha suas chaves "auto
#              provisionadas", gerando um par proprio e substituindo a chave do
#              analista. As capturas seguintes ficaram ilegiveis no servidor,
#              sem qualquer aviso. Numa pericia isso e perda silenciosa de
#              prova.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

from src.core.crypto import (ensure_crypto_environment, load_public_key,
                             encrypt_data, decrypt_data, load_private_key)


def _analyst_keys():
    """Par do analista, como seria gerado na estacao de analise."""
    d = tempfile.mkdtemp()
    pub = os.path.join(d, "public_key.pem")
    priv = os.path.join(d, "private_key.pem")
    ensure_crypto_environment(pub, priv)
    return pub, priv


def _agent_dir_with_public_only(analyst_pub):
    """Agente em campo: recebe a chave publica e NAO possui a privada."""
    d = tempfile.mkdtemp()
    agent_pub = os.path.join(d, "public_key.pem")
    with open(analyst_pub, "rb") as origem, open(agent_pub, "wb") as destino:
        destino.write(origem.read())
    return d, agent_pub, os.path.join(d, "private_key.pem")


def test_agent_public_key_is_not_replaced():
    """
    Com apenas a chave publica presente, nada e regenerado: essa e a
    implantacao correta de um agente, nao um ambiente incompleto.
    """
    analyst_pub, _ = _analyst_keys()
    _, agent_pub, agent_priv = _agent_dir_with_public_only(analyst_pub)

    antes = open(agent_pub, "rb").read()
    ensure_crypto_environment(agent_pub, agent_priv)

    assert open(agent_pub, "rb").read() == antes, "a chave do analista foi trocada"
    assert not os.path.exists(agent_priv), "o agente nao pode ganhar chave privada"


def test_capture_stays_readable_by_the_analyst():
    """
    O teste que importa de verdade: apos o agente iniciar, o que ele cifra
    continua legivel com a chave privada do analista.
    """
    analyst_pub, analyst_priv = _analyst_keys()
    _, agent_pub, agent_priv = _agent_dir_with_public_only(analyst_pub)

    ensure_crypto_environment(agent_pub, agent_priv)

    payload = {"processes": {"1": {"cmd": "systemd"}}}
    bundle = encrypt_data(payload, load_public_key(agent_pub))
    assert decrypt_data(bundle, load_private_key(analyst_priv)) == payload


def test_keys_are_provisioned_when_nothing_exists():
    """Numa maquina virgem o par ainda e criado, como antes."""
    d = tempfile.mkdtemp()
    pub = os.path.join(d, "public_key.pem")
    priv = os.path.join(d, "private_key.pem")
    ensure_crypto_environment(pub, priv)
    assert os.path.exists(pub) and os.path.exists(priv)


def test_existing_pair_is_left_alone():
    """Um par ja existente nunca e regenerado."""
    pub, priv = _analyst_keys()
    antes = open(pub, "rb").read()
    ensure_crypto_environment(pub, priv)
    assert open(pub, "rb").read() == antes
