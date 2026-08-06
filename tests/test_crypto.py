# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_crypto.py
# DESCRIPTION: Testa o roundtrip de criptografia hibrida (RSA + AES-GCM):
#              provisiona um par de chaves, cifra um payload e confere que a
#              descriptografia recupera o dado original.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

from src.core.crypto import (ensure_crypto_environment, load_public_key,
                             load_private_key, encrypt_data, decrypt_data)


def test_encrypt_decrypt_roundtrip():
    """encrypt_data seguido de decrypt_data recupera o payload original."""
    d = tempfile.mkdtemp()
    pub_path = os.path.join(d, "public_key.pem")
    priv_path = os.path.join(d, "private_key.pem")
    ensure_crypto_environment(pub_path, priv_path)

    payload = {
        "processes": {"1": {"cmd": "systemd", "anomaly_score": 64}},
        "count": 42,
        "list": [1, 2, 3],
        "nested": {"a": {"b": "c"}},
    }

    bundle = encrypt_data(payload, load_public_key(pub_path))
    # O bundle cifrado nao pode ser igual ao payload em claro.
    assert bundle != payload

    recovered = decrypt_data(bundle, load_private_key(priv_path))
    assert recovered == payload


def test_wrong_key_does_not_recover_payload():
    """Uma chave privada diferente nao recupera o payload (integridade)."""
    d1 = tempfile.mkdtemp()
    d2 = tempfile.mkdtemp()
    ensure_crypto_environment(os.path.join(d1, "public_key.pem"),
                              os.path.join(d1, "private_key.pem"))
    ensure_crypto_environment(os.path.join(d2, "public_key.pem"),
                              os.path.join(d2, "private_key.pem"))

    bundle = encrypt_data({"secret": "x"},
                          load_public_key(os.path.join(d1, "public_key.pem")))
    wrong = load_private_key(os.path.join(d2, "private_key.pem"))
    # Chave errada nao deve reproduzir o dado original (retorna None ou difere).
    assert decrypt_data(bundle, wrong) != {"secret": "x"}
