# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_compression.py
# DESCRIPTION: Compressao da captura antes da cifragem.
#
#              A ordem nao e escolha de estilo. Dado cifrado e indistinguivel de
#              aleatorio e nao comprime nada, entao comprimir depois seria
#              trabalho jogado fora. Medido em captura real: 180 KB -> 14 KB,
#              porque 93% do payload e arvore de processos, texto com enorme
#              repeticao de caminhos e nomes.
#
#              A garantia que mais importa aqui e a de leitura: material forense
#              coletado antes desta mudanca PRECISA continuar abrindo. Um laudo
#              que nao pode mais ser lido nao vale nada.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import json
import zlib

import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from src.core.crypto import (encrypt_data, decrypt_data, MAGIC_COMPRESSED,
                             COMPRESSION_LEVEL)


@pytest.fixture(scope="module")
def par():
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return chave, chave.public_key()


def _payload_realista(n=300):
    """
    Imita a captura real: muitos processos com caminhos repetidos.

    As chaves sao texto de proposito. O PID e int na arvore, mas o JSON so
    admite chave textual, entao toda captura ja atravessa essa conversao antes
    de ser cifrada; e o mesmo motivo pelo qual a cadeia de custodia normaliza o
    payload antes de calcular o digest.
    """
    return {"processes": dict(
        (str(i), {"pid": i, "ppid": 1, "cmd": "/usr/lib/systemd/systemd --user",
             "exe_path": "/usr/lib/systemd/systemd", "username": "root",
             "context_tags": ["UNSAFE"], "anomaly_score": 3})
        for i in range(n))}


# ------------------------------------------------------------------------------
# O CICLO COMPLETO
# ------------------------------------------------------------------------------
def test_a_compressed_capture_reads_back_identical(par):
    """O conteudo tem que voltar byte a byte: e evidencia, nao cache."""
    privada, publica = par
    dados = _payload_realista()

    assert decrypt_data(encrypt_data(dados, publica), privada) == dados


def test_compression_actually_shrinks_a_real_capture(par):
    """Sem ganho real nao haveria motivo para assumir a ressalva do CRIME."""
    privada, publica = par
    dados = _payload_realista()

    com = len(encrypt_data(dados, publica, compress=True)["ciphertext"])
    sem = len(encrypt_data(dados, publica, compress=False)["ciphertext"])

    assert com < sem / 5      # medido em campo: ~13x


def test_compression_can_be_switched_off(par):
    """
    Comprimir antes de cifrar expoe em tese a classe CRIME/BREACH. Nao se
    aplica ao nosso modelo de ameaca, mas a premissa pode mudar, e desligar tem
    que ser possivel sem tocar em mais nada.
    """
    privada, publica = par
    dados = _payload_realista(10)

    assert decrypt_data(encrypt_data(dados, publica, compress=False),
                        privada) == dados


# ------------------------------------------------------------------------------
# COMPATIBILIDADE COM O QUE JA FOI COLETADO
# ------------------------------------------------------------------------------
def test_an_old_uncompressed_capture_still_opens(par):
    """
    Capturas anteriores a esta versao nao tem o marcador. Se deixassem de abrir,
    todo o material ja coletado viraria lixo, que e o pior desfecho possivel
    para uma ferramenta forense.
    """
    privada, publica = par
    dados = {"processes": {}, "findings": []}

    antigo = encrypt_data(dados, publica, compress=False)
    assert decrypt_data(antigo, privada) == dados


def test_the_marker_does_not_look_like_json():
    """
    A deteccao e pelo prefixo. Um marcador que pudesse iniciar um JSON valido
    tornaria ambigua a distincao entre formato novo e antigo.
    """
    assert not MAGIC_COMPRESSED.startswith(b"{")
    assert not MAGIC_COMPRESSED.startswith(b"[")


def test_a_tiny_payload_is_not_made_bigger(par):
    """
    O cabecalho do zlib pode superar o ganho num payload minusculo. Guardar
    mais bytes do que o original seria o oposto do objetivo.
    """
    privada, publica = par
    minusculo = {"a": 1}

    com = len(encrypt_data(minusculo, publica, compress=True)["ciphertext"])
    sem = len(encrypt_data(minusculo, publica, compress=False)["ciphertext"])
    assert com <= sem


def test_compression_level_favours_the_inspected_host():
    """
    O nivel maximo custa muita CPU para ganhar pouco tamanho, e essa CPU e
    gasta no host sob investigacao, onde a ferramenta deve pesar o minimo.
    """
    assert 1 <= COMPRESSION_LEVEL <= 6


def test_corrupted_payload_fails_loudly(par):
    """Dado corrompido nao pode virar dicionario vazio silenciosamente."""
    privada, publica = par
    pacote = encrypt_data(_payload_realista(5), publica)
    pacote["ciphertext"] = pacote["ciphertext"][:-8] + "AAAAAAAA"

    assert decrypt_data(pacote, privada) is None
