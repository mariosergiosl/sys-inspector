# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_custody.py
# DESCRIPTION: Testa a cadeia de custodia: digest canonico, assinatura pelo
#              agente e encadeamento entre capturas.
#
#              A cifra protege o sigilo, mas nao prova que a evidencia nao foi
#              alterada, nem de onde veio, nem que nenhuma captura foi retirada
#              da serie. E isso que estes testes cobrem.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

from src.core.custody import (canonical_bytes, compute_digest, build_record,
                              verify_payload, verify_signature, verify_chain,
                              GENESIS)
from src.core.crypto import (ensure_agent_identity, load_private_key,
                             load_public_key, sign_bytes, verify_bytes)


def _payload(n=1):
    return {"processes": {"1": {"cmd": "systemd"}}, "n": n}


def _agent_keys():
    d = tempfile.mkdtemp()
    priv = os.path.join(d, "agent_private_key.pem")
    pub = os.path.join(d, "agent_public_key.pem")
    ensure_agent_identity(priv, pub)
    return priv, pub


# ------------------------------------------------------------------------------
# Digest canonico
# ------------------------------------------------------------------------------
def test_digest_is_reproducible():
    """O mesmo conteudo produz sempre o mesmo digest."""
    assert compute_digest(_payload()) == compute_digest(_payload())


def test_key_order_does_not_change_the_digest():
    """
    Serializacao canonica: a ordem em que as chaves foram inseridas nao pode
    alterar o digest, senao a evidencia pareceria adulterada sem ter mudado.
    """
    a = {"x": 1, "y": 2}
    b = {"y": 2, "x": 1}
    assert compute_digest(a) == compute_digest(b)


def test_any_change_changes_the_digest():
    """Qualquer alteracao no conteudo muda o digest."""
    assert compute_digest(_payload(1)) != compute_digest(_payload(2))


def test_canonical_bytes_are_deterministic():
    """Os bytes canonicos nao variam entre execucoes."""
    assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})


def test_digest_survives_the_json_roundtrip():
    """
    Regressao real: o digest e calculado sobre o conteudo em memoria, mas o
    analista so consegue recalcula-lo depois de descriptografar, ou seja, apos
    o conteudo passar por JSON. Em memoria as chaves de processos sao inteiros
    e, ordenadas, dao 1, 2, 10; depois do JSON viram texto e dao "1", "10",
    "2". Sem normalizar, a evidencia intacta pareceria adulterada.
    """
    import json as _json
    payload = {"processes": {1: {"cmd": "a"}, 2: {"cmd": "b"}, 10: {"cmd": "c"}}}
    recuperado = _json.loads(_json.dumps(payload))
    assert compute_digest(payload) == compute_digest(recuperado)


def test_verify_payload_after_roundtrip():
    """O conteudo recuperado confere com o registro feito na coleta."""
    import json as _json
    payload = {"processes": {1: {"cmd": "x"}, 20: {"cmd": "y"}}}
    rec = build_record(payload, "a", "v")
    assert verify_payload(_json.loads(_json.dumps(payload)), rec) is True


# ------------------------------------------------------------------------------
# Registro e verificacao
# ------------------------------------------------------------------------------
def test_record_carries_custody_metadata():
    """O registro identifica agente, versao, momento e host da coleta."""
    rec = build_record(_payload(), "agent-1", "0.91.0")
    for field in ("digest", "previous_digest", "agent_uuid",
                  "collector_version", "captured_at_utc", "boot_id",
                  "machine_id", "hostname", "case_id", "operator"):
        assert field in rec


def test_first_record_links_to_genesis():
    """Sem antecessor, o elo anterior e o marco inicial."""
    assert build_record(_payload(), "a", "v")["previous_digest"] == GENESIS


def test_case_and_operator_are_recorded():
    """Numero do caso e responsavel pela coleta entram na custodia."""
    rec = build_record(_payload(), "a", "v", case_id="2026/001",
                       operator="Mario Luz")
    assert rec["case_id"] == "2026/001"
    assert rec["operator"] == "Mario Luz"


def test_untouched_payload_verifies():
    """Conteudo intacto confere com o digest registrado."""
    payload = _payload()
    assert verify_payload(payload, build_record(payload, "a", "v")) is True


def test_tampered_payload_is_detected():
    """Alterar o conteudo depois da coleta e detectado."""
    payload = _payload()
    rec = build_record(payload, "a", "v")
    payload["processes"]["1"]["cmd"] = "evil"
    assert verify_payload(payload, rec) is False


# ------------------------------------------------------------------------------
# Assinatura
# ------------------------------------------------------------------------------
def test_agent_identity_is_created_once():
    """O par de chaves do agente e criado na primeira execucao e reutilizado."""
    priv, pub = _agent_keys()
    assert os.path.exists(priv) and os.path.exists(pub)
    before = open(priv, "rb").read()
    ensure_agent_identity(priv, pub)
    assert open(priv, "rb").read() == before


def test_signature_roundtrip():
    """Assinatura feita pelo agente confere com a chave publica dele."""
    priv, pub = _agent_keys()
    key = load_private_key(priv)
    data = b"evidence"
    assert verify_bytes(data, sign_bytes(data, key), load_public_key(pub)) is True


def test_signature_fails_for_modified_data():
    """Assinatura nao confere se os dados mudaram."""
    priv, pub = _agent_keys()
    sig = sign_bytes(b"original", load_private_key(priv))
    assert verify_bytes(b"modified", sig, load_public_key(pub)) is False


def test_signed_record_verifies():
    """O registro assinado passa na verificacao com a chave do agente."""
    priv, pub = _agent_keys()
    key = load_private_key(priv)
    rec = build_record(_payload(), "a", "v", signer=lambda d: sign_bytes(d, key))
    assert rec["signature"]
    pubkey = load_public_key(pub)
    assert verify_signature(rec, lambda d, s: verify_bytes(d, s, pubkey)) is True


def test_tampered_metadata_breaks_the_signature():
    """
    A assinatura cobre os METADADOS tambem: mudar o operador ou o caso depois
    da coleta invalida o registro.
    """
    priv, pub = _agent_keys()
    key = load_private_key(priv)
    rec = build_record(_payload(), "a", "v", operator="Mario",
                       signer=lambda d: sign_bytes(d, key))
    rec["operator"] = "Outro"
    pubkey = load_public_key(pub)
    assert verify_signature(rec, lambda d, s: verify_bytes(d, s, pubkey)) is False


def test_unsigned_record_reports_none():
    """Sem assinatura, a verificacao informa ausencia em vez de falha."""
    rec = build_record(_payload(), "a", "v")
    assert verify_signature(rec, lambda d, s: True) is None


# ------------------------------------------------------------------------------
# Encadeamento
# ------------------------------------------------------------------------------
def _chain(size=3):
    records = []
    prev = None
    for i in range(size):
        rec = build_record(_payload(i), "a", "v", previous_digest=prev)
        records.append(rec)
        prev = rec["digest"]
    return records


def test_intact_chain_verifies():
    """Serie completa e em ordem passa na verificacao."""
    ok, problems = verify_chain(_chain())
    assert ok is True
    assert problems == []


def test_removed_capture_breaks_the_chain():
    """Retirar uma captura do meio quebra o elo e o ponto e reportado."""
    chain = _chain(4)
    del chain[1]
    ok, problems = verify_chain(chain)
    assert ok is False
    assert problems


def test_reordered_captures_break_the_chain():
    """Reordenar capturas e detectado."""
    chain = _chain(3)
    chain[1], chain[2] = chain[2], chain[1]
    assert verify_chain(chain)[0] is False


def test_empty_chain_is_valid():
    """Nenhuma captura ainda: nada a contestar."""
    assert verify_chain([]) == (True, [])
