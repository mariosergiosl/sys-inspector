# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/custody.py
# DESCRIPTION: Chain of custody for captures: what makes the evidence hold up,
#              beyond keeping it secret.
#
# WHY:         Encryption protects confidentiality. It does not, by itself,
#              prove that evidence was not altered, that it came from a given
#              collector, or that a capture was not quietly removed from a
#              series. Those are integrity, authenticity and completeness, and
#              they are what a challenge in court actually targets.
#
# HOW:         Each capture gets a canonical SHA-256 digest, a signature made
#              with the agent's own key, and a reference to the digest of the
#              previous capture. Linking each record to the one before turns the
#              series into a chain: removing or reordering a capture breaks it
#              and the break is detectable.
#
# LIMIT:       The timestamp here is the host clock, which an intruder with root
#              can change. A trusted timestamp (RFC 3161) from an external
#              authority requires network access to a TSA and is offered as an
#              optional step, not assumed.
#
# NOTES:       Compatible with Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import json
import time

# A versao do coletor entra na cadeia de custodia; vem da FONTE UNICA para o
# carimbo forense nao divergir do resto do produto (D-018).
from src.version import __version__
import base64
import hashlib
import logging
import platform

LOG = logging.getLogger("Custody")

# Digest de um encadeamento que ainda nao tem antecessor (primeira captura).
GENESIS = "0" * 64


def canonical_bytes(payload):
    """
    Serializa o conteudo de forma canonica e reproduzivel.

    Duas execucoes sobre o mesmo dado precisam produzir exatamente os mesmos
    bytes, senao o digest muda sem que a evidencia tenha mudado. Chaves
    ordenadas, sem espacos supérfluos e sem escapar caracteres nao-ASCII.

    O conteudo passa antes por uma normalizacao em JSON, o mesmo caminho que a
    evidencia percorre ao ser cifrada e recuperada. Sem isso o digest calculado
    na coleta nao bateria com o calculado apos descriptografar: em memoria as
    chaves de processos sao inteiros e, ordenadas, dao 1, 2, 10; depois do JSON
    viram texto e dao "1", "10", "2". Mesma evidencia, bytes diferentes.
    """
    normalized = json.loads(json.dumps(payload, default=str))
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def compute_digest(payload):
    """SHA-256 do conteudo canonico, em hexadecimal."""
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _boot_id():
    """
    Identificador do boot atual. Amarra a captura a uma sessao especifica do
    sistema: se o host reiniciou, capturas de antes e depois sao distinguiveis
    mesmo com o relogio adulterado.
    """
    try:
        with open("/proc/sys/kernel/random/boot_id", "r") as handle:
            return handle.read().strip()
    except Exception:
        return ""


def _machine_id():
    """Identidade estavel do host, independente de hostname (que muda)."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, "r") as handle:
                value = handle.read().strip()
                if value:
                    return value
        except Exception:
            continue
    return ""


def build_record(payload, agent_uuid, collector_version, previous_digest=None,
                 case_id="", operator="", signer=None):
    """
    Monta o registro de custodia de uma captura.

    PARAMETER payload: o conteudo capturado (dict), antes de cifrar.
    PARAMETER agent_uuid: identidade do agente que coletou.
    PARAMETER collector_version: versao do coletor, para reproduzir a analise.
    PARAMETER previous_digest: digest da captura anterior deste agente; None na
        primeira, que usa GENESIS.
    PARAMETER case_id: numero do caso/procedimento, quando informado.
    PARAMETER operator: quem conduziu a coleta.
    PARAMETER signer: funcao que recebe bytes e devolve assinatura em bytes;
        None produz um registro sem assinatura (ainda com digest e cadeia).
    """
    digest = compute_digest(payload)
    prev = previous_digest or GENESIS

    record = {
        "digest": digest,
        "previous_digest": prev,
        "algorithm": "sha256",
        "agent_uuid": agent_uuid,
        "collector_version": collector_version,
        "captured_at": time.time(),
        "captured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "boot_id": _boot_id(),
        "machine_id": _machine_id(),
        "hostname": platform.node(),
        "case_id": case_id or "",
        "operator": operator or "",
        "timestamp_authority": None,  # reservado para carimbo RFC 3161
    }

    # A assinatura cobre o registro inteiro, nao apenas o digest do conteudo:
    # assim os metadados de custodia (quem, quando, qual cadeia) tambem ficam
    # protegidos contra alteracao.
    if signer:
        try:
            signature = signer(canonical_bytes(record))
            record["signature"] = base64.b64encode(signature).decode("ascii")
            record["signature_algorithm"] = "rsa-pss-sha256"
        except Exception as exc:
            LOG.error("Failed to sign custody record: %s", exc)
            record["signature"] = None
    else:
        record["signature"] = None

    return record


def build_for_capture(db, config, payload, collector_version=None):
    """
    Monta o registro de custodia de uma captura, resolvendo a identidade do
    agente e o elo anterior a partir do banco e da configuracao.

    Compartilhado por todos os modos que coletam (snapshot e daemon), para que
    uma captura feita por um agente em campo tenha exatamente a mesma cadeia de
    custodia de uma coleta pontual: perder a custodia justamente nas capturas
    automaticas seria o pior dos casos.

    Nunca levanta: falhar aqui nao pode custar a captura, entao a coleta segue
    sem assinatura e o problema fica registrado.
    """
    # Sem versao explicita, carimba a versao real do produto (fonte unica).
    if collector_version is None:
        collector_version = __version__

    # Importado aqui para manter este modulo utilizavel sem o backend de cripto.
    from src.core.crypto import (ensure_agent_identity, load_private_key,
                                 sign_bytes)

    sec = config.get("security", {}) or {}
    base = os.path.dirname(sec.get("private_key_path", "") or "") or "."
    agent_priv = sec.get("agent_private_key_path",
                         os.path.join(base, "agent_private_key.pem"))
    agent_pub = sec.get("agent_public_key_path",
                        os.path.join(base, "agent_public_key.pem"))

    signer = None
    try:
        ensure_agent_identity(agent_priv, agent_pub)
        agent_key = load_private_key(agent_priv)
        signer = lambda data: sign_bytes(data, agent_key)
    except Exception as exc:
        LOG.error("Agent identity unavailable, capture will be unsigned: %s", exc)

    agent_uuid = getattr(db, "agent_id", "local")
    try:
        previous = db.get_last_digest(agent_uuid)
    except Exception:
        previous = None

    forensic = config.get("forensics", {}) or {}
    return build_record(
        payload,
        agent_uuid=agent_uuid,
        collector_version=collector_version,
        previous_digest=previous,
        case_id=forensic.get("case_id", ""),
        operator=forensic.get("operator", ""),
        signer=signer,
    )


def verify_payload(payload, record):
    """
    Confere se o conteudo ainda corresponde ao digest registrado.
    Retorna True se integro, False se foi alterado.
    """
    if not record or "digest" not in record:
        return False
    return compute_digest(payload) == record["digest"]


def verify_signature(record, verifier):
    """
    Confere a assinatura do registro.

    PARAMETER verifier: funcao (bytes, bytes) -> bool, recebendo o conteudo
        assinado e a assinatura.
    Retorna None quando nao ha assinatura para verificar.
    """
    if not record or not record.get("signature"):
        return None
    unsigned = {k: v for k, v in record.items()
                if k not in ("signature", "signature_algorithm")}
    try:
        signature = base64.b64decode(record["signature"])
    except Exception:
        return False
    return bool(verifier(canonical_bytes(unsigned), signature))


def verify_chain(records):
    """
    Valida uma serie de registros em ordem cronologica.

    Cada registro precisa apontar para o digest do anterior. Se uma captura for
    removida, reordenada ou substituida, o elo quebra e o indice do ponto de
    ruptura e reportado.

    Retorna (ok, problemas), onde problemas descreve cada quebra encontrada.
    """
    problems = []
    if not records:
        return True, problems

    for index, record in enumerate(records):
        expected = GENESIS if index == 0 else records[index - 1].get("digest")
        actual = record.get("previous_digest")
        if actual != expected:
            problems.append(
                "record %d does not link to the previous capture "
                "(expected previous_digest %s, found %s)"
                % (index, expected, actual))

    return (not problems), problems
