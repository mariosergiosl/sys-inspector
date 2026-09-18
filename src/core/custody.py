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
                 case_id="", operator="", signer=None,
                 key_fingerprint=None, key_event=None):
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
    PARAMETER key_fingerprint: [C-158] impressao digital da chave que assina.
    PARAMETER key_event: [C-158] como essa chave chegou aqui nesta execucao:
        "existing", "migrated" ou "created". "created" e o unico que significa
        descontinuidade da identidade, e por isso precisa estar escrito.
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
        # [C-158] Quem assinou, e por que e esta a chave.
        #
        # A impressao digital vai em TODA captura, e nao so quando muda: assim a
        # troca aparece na propria peca, em vez de so aparecer para quem
        # comparar assinaturas de capturas distintas, que e o trabalho que a
        # parte contraria faz e nos nao.
        #
        # O evento explica a descontinuidade quando ela existe. Uma chave nova
        # nascendo e um fato legitimo (agente novo, primeira execucao); o que
        # nao pode e nascer CALADA, porque ai o mesmo agente aparece assinando
        # com duas chaves sem nada dizendo por que.
        "agent_key_fingerprint": key_fingerprint or None,
        "agent_key_event": key_event or None,
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
    from src.core.crypto import (ensure_agent_identity, agent_key_fingerprint,
                                 load_private_key, sign_bytes,
                                 IDENTITY_CREATED)

    sec = config.get("security", {}) or {}

    # [C-158] A identidade do agente e ESTADO, e mora onde o estado mora: ao
    # lado do banco, junto do `.agent_id`. Antes ela era derivada do diretorio
    # da chave do analista, que e CONFIGURACAO, e configuracao se recria: numa
    # troca de diretorio de implantacao a chave desaparecia e uma nova nascia em
    # silencio, enquanto o UUID, que mora ao lado do banco, sobrevivia.
    #
    # Era essa assimetria o defeito. O numero da identidade durava mais que a
    # identidade, e quem fosse verificar a cadeia via o mesmo agente assinando
    # com duas chaves diferentes, sem explicacao.
    #
    # Um caminho declarado na configuracao continua mandando: quem escolheu onde
    # a chave fica escolheu por algum motivo, e nao cabe a uma atualizacao mudar
    # isso por conta propria.
    # [C-158] De onde vem o diretorio de CONFIGURACAO, que e onde a chave do
    # agente morava antes e de onde ela precisa ser herdada.
    #
    # Derivar isso de `private_key_path` sozinho era um furo, achado ao preparar
    # o laboratorio em 2026-09-18: essa e a chave do ANALISTA, e um agente
    # corretamente enrijecido NAO a possui. Nesses hosts o caminho virava ".",
    # relativo ao diretorio de trabalho do processo, a heranca nao encontrava
    # nada e o agente gerava chave nova. Ou seja, o defeito que este item existe
    # para evitar sobreviveria dentro da propria correcao, e justamente nos
    # agentes mais bem configurados.
    #
    # A ordem abaixo vai do mais especifico ao mais generico, e termina na chave
    # PUBLICA, que todo agente tem por definicao: sem ela ele nao consegue
    # cifrar o que coleta.
    base_conf = "."
    for chave in ("agent_private_key_path", "private_key_path",
                  "public_key_path"):
        caminho = os.path.dirname(sec.get(chave, "") or "")
        if caminho:
            base_conf = caminho
            break

    base_estado = os.path.dirname(getattr(db, "db_path", "") or "") or base_conf

    # O PAR mora junto, sempre.
    #
    # Antes, cada metade era resolvida por conta propria: declarar so a privada
    # deixava a publica no diretorio do banco, o par ficava partido em dois
    # lugares, o codigo concluia que estava incompleto e GERAVA UMA CHAVE NOVA
    # POR CIMA da que o operador tinha declarado. E o mesmo defeito da chave que
    # some no deploy, chegando por outro caminho, e ele destroi a identidade que
    # alguem escolheu preservar. Achado por teste em 2026-09-18.
    #
    # Declarar uma metade fixa o diretorio das duas.
    agent_priv = sec.get("agent_private_key_path")
    agent_pub = sec.get("agent_public_key_path")
    if agent_priv and not agent_pub:
        agent_pub = os.path.join(os.path.dirname(agent_priv),
                                 "agent_public_key.pem")
    elif agent_pub and not agent_priv:
        agent_priv = os.path.join(os.path.dirname(agent_pub),
                                  "agent_private_key.pem")
    elif not agent_priv and not agent_pub:
        agent_priv = os.path.join(base_estado, "agent_private_key.pem")
        agent_pub = os.path.join(base_estado, "agent_public_key.pem")

    # De onde herdar, quando o destino ainda nao existe: o local antigo, dentro
    # do diretorio de configuracao. Herdar e o que impede que a PROPRIA correcao
    # produza a troca de chave que ela existe para evitar.
    legado = (os.path.join(base_conf, "agent_private_key.pem"),
              os.path.join(base_conf, "agent_public_key.pem"))

    signer = None
    key_event = None
    key_fp = None
    try:
        key_event = ensure_agent_identity(agent_priv, agent_pub,
                                          legacy_paths=legado)
        key_fp = agent_key_fingerprint(agent_pub)
        if key_event == IDENTITY_CREATED:
            # Alto por escolha: uma identidade nova rompe a continuidade das
            # assinaturas deste agente. Legitimo na primeira execucao, e sinal
            # de que algo se perdeu em qualquer outra.
            LOG.warning("New agent identity created (%s). Signatures before "
                        "this point were made with a different key; the "
                        "custody record states the change.", key_fp)
        agent_key = load_private_key(agent_priv)

        def _sign(data):
            return sign_bytes(data, agent_key)
        signer = _sign
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
        key_fingerprint=key_fp,
        key_event=key_event,
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
