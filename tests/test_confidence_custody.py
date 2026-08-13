# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_confidence_custody.py
# DESCRIPTION: Testa os campos de CONFIANCA e CUSTODIA do Finding (contrato de
#              resposta do achado, D-022) e a atribuicao por sinais estruturados
#              no coletor de persistencia.
#
#              Confianca separa fato de indicio de hipotese, para o laudo nao
#              apresentar heuristica como verdade. Custodia declara o que foi de
#              fato preservado do artefato (hoje so metadado). Ambos existem para
#              o laudo dizer a verdade sobre o que tem em maos.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core.findings import (
    Finding, SEV_INFO, SEV_HIGH, SEV_CRITICAL, SRC_PERSISTENCE,
    CONF_CONFIRMED, CONF_PROBABLE, CONF_HEURISTIC,
    CUSTODY_NONE, CUSTODY_METADATA, CUSTODY_HASH, CUSTODY_FULL,
    confidence_label, custody_level, custody_label)
from src.collectors.persistence import _assign_confidence_custody


# ------------------------------------------------------------------------------
# Modelo: campos novos, defaults e serializacao
# ------------------------------------------------------------------------------
def test_finding_accepts_confidence_and_custody():
    """Um achado carrega confianca e custodia quando declarados."""
    f = Finding(title="t", severity=SEV_HIGH, source=SRC_PERSISTENCE,
                confidence=CONF_PROBABLE, custody={"level": CUSTODY_METADATA})
    assert f.confidence == CONF_PROBABLE
    assert f.custody["level"] == CUSTODY_METADATA


def test_confidence_defaults_to_none_when_not_declared():
    """Sem declarar, a confianca e None: a interface trata como 'nao dito'."""
    f = Finding(title="t", severity=SEV_HIGH, source=SRC_PERSISTENCE)
    assert f.confidence is None
    assert f.custody == {}


def test_invalid_confidence_becomes_none():
    """Valor fora do vocabulario nao vira confianca falsa."""
    f = Finding(title="t", severity=SEV_HIGH, source=SRC_PERSISTENCE,
                confidence="muito_certo")
    assert f.confidence is None


def test_invalid_custody_becomes_empty_dict():
    """Custodia so aceita dict; qualquer outra coisa vira vazio."""
    f = Finding(title="t", severity=SEV_HIGH, source=SRC_PERSISTENCE,
                custody="metadata")
    assert f.custody == {}


def test_to_dict_carries_confidence_and_custody():
    """Os campos viajam no payload da captura."""
    d = Finding(title="t", severity=SEV_HIGH, source=SRC_PERSISTENCE,
                confidence=CONF_CONFIRMED,
                custody={"level": CUSTODY_HASH, "sha256": "abc"}).to_dict()
    assert d["confidence"] == CONF_CONFIRMED
    assert d["custody"]["level"] == CUSTODY_HASH
    assert d["custody"]["sha256"] == "abc"


# ------------------------------------------------------------------------------
# Helpers de rotulo/nivel
# ------------------------------------------------------------------------------
def test_confidence_label_is_portuguese_and_safe():
    """Rotulo PT para a interface; desconhecido vira vazio, nao erro."""
    assert confidence_label(CONF_CONFIRMED) == "confirmado"
    assert confidence_label(CONF_PROBABLE) == "provavel"
    assert confidence_label(CONF_HEURISTIC) == "heuristico"
    assert confidence_label(None) == ""
    assert confidence_label("xpto") == ""


def test_custody_level_never_returns_none():
    """Ausencia de custodia e uma resposta (CUSTODY_NONE), nunca None."""
    assert custody_level({"level": CUSTODY_FULL}) == CUSTODY_FULL
    assert custody_level({}) == CUSTODY_NONE
    assert custody_level(None) == CUSTODY_NONE
    assert custody_level({"level": "invalido"}) == CUSTODY_NONE


def test_custody_label_is_portuguese():
    """Rotulo PT do nivel de custodia."""
    assert custody_label({"level": CUSTODY_METADATA}) == "so metadado"
    assert custody_label({}) == "nada preservado"


# ------------------------------------------------------------------------------
# Atribuicao por sinais estruturados no coletor de persistencia
# ------------------------------------------------------------------------------
def _f(severity, evidence, confidence=None, custody=None):
    return Finding(title="x", severity=severity, source=SRC_PERSISTENCE,
                   evidence=evidence, confidence=confidence, custody=custody)


def test_inventory_finding_is_confirmed_without_custody():
    """Um inventario (Info, contagem) e fato confirmado, sem artefato preservado."""
    f = _assign_confidence_custody(_f(SEV_INFO, {"count": 12}))
    assert f.confidence == CONF_CONFIRMED
    assert custody_level(f.custody) == CUSTODY_NONE


def test_reference_finding_is_probable_with_metadata():
    """Achado que extraiu uma referencia concreta e provavel, com metadado."""
    f = _assign_confidence_custody(
        _f(SEV_CRITICAL, {"reference": "/dev/shm/x", "meta": {"uid": 0}}))
    assert f.confidence == CONF_PROBABLE
    assert custody_level(f.custody) == CUSTODY_METADATA


def test_escalated_finding_without_reference_is_heuristic():
    """Achado escalado so por atributo/mtime (sem referencia) e heuristica."""
    f = _assign_confidence_custody(_f(SEV_HIGH, {"meta": {"uid": 0}}))
    assert f.confidence == CONF_HEURISTIC
    assert custody_level(f.custody) == CUSTODY_METADATA


def test_explicit_confidence_is_not_overwritten():
    """O que o coletor declarou explicitamente prevalece sobre a heuristica."""
    f = _assign_confidence_custody(
        _f(SEV_HIGH, {"meta": {}}, confidence=CONF_PROBABLE))
    assert f.confidence == CONF_PROBABLE


def test_explicit_custody_is_not_overwritten():
    """Custodia declarada pelo coletor prevalece."""
    f = _assign_confidence_custody(
        _f(SEV_HIGH, {"meta": {}}, custody={"level": CUSTODY_HASH}))
    assert custody_level(f.custody) == CUSTODY_HASH


# ------------------------------------------------------------------------------
# Fumaca: os coletores de runtime importam e nao quebram
# ------------------------------------------------------------------------------
def test_runtime_collectors_import():
    """hidden e memory_forensics importam com as constantes novas."""
    import src.collectors.hidden as h
    import src.collectors.memory_forensics as m
    assert hasattr(h, "collect_hidden") or hasattr(h, "find_hidden_pids")
    assert hasattr(m, "find_wx_regions")
