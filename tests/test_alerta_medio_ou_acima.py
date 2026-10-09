# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_alerta_medio_ou_acima.py
# DESCRIPTION: Trava a regra unica de alerta de uma captura (F-261).
#
# WHY:         Ate 2026-10-09 `is_alert` era `score > 0`: qualquer bit de sinal,
#              inclusive Info e Low, que todo host ativo levanta o tempo todo.
#              Medido nas tres VMs: 45 de 45 capturas marcadas como alerta. O
#              calendario de capturas (F-259) usa essa marca para destacar o dia,
#              e uma marca que sempre acende nao destaca nada.
#
#              Decisao do Mario: achado comum nao gera alerta, separado pela
#              NATUREZA (Info e Low), nunca pela frequencia.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile
import time

import pytest

from src.core import risk
from src.core.database import DatabaseManager, eh_alerta


def _bit(chave):
    """Bit de um sinal pelo nome, lido do registro (nunca numero solto)."""
    for bit, nome, _rotulo, _sev, _txt in risk.SINAIS:
        if nome == chave:
            return bit
    raise KeyError(chave)


def _bits_de(nivel):
    return [b for b, _n, _r, sev, _t in risk.SINAIS if sev == nivel]


def test_so_info_e_low_nao_e_alerta():
    """REPROVA A VERSAO ANTERIOR: net_error (Low) acendia o alerta."""
    score = _bit("net_error") | _bit("dns_query") | _bit("cred_change")
    assert not eh_alerta(score, {"Info": 3, "Low": 12, "Medium": 0,
                                 "High": 0, "Critical": 0})


def test_achado_medio_ou_acima_e_alerta():
    for nivel in ("Medium", "High", "Critical"):
        assert eh_alerta(0, {nivel: 1}), nivel


def test_sinal_de_processo_medio_ou_acima_e_alerta():
    for nivel in (risk.SEV_MEDIUM, risk.SEV_HIGH, risk.SEV_CRITICAL):
        for bit in _bits_de(nivel):
            assert eh_alerta(bit, None), (nivel, bit)


def test_sem_nada_nao_e_alerta():
    assert not eh_alerta(0, None)
    assert not eh_alerta(None, {})


def test_resumo_malformado_nao_quebra_a_gravacao():
    assert not eh_alerta(0, {"Medium": "x", "High": None})


@pytest.fixture
def db():
    d = tempfile.mkdtemp()
    return DatabaseManager(db_path=os.path.join(d, "t.db"), max_snapshots=100)


def test_a_gravacao_usa_a_regra(db):
    """REPROVA A VERSAO ANTERIOR: a coluna gravada vinha de score > 0."""
    db.insert_snapshot({"x": 1}, agent_uuid="a",
                       metrics={"score": _bit("net_error")},
                       findings_summary={"Low": 5})
    time.sleep(0.02)
    db.insert_snapshot({"x": 2}, agent_uuid="a", metrics={"score": 0},
                       findings_summary={"Critical": 1})
    linhas = db.get_history(0, time.time() + 10)
    assert [r["is_alert"] for r in linhas] == [1, 0]
