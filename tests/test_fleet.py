# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_fleet.py
# DESCRIPTION: Testa a triagem da frota: o estado de risco de cada agente
#              montado apenas com colunas em claro.
#
#              Com dezenas ou centenas de hosts, o analista precisa responder
#              "qual esta pior?" sem descriptografar captura por captura, o que
#              seria caro e exporia conteudo sem necessidade.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import time
import tempfile

import pytest

from src.core.database import DatabaseManager


@pytest.fixture
def db():
    d = tempfile.mkdtemp()
    return DatabaseManager(db_path=os.path.join(d, "fleet.db"))


def _capture(db, agent, score=0, findings=None):
    return db.insert_snapshot({"x": 1}, agent_uuid=agent,
                              metrics={"score": score, "cpu": 1, "mem": 10, "pids": 5},
                              findings_summary=findings)


# ------------------------------------------------------------------------------
# Estado da frota
# ------------------------------------------------------------------------------
def test_empty_fleet(db):
    """Sem agentes, a triagem devolve lista vazia em vez de falhar."""
    assert db.get_fleet_status() == []


def test_agent_appears_after_first_capture(db):
    """O agente entra na frota assim que envia a primeira captura."""
    _capture(db, "agent-a")
    fleet = db.get_fleet_status()
    assert len(fleet) == 1
    assert fleet[0]["uuid"] == "agent-a"


def test_fleet_reports_the_latest_capture(db):
    """A triagem reflete a captura MAIS RECENTE, nao a primeira."""
    _capture(db, "agent-a", score=1)
    time.sleep(0.02)
    _capture(db, "agent-a", score=99)
    assert db.get_fleet_status()[0]["alert_score"] == 99


def test_findings_summary_is_available_without_decrypting(db):
    """
    A contagem por severidade fica em claro, permitindo ordenar a frota por
    gravidade sem abrir o conteudo cifrado.
    """
    _capture(db, "agent-a", findings={"Critical": 2, "High": 1, "Low": 5})
    item = db.get_fleet_status()[0]
    assert item["findings"]["Critical"] == 2
    assert item["findings"]["High"] == 1


def test_missing_summary_becomes_empty(db):
    """Captura antiga, sem resumo, nao quebra a triagem."""
    _capture(db, "agent-a")
    assert db.get_fleet_status()[0]["findings"] == {}


def test_several_agents_are_listed(db):
    """Cada agente aparece uma vez, com seus proprios numeros."""
    _capture(db, "a", score=10, findings={"Critical": 1})
    _capture(db, "b", score=20, findings={"High": 3})
    _capture(db, "c")
    fleet = {i["uuid"]: i for i in db.get_fleet_status()}
    assert set(fleet) == {"a", "b", "c"}
    assert fleet["a"]["findings"]["Critical"] == 1
    assert fleet["b"]["findings"]["High"] == 3


def test_fleet_carries_the_fields_the_triage_needs(db):
    """A tabela de triagem le estes campos diretamente."""
    _capture(db, "a", findings={"Critical": 1})
    item = db.get_fleet_status()[0]
    for field in ("uuid", "hostname", "ip_address", "os_info", "status",
                  "last_seen", "last_capture", "alert_score", "findings"):
        assert field in item, field


def test_corrupted_summary_does_not_break_triage(db):
    """
    Resumo ilegivel no banco vira vazio em vez de derrubar a tela da frota
    inteira por causa de um unico agente.
    """
    _capture(db, "a")
    import sqlite3
    conn = sqlite3.connect(db.db_path)
    conn.execute("UPDATE snapshots SET findings_summary = ?", ("{nao-e-json",))
    conn.commit()
    conn.close()
    assert db.get_fleet_status()[0]["findings"] == {}


# ------------------------------------------------------------------------------
# Custodia preservada
# ------------------------------------------------------------------------------
def test_custody_still_recorded_with_findings_summary(db):
    """
    O resumo de achados nao pode atrapalhar a cadeia de custodia gravada na
    mesma insercao.
    """
    db.insert_snapshot({"x": 1}, agent_uuid="a",
                       metrics={"score": 0},
                       custody={"digest": "d1", "previous_digest": "0" * 64},
                       findings_summary={"Critical": 1})
    assert db.get_last_digest("a") == "d1"
    assert db.get_fleet_status()[0]["findings"]["Critical"] == 1
