# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_database.py
# DESCRIPTION: Testes do DatabaseManager (SQLite): insercao, colunas quentes,
#              contrato de get_history, filtro por agente, janela de tempo e
#              retencao. Cobre F3 (get_history) e C1 (colunas quentes + row id).
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
    """DatabaseManager novo em diretorio temporario."""
    d = tempfile.mkdtemp()
    return DatabaseManager(db_path=os.path.join(d, "test.db"), max_snapshots=100)


def test_insert_returns_row_id(db):
    """insert_snapshot retorna o id da linha (int), nao mais True (C1)."""
    rid = db.insert_snapshot({"x": 1}, agent_uuid="a")
    assert isinstance(rid, int)
    assert rid > 0


def test_hot_columns_persisted(db):
    """As metricas passadas alimentam as colunas quentes (C1)."""
    db.insert_snapshot({"x": 1}, agent_uuid="a",
                       metrics={"cpu": 12.5, "mem": 345, "pids": 7, "score": 64})
    row = db.get_history(0, time.time() + 10)[0]
    assert row["cpu_avg"] == 12.5
    assert row["mem_used_mb"] == 345
    assert row["alert_score"] == 64
    assert row["is_alert"] == 1


def test_is_alert_zero_when_no_score(db):
    """Sem score, is_alert fica 0."""
    db.insert_snapshot({"x": 1}, agent_uuid="a", metrics={"score": 0})
    row = db.get_history(0, time.time() + 10)[0]
    assert row["alert_score"] == 0
    assert row["is_alert"] == 0


def test_get_history_contract_and_order(db):
    """get_history retorna dicts com as chaves esperadas, ordenado DESC (F3)."""
    db.insert_snapshot({"n": 1}, agent_uuid="a", metrics={"score": 0})
    time.sleep(0.02)
    db.insert_snapshot({"n": 2}, agent_uuid="b", metrics={"score": 5})
    rows = db.get_history(0, time.time() + 10)
    assert len(rows) == 2
    expected_keys = {"id", "timestamp", "agent_uuid", "cpu_avg",
                     "mem_used_mb", "alert_score", "is_alert"}
    assert set(rows[0].keys()) == expected_keys
    # Ordenacao decrescente por timestamp: o mais recente primeiro.
    assert rows[0]["timestamp"] >= rows[1]["timestamp"]


def test_get_history_agent_filter(db):
    """O filtro por agente restringe corretamente (F3)."""
    db.insert_snapshot({}, agent_uuid="a")
    db.insert_snapshot({}, agent_uuid="b")
    rows = db.get_history(0, time.time() + 10, agent_filter="a")
    assert len(rows) == 1
    assert all(r["agent_uuid"] == "a" for r in rows)


def test_get_history_empty_window(db):
    """Janela de tempo que nao abrange nada retorna lista vazia (F3)."""
    db.insert_snapshot({}, agent_uuid="a")
    assert db.get_history(0, 1) == []


def test_retention_keeps_only_max_snapshots():
    """A retencao mantem no maximo max_snapshots por agente."""
    d = tempfile.mkdtemp()
    small = DatabaseManager(db_path=os.path.join(d, "r.db"), max_snapshots=3)
    for i in range(6):
        small.insert_snapshot({"i": i}, agent_uuid="a")
    rows = small.get_history(0, time.time() + 10, agent_filter="a")
    assert len(rows) == 3


def test_get_snapshot_details_roundtrip(db):
    """get_snapshot_details devolve o blob armazenado para o id retornado."""
    rid = db.insert_snapshot({"hello": "world"}, agent_uuid="a")
    assert db.get_snapshot_details(rid) == {"hello": "world"}
