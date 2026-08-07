# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_retention.py
# DESCRIPTION: Quanto tempo a evidencia fica, e o que se pode apagar dela.
#
#              Medido em campo: 1.2 GB de banco em um dia com dois agentes, dos
#              quais 1.03 GB eram payloads que a fila de ingestao guardava para
#              sempre depois de ja terem sido salvos. Cada captura existia em
#              duplicidade.
#
#              Mas apagar evidencia nao e decisao de armazenamento, e decisao
#              PERICIAL: as capturas sao encadeadas por digest, e remover uma
#              rompe a cadeia entre a anterior e a seguinte. Uma politica
#              ingenua destruiria em silencio a propriedade que da valor
#              pericial ao conjunto.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import sqlite3
import time

import pytest

from src.core.retention import (RetentionPolicy, MODE_FORENSIC, MODE_SECURITY)


@pytest.fixture
def banco(tmp_path):
    caminho = str(tmp_path / "s.db")
    conn = sqlite3.connect(caminho)
    conn.execute("""CREATE TABLE snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_uuid TEXT, timestamp REAL,
        json_blob TEXT, digest TEXT, previous_digest TEXT, custody TEXT)""")
    conn.commit()
    conn.close()
    return caminho


def _inserir(caminho, agente="a", quando=None, peso=1000, n=1):
    conn = sqlite3.connect(caminho)
    for _ in range(n):
        conn.execute("INSERT INTO snapshots (agent_uuid, timestamp, json_blob, "
                     "digest, previous_digest) VALUES (?, ?, ?, ?, ?)",
                     (agente, quando or time.time(), "x" * peso,
                      "dig", "ant"))
    conn.commit()
    conn.close()


def _sobrando(caminho):
    conn = sqlite3.connect(caminho)
    n = conn.execute("SELECT COUNT(*) FROM snapshots "
                     "WHERE json_blob IS NOT NULL").fetchone()[0]
    conn.close()
    return n


def _linhas(caminho):
    conn = sqlite3.connect(caminho)
    n = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    conn.close()
    return n


# ------------------------------------------------------------------------------
# A DECISAO PERICIAL
# ------------------------------------------------------------------------------
def test_forensic_mode_deletes_nothing(banco):
    """
    Investigacao criminal nao admite lacuna. Em modo forense o disco e problema
    do operador, nunca justificativa para apagar evidencia.
    """
    _inserir(banco, quando=time.time() - 400 * 86400, n=20)
    politica = RetentionPolicy(banco, {"retention": {"mode": MODE_FORENSIC}})

    politica.apply()
    assert _sobrando(banco) == 20


def test_purging_never_removes_the_row(banco):
    """
    A linha e o elo da cadeia. Apaga-la romperia o encadeamento entre a captura
    anterior e a seguinte, e toda verificacao posterior falharia sem que
    ninguem soubesse por que.
    """
    _inserir(banco, quando=time.time() - 400 * 86400, n=5)
    RetentionPolicy(banco, {"retention": {"max_age_days": 90}}).apply()

    assert _linhas(banco) == 5
    assert _sobrando(banco) == 0


def test_the_tombstone_keeps_what_verifies_the_chain(banco):
    """Sem digest e digest anterior, a lapide nao serviria para nada."""
    _inserir(banco, quando=time.time() - 400 * 86400)
    RetentionPolicy(banco, {"retention": {"max_age_days": 90}}).apply()

    conn = sqlite3.connect(banco)
    linha = conn.execute("SELECT digest, previous_digest, purged_at "
                         "FROM snapshots").fetchone()
    conn.close()
    assert linha[0] == "dig"
    assert linha[1] == "ant"
    assert linha[2]          # momento da remocao registrado


# ------------------------------------------------------------------------------
# OS TRES LIMITES
# ------------------------------------------------------------------------------
def test_old_payload_is_purged(banco):
    _inserir(banco, quando=time.time() - 200 * 86400, n=3)
    _inserir(banco, quando=time.time(), n=2)

    RetentionPolicy(banco, {"retention": {"max_age_days": 90}}).apply()
    assert _sobrando(banco) == 2


def test_a_noisy_agent_does_not_consume_the_whole_quota(banco):
    """
    Era o defeito da retencao por contagem global: um host de ciclo curto
    empurrava os outros para fora e apagava o proprio historico em horas.
    """
    _inserir(banco, agente="falante", n=10)
    _inserir(banco, agente="quieto", n=2)

    RetentionPolicy(banco, {"retention": {"max_per_agent": 5,
                                          "max_age_days": 0,
                                          "max_total_mb": 0}}).apply()

    conn = sqlite3.connect(banco)
    quieto = conn.execute("SELECT COUNT(*) FROM snapshots WHERE agent_uuid='quieto' "
                          "AND json_blob IS NOT NULL").fetchone()[0]
    falante = conn.execute("SELECT COUNT(*) FROM snapshots WHERE agent_uuid='falante' "
                           "AND json_blob IS NOT NULL").fetchone()[0]
    conn.close()
    assert quieto == 2       # intocado
    assert falante == 5      # limitado


def test_size_ceiling_protects_the_volume(banco):
    """
    E o unico limite que protege de verdade: idade e contagem podem estar
    satisfeitas e ainda assim um pico de capturas grandes encher o disco.
    """
    _inserir(banco, peso=1048576, n=10)   # 10 MB

    RetentionPolicy(banco, {"retention": {"max_total_mb": 5,
                                          "max_age_days": 0,
                                          "max_per_agent": 0}}).apply()
    assert _sobrando(banco) <= 5


def test_the_oldest_goes_first_when_space_runs_out(banco):
    """Descartar o mais recente inverteria o valor: o presente investiga-se."""
    _inserir(banco, peso=1048576, n=4)

    RetentionPolicy(banco, {"retention": {"max_total_mb": 2,
                                          "max_age_days": 0,
                                          "max_per_agent": 0}}).apply()

    conn = sqlite3.connect(banco)
    vivos = [r[0] for r in conn.execute(
        "SELECT id FROM snapshots WHERE json_blob IS NOT NULL ORDER BY id")]
    conn.close()
    assert vivos == sorted(vivos, reverse=False)
    assert 1 not in vivos     # o mais antigo saiu


def test_nothing_to_purge_is_not_an_error(banco):
    _inserir(banco, n=2)
    assert RetentionPolicy(banco).apply()["purged"] == 0


# ------------------------------------------------------------------------------
# ESPACO REALMENTE DEVOLVIDO
# ------------------------------------------------------------------------------
def test_space_is_returned_to_the_system(banco):
    """
    O SQLite marca a pagina como livre e a reutiliza, mas NUNCA encolhe o
    arquivo sozinho. Sem VACUUM, apagar capturas nao libera um byte e a
    politica parece nao funcionar.
    """
    _inserir(banco, peso=200000, n=40)
    politica = RetentionPolicy(banco, {"retention": {"max_per_agent": 2,
                                                     "max_age_days": 0,
                                                     "max_total_mb": 0}})
    politica.apply()

    import os
    antes = os.path.getsize(banco)
    politica.reclaim_space()
    assert os.path.getsize(banco) < antes


def test_usage_reports_what_can_still_be_reclaimed(banco):
    _inserir(banco, n=3)
    uso = RetentionPolicy(banco).usage()

    assert uso["snapshots"] == 3
    assert "file_mb" in uso
    assert "reclaimable_mb" in uso


def test_usage_reports_the_active_mode(banco):
    """
    O modo precisa ser visivel: alguem apresentaria em juizo material coletado
    em modo relaxado acreditando ser o outro.
    """
    uso = RetentionPolicy(banco, {"retention": {"mode": MODE_FORENSIC}}).usage()
    assert uso["mode"] == MODE_FORENSIC


# ------------------------------------------------------------------------------
# O VAZAMENTO QUE MOTIVOU TUDO
# ------------------------------------------------------------------------------
def test_the_queue_discards_the_payload_once_stored(tmp_path):
    """
    A fila e um buffer de transporte, nao um segundo arquivo. Guardar o payload
    depois de a captura estar salva mantinha cada evidencia em duplicidade, e
    como a fila nunca teve retencao a copia crescia sem limite: medido em campo,
    785 entradas ocupavam 1.03 GB, contra 65 MB das capturas de fato guardadas.
    """
    from src.core.ingest import IngestQueue

    fila = IngestQueue(str(tmp_path / "q.db"))
    fila.enqueue("agente", {"processes": {"1": {"cmd": "x" * 5000}}})

    item = fila.next_batch(1)[0]
    antes = len(str(item["payload"]))
    fila.mark_done(item["id"])

    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "q.db"))
    depois = conn.execute("SELECT LENGTH(payload) FROM ingest_queue "
                          "WHERE id = ?", (item["id"],)).fetchone()[0]
    conn.close()

    assert depois < antes / 10


def test_the_queue_keeps_the_trail_after_discarding(tmp_path):
    """
    O conteudo vai embora, o rastro fica: quem entregou, quando, com que digest
    e qual o desfecho. E o registro que importa para auditoria.
    """
    from src.core.ingest import IngestQueue

    fila = IngestQueue(str(tmp_path / "q.db"))
    fila.enqueue("agente-a", {"x": 1})
    item = fila.next_batch(1)[0]
    fila.mark_done(item["id"])

    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "q.db"))
    linha = conn.execute("SELECT agent_uuid, status FROM ingest_queue "
                         "WHERE id = ?", (item["id"],)).fetchone()
    conn.close()
    assert linha[0] == "agente-a"
    assert linha[1] == "DONE"


def test_a_processed_entry_is_not_handed_out_again(tmp_path):
    """Sem payload, reprocessar produziria uma captura vazia no lugar da real."""
    from src.core.ingest import IngestQueue

    fila = IngestQueue(str(tmp_path / "q.db"))
    fila.enqueue("agente", {"x": 1})
    item = fila.next_batch(1)[0]
    fila.mark_done(item["id"])

    assert fila.next_batch(10) == []
