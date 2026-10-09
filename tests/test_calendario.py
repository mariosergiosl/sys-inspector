# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_calendario.py
# DESCRIPTION: Trava o calendario de capturas e coletas (F-259) e a distincao
#              entre o instante de captura (agente) e o de coleta (servidor).
#
# WHY:         Pedido do Mario em 2026-10-09: com uma captura a cada ~40 s, a
#              navegacao sequencial nao leva ao incidente. O calendario mostra,
#              por dia, quantas capturas houve, a composicao por severidade e o
#              que destoa. Os casos abaixo seguem as decisoes dele, inclusive o
#              exemplo literal: "10 coletas por dia, todas com contagem 1; se
#              aparecer uma com 3 ou 15, ja e diferente e deve ser analisada".
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import datetime
import io
import json
import os
import tempfile
import time

from src.core import calendario
from src.core.database import DatabaseManager

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = datetime.datetime(2026, 10, 9, 10, 0, 0).timestamp()


def _linha(i, ts, resumo, uuid="a", tipo="full", atraso=2.0, sem_captura=False):
    return {"id": i, "agent_uuid": uuid, "collected_at": ts + atraso,
            "captured_at": None if sem_captura else ts, "capture_type": tipo,
            "findings_summary": resumo}


def test_dez_com_um_e_uma_com_quinze():
    """O exemplo do Mario: so a captura que destoa sai fora do padrao."""
    linhas = [_linha(i, BASE + 40 * i, {"Low": 1}) for i in range(10)]
    linhas.append(_linha(10, BASE + 400, {"Low": 3, "High": 12}))
    itens = calendario.preparar(linhas)
    fora = [i["id"] for i in itens if i["fora_do_padrao"]]
    assert fora == [10]


def test_mudou_e_marcador_por_host():
    linhas = [_linha(1, BASE, {"Low": 1}), _linha(2, BASE + 40, {"Low": 1}),
              _linha(3, BASE + 80, {"Medium": 1}),
              _linha(4, BASE + 10, {"High": 2}, uuid="b")]
    itens = {i["id"]: i for i in calendario.preparar(linhas)}
    assert not itens[1]["mudou"], "a primeira captura nao tem anterior"
    assert not itens[2]["mudou"]
    assert itens[3]["mudou"]
    assert not itens[4]["mudou"], "outro host nao e a captura anterior"


def test_info_fica_fora_da_composicao():
    itens = calendario.preparar([_linha(1, BASE, {"Info": 9, "Low": 2})])
    assert itens[0]["total"] == 2
    assert "Info" not in itens[0]["sev"]


def test_lacuna_e_relativa_ao_intervalo_tipico_do_host():
    tempos = [0, 40, 80, 120, 160, 900, 940]
    itens = calendario.preparar([_linha(i, BASE + t, {"Low": 1})
                                 for i, t in enumerate(tempos)])
    lacunas = [i["id"] for i in itens if i["lacuna_antes"]]
    assert lacunas == [5]


def test_captura_e_coleta_sao_instantes_distintos():
    """Capturado = agente; coletado = servidor; a diferenca e o atraso."""
    it = calendario.preparar([_linha(1, BASE, {}, atraso=3600)])[0]
    assert it["captured_at"] == BASE
    assert it["collected_at"] == BASE + 3600
    assert it["atraso"] == 3600
    assert not it["captura_estimada"]


def test_sem_data_do_agente_usa_a_coleta_e_avisa():
    it = calendario.preparar([_linha(1, BASE, {}, sem_captura=True)])[0]
    assert it["captura_estimada"]
    assert it["atraso"] is None


def test_pior_composicao_do_dia():
    linhas = [_linha(1, BASE, {"Low": 5}), _linha(2, BASE + 40, {"High": 1}),
              _linha(3, BASE + 80, {"Low": 2, "Medium": 3})]
    dias = calendario.resumir_dias(calendario.preparar(linhas))
    r = dias[datetime.date(2026, 10, 9)]
    assert r["capturas"] == 3
    assert r["pior"] == {"Critical": 0, "High": 1, "Medium": 3, "Low": 5}


def test_visao_geral_conta_hosts_a_olhar():
    linhas = [_linha(1, BASE, {"Low": 1}, uuid="a"),
              _linha(2, BASE + 40, {"High": 1}, uuid="a"),
              _linha(3, BASE, {"Low": 1}, uuid="b"),
              _linha(4, BASE + 40, {"Low": 1}, uuid="b")]
    itens = calendario.preparar(linhas, {"a": "gwlocal", "b": "openSUSE"})
    dias = calendario.resumir_dias(itens)
    html = calendario.render_mes(2026, 10, dias, lambda d: "/d", lambda a, m: "/m",
                                 geral=True)
    assert "2 hosts" in html
    assert "1 host(s) a olhar" in html


def test_dia_sem_captura_diz_que_nao_houve():
    html = calendario.render_mes(2026, 10, {}, lambda d: "/d", lambda a, m: "/m",
                                 geral=False)
    assert "sem captura" in html
    assert "outubro de 2026" in html


def test_borda_na_cor_da_severidade_mais_alta():
    dias = calendario.resumir_dias(calendario.preparar(
        [_linha(1, BASE, {"Low": 3, "Critical": 1})]))
    html = calendario.render_mes(2026, 10, dias, lambda d: "/d", lambda a, m: "/m",
                                 geral=False)
    assert "border-left-color:#ff4d4d" in html


def test_lista_do_dia_escapa_o_nome_do_host():
    itens = calendario.preparar([_linha(1, BASE, {"Low": 1}, uuid="x")],
                                {"x": "<script>alert(1)</script>"})
    html = calendario.render_lista_do_dia(datetime.date(2026, 10, 9), itens,
                                          lambda t: t, lambda u, i: "/r")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def _db():
    d = tempfile.mkdtemp()
    return DatabaseManager(db_path=os.path.join(d, "t.db"), max_snapshots=100)


def test_consulta_em_banco_novo_sem_a_coluna_da_retencao():
    """Banco novo nao tem purged_at; filtrar por ela devolvia lista vazia SEM
    erro, e o calendario sairia em branco calado."""
    db = _db()
    db.insert_snapshot({"x": 1}, agent_uuid="a",
                       custody={"digest": "d1", "captured_at": BASE},
                       findings_summary={"Low": 2}, capture_type="chaos")
    linhas = db.get_calendar_rows(0, time.time() + 10)
    assert len(linhas) == 1
    assert linhas[0]["captured_at"] == BASE
    assert linhas[0]["capture_type"] == "chaos"
    assert linhas[0]["findings_summary"] == {"Low": 2}


def test_instante_de_captura_vem_da_custodia():
    db = _db()
    sid = db.insert_snapshot({"x": 1}, agent_uuid="a",
                             custody={"digest": "d2", "captured_at": BASE})
    sem = db.insert_snapshot({"x": 2}, agent_uuid="a", custody=None)
    assert db.get_captured_at(sid) == BASE
    assert db.get_captured_at(sem) is None


def test_a_barra_mostra_a_captura_do_agente_e_nao_a_coleta():
    """REPROVA A VERSAO ANTERIOR: a barra dizia 'capturado em' com o instante
    em que o servidor gravou."""
    with io.open(os.path.join(RAIZ, "src/controllers/server_controller.py"),
                 encoding="utf-8") as fh:
        fonte = fh.read()
    assert "controller.db.get_captured_at(" in fonte
    assert '"coletado em"' in fonte, (
        "sem a data do agente, a barra tem que dizer coletado, nao capturado")


def test_o_calendario_esta_na_navegacao_e_valida_o_host():
    with io.open(os.path.join(RAIZ, "src/controllers/server_controller.py"),
                 encoding="utf-8") as fh:
        fonte = fh.read()
    assert '("&#128197;", "/calendario", "Calendario")' in fonte
    corpo = fonte.split("def _serve_calendario(")[1].split("\n    def ")[0]
    assert "id_valido(host)" in corpo
    assert json.dumps("dia") and "_RE_DIA.match" in corpo
