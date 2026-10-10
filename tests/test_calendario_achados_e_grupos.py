# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_calendario_achados_e_grupos.py
# DESCRIPTION: Trava o que o Mario pediu na segunda volta dos calendarios
#              (2026-10-09/10):
#              - a Linha do tempo abre num calendario de ACHADOS (F-258), que
#                explode para a lista atual ao escolher um dia ou uma captura;
#              - "Capturas / Coletas" e o outro calendario (F-259);
#              - os dois botoes existem dentro de cada host, filtrados por ele;
#              - capturas iguais e seguidas viram uma linha so, porque 144
#                linhas identicas a cada ~36 s "estao confusas";
#              - a faixa de 24 horas dentro do dia.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import datetime
import io
import os
import re
import tempfile

from src.core import calendario
from src.core.events import EventStore, make_event

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = datetime.datetime(2026, 10, 9, 17, 31, 56).timestamp()
DIA = datetime.date(2026, 10, 9)


def _cap(i, ts, resumo, uuid="g", tipo="full"):
    return {"id": i, "agent_uuid": uuid, "collected_at": ts + 1,
            "captured_at": ts, "capture_type": tipo, "findings_summary": resumo}


def _fonte(caminho):
    with io.open(os.path.join(RAIZ, caminho), encoding="utf-8") as fh:
        return fh.read()


# ------------------------------------------------------------------------------
# Agrupamento das capturas iguais
# ------------------------------------------------------------------------------

def test_capturas_iguais_seguidas_viram_um_grupo():
    """O caso do print do Mario: a mesma leitura C2 A2 B2 a cada ~36 s."""
    resumo = {"Critical": 2, "High": 2, "Low": 2}
    itens = calendario.preparar([_cap(i, BASE + 36 * i, resumo)
                                 for i in range(144)], {"g": "gwlocal"})
    grupos = calendario.agrupar_iguais(itens)
    assert [len(g) for g in grupos] == [144]


def test_a_captura_que_muda_abre_grupo_novo():
    linhas = ([_cap(i, BASE + 36 * i, {"Low": 1}) for i in range(10)]
              + [_cap(10, BASE + 360, {"Low": 1, "High": 1})]
              + [_cap(11, BASE + 396, {"Low": 1, "High": 1})])
    grupos = calendario.agrupar_iguais(calendario.preparar(linhas))
    assert [len(g) for g in grupos] == [10, 2]
    assert grupos[1][0]["mudou"], "o que mudou fica na cabeca do grupo novo"


def test_lacuna_quebra_o_grupo():
    tempos = [0, 36, 72, 108, 144, 900, 936]
    grupos = calendario.agrupar_iguais(calendario.preparar(
        [_cap(i, BASE + t, {"Low": 1}) for i, t in enumerate(tempos)]))
    assert [len(g) for g in grupos] == [5, 2]


def test_a_lista_mostra_o_grupo_e_permite_abrir():
    itens = calendario.preparar([_cap(i, BASE + 36 * i, {"Low": 1})
                                 for i in range(20)], {"g": "gwlocal"})
    html = calendario.render_lista_do_dia(DIA, itens, lambda t: t,
                                          lambda u, i: "/r/%s" % i)
    assert "20 capturas iguais" in html
    assert "20 capturas em 1 grupos" in html
    assert "<details>" in html and "ver as 20 capturas" in html
    assert "Atraso da coleta" in html, (
        "a coluna dizia so 'Atraso', e o 1s foi lido como intervalo")


# ------------------------------------------------------------------------------
# Faixa de 24 horas
# ------------------------------------------------------------------------------

def test_faixa_de_horas_conta_por_hora_e_filtra():
    linhas = ([_cap(i, BASE + 36 * i, {"Low": 1}) for i in range(5)]
              + [_cap(100, BASE + 3600, {"High": 1})])
    itens = calendario.preparar(linhas)
    html = calendario.render_lista_do_dia(
        DIA, itens, lambda t: t, lambda u, i: "/r/%s" % i, hora=18,
        link_hora=lambda h: "/h/%s" % h)
    # Exato: "class='cal-horas'" (o conteiner) comeca com o mesmo texto.
    assert len(re.findall(r"class='cal-hora(?: sel)?'", html)) == 24
    assert "/h/17" in html and "/h/18" in html
    assert "Capturas de 09/10/2026, 18h" in html
    assert "/r/100" in html
    assert "/r/0'" not in html, "com a hora escolhida, so aquela hora aparece"


def test_cada_captura_leva_aos_eventos_dela():
    itens = calendario.preparar([_cap(7, BASE, {"Low": 1})])
    html = calendario.render_lista_do_dia(
        DIA, itens, lambda t: t, lambda u, i: "/r",
        link_eventos=lambda u, i: "/timeline?agent=%s&capture=%s" % (u, i))
    assert "/timeline?agent=g&capture=7" in html


# ------------------------------------------------------------------------------
# Calendario de achados
# ------------------------------------------------------------------------------

def _ev(ts, tipo, sev="", subject="", uuid="a"):
    return {"agent_uuid": uuid, "type": tipo, "severity": sev,
            "subject": subject, "corrected_ts": ts, "capture_id": 1}


def test_o_mesmo_achado_repetido_conta_uma_vez_no_dia():
    eventos = [_ev(BASE + i, "finding.raised", "Critical", "evil-cron")
               for i in range(30)]
    r = calendario.resumir_dias_achados(eventos)[DIA]
    assert len(r["achados"]) == 1
    assert r["composicao"]["Critical"] == 1


def test_novo_so_na_primeira_vez():
    eventos = [_ev(BASE, "finding.raised", "High", "x"),
               _ev(BASE + 86400, "finding.raised", "High", "x"),
               _ev(BASE + 86400, "finding.raised", "Medium", "y")]
    dias = calendario.resumir_dias_achados(eventos)
    assert dias[DIA]["novos"] == 1
    assert dias[DIA + datetime.timedelta(days=1)]["novos"] == 1


def test_descobertas_e_capturas_contam_separado_e_info_fica_fora():
    eventos = [_ev(BASE, "capture.taken"), _ev(BASE, "process.start"),
               _ev(BASE, "network.connect"),
               _ev(BASE, "finding.raised", "Info", "inventario")]
    r = calendario.resumir_dias_achados(eventos)[DIA]
    assert r["capturas"] == 1
    assert r["descobertas"] == 2
    assert len(r["achados"]) == 0


def test_calendario_de_achados_usa_as_mesmas_cores():
    dias = calendario.resumir_dias_achados(
        [_ev(BASE, "finding.raised", "Critical", "evil-cron")])
    html = calendario.render_mes_achados(2026, 10, dias, lambda d: "/d",
                                         lambda a, m: "/m", geral=True)
    assert "border-left-color:#ff4d4d" in html
    assert "1 achados" in html and "1 host(s) com achado novo" in html


# ------------------------------------------------------------------------------
# Eventos: consulta por periodo e por captura
# ------------------------------------------------------------------------------

def test_eventos_por_periodo_e_por_captura():
    store = EventStore(os.path.join(tempfile.mkdtemp(), "ev.db"))
    store.add([make_event(BASE, "finding.raised", "a", "x", severity="High",
                          capture_id=10),
               make_event(BASE + 1, "process.start", "a", "bash",
                          capture_id=11),
               make_event(BASE + 86400 * 40, "process.start", "a", "fora",
                          capture_id=12)])
    linhas = store.daily_rows(BASE - 10, BASE + 3600)
    assert [ln["subject"] for ln in linhas] == ["x", "bash"]
    so_10 = store.timeline(capture_id=10)
    assert [e["subject"] for e in so_10] == ["x"]


# ------------------------------------------------------------------------------
# Ligacao nas telas
# ------------------------------------------------------------------------------

def test_a_linha_do_tempo_abre_no_calendario_sem_recorte():
    """Sem dia, captura, janela ou tipo, a Linha do tempo e o calendario;
    com eles, a lista que ja existia, restrita."""
    corpo = _fonte("src/controllers/server_controller.py").split(
        "def _serve_timeline(")[1].split("\n    def ")[0]
    assert ("if not (dia_txt or captura_txt or \"min\" in args or tipos):"
            in corpo)
    assert "self._serve_calendario_achados(controller, args)" in corpo
    assert "capture_id=captura_id" in corpo and "fim=fim_janela" in corpo


def test_os_dois_botoes_dentro_de_cada_host():
    fonte = _fonte("src/controllers/server_controller.py")
    assert 'href=\\"/timeline?agent=%s\\"' in fonte
    assert 'href=\\"/calendario?agent=%s\\"' in fonte
    assert "Linha do tempo" in fonte and "Capturas / \"" in fonte


# ------------------------------------------------------------------------------
# Leitura da sequencia sem cartoes repetidos (F-260)
# ------------------------------------------------------------------------------

def test_a_mesma_conclusao_repetida_vira_um_cartao_com_contagem():
    """O print do Mario: oito cartoes iguais, mudando so os segundos."""
    from collections import namedtuple
    from src.core.correlation import agrupar_conclusoes
    C = namedtuple("C", "title severity technique recommendation description")
    rep = [C("Persistencia criada logo apos atividade suspeita", "Critical",
             "T1053", "Reconstituir a janela", "%d segundo(s) depois" % s)
           for s in (15, 15, 14, 14, 15, 15, 15, 9)]
    outra = C("Outra leitura", "High", "T1070", "Conferir", "x")
    grupos = agrupar_conclusoes(rep + [outra])
    assert [n for _c, n in grupos] == [8, 1]
    assert grupos[0][0].description == "15 segundo(s) depois"


def test_a_linha_do_tempo_usa_o_agrupamento():
    corpo = _fonte("src/controllers/server_controller.py").split(
        "def _serve_timeline(")[1].split("\n    def ")[0]
    assert "agrupar_conclusoes(conclusoes)" in corpo
    assert "visto %d vezes" in corpo
