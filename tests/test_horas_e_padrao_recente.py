# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_horas_e_padrao_recente.py
# DESCRIPTION: Trava a faixa de horas na lista de eventos do dia (pedido do
#              Mario em 2026-10-10: "pode colocar nessa tela aquela mesma barra
#              de filtro de hora?") e o padrao RECENTE do host no calendario de
#              capturas (F-265).
#
# WHY:         O padrao era o total mais comum do MES. Medido em 2026-10-10: as
#              primeiras capturas limpas da .161, logo depois de remover
#              artefatos plantados, sairam "fora do padrao" porque o mes ainda
#              era dominado pelo estado anterior.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import datetime
import io
import os
import re

from src.core import calendario

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ONTEM = datetime.datetime(2026, 10, 9, 17, 0, 0).timestamp()


def _cap(i, ts, resumo):
    return {"id": i, "agent_uuid": "o", "collected_at": ts + 2,
            "captured_at": ts, "capture_type": "full",
            "findings_summary": resumo}


def test_estado_limpo_novo_deixa_de_ser_fora_do_padrao():
    """REPROVA A VERSAO ANTERIOR: cem capturas sujas ontem (C2 A2) e, no dia
    seguinte, depois de mais de 24 h, capturas limpas (A1). Com o padrao do
    mes, as limpas saiam 'fora do padrao'."""
    sujas = [_cap(i, ONTEM + 36 * i, {"Critical": 2, "High": 2})
             for i in range(100)]
    amanha = ONTEM + 36 * 99 + 25 * 3600
    limpas = [_cap(200 + i, amanha + 300 * i, {"High": 1}) for i in range(6)]
    itens = {i["id"]: i for i in calendario.preparar(sujas + limpas)}
    assert not any(itens[200 + i]["fora_do_padrao"] for i in range(6))


def test_mudanca_dentro_das_24h_continua_fora_do_padrao():
    """Dentro da janela, o estado anterior ainda e o padrao: a primeira
    captura diferente acende, como deve."""
    sujas = [_cap(i, ONTEM + 36 * i, {"Critical": 2, "High": 2})
             for i in range(20)]
    diferente = _cap(99, ONTEM + 36 * 20, {"High": 1})
    itens = {i["id"]: i for i in calendario.preparar(sujas + [diferente])}
    assert itens[99]["fora_do_padrao"]
    assert itens[99]["padrao"] == 4


def test_sem_capturas_suficientes_nao_ha_padrao():
    itens = calendario.preparar([_cap(1, ONTEM, {"High": 9}),
                                 _cap(2, ONTEM + 36, {"High": 1})])
    assert not any(i["fora_do_padrao"] for i in itens)


def _ev(ts, tipo, sev="", subject="", uuid="a"):
    return {"agent_uuid": uuid, "type": tipo, "severity": sev,
            "subject": subject, "corrected_ts": ts, "capture_id": 1}


def test_faixa_de_horas_da_linha_do_tempo():
    """Mesmo desenho da faixa do calendario de capturas: 24 colunas, o achado
    repetido conta uma vez por hora, e cada hora e um link."""
    eventos = ([_ev(ONTEM + i, "finding.raised", "Critical", "evil-cron")
                for i in range(30)]
               + [_ev(ONTEM + 3600 + i, "process.start", subject="bash")
                  for i in range(5)])
    html = calendario.render_horas_achados(eventos, lambda h: "/h/%s" % h)
    assert len(re.findall(r"class='cal-hora(?: sel)?'", html)) == 24
    assert "/h/17" in html and "/h/18" in html
    assert "Critico: 1 achado(s) distintos nesta hora" in html
    assert "class='ajuda'" in html


def test_a_lista_do_dia_tem_a_faixa_e_a_hora_restringe():
    with io.open(os.path.join(RAIZ, "src/controllers/server_controller.py"),
                 encoding="utf-8") as fh:
        corpo = fh.read().split("def _serve_timeline(")[1].split(
            "\n    def ")[0]
    assert "calendario.render_horas_achados(" in corpo
    assert "desde = inicio_dia + hora_ev * 3600" in corpo
    assert 'params.append(("hora", hora_ev))' in corpo, (
        "os filtros de tipo tem que manter a hora escolhida")
    assert "faixa_horas + barras + topo" in corpo
