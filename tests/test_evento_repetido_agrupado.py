# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_evento_repetido_agrupado.py
# DESCRIPTION: A Linha do tempo agrupa o mesmo evento repetido em uma linha.
#
# WHY:         Medido em 2026-10-10 na .161: a hora das 18h de 09/10 tinha 3140
#              eventos, 1367 deles o mesmo achado reemitido por cada uma das 81
#              capturas (F-266). Agora vira uma linha, na primeira ocorrencia,
#              com "visto N vezes, de HH:MM:SS a HH:MM:SS" abrivel.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import datetime
import io
import os

from src.core import calendario
from src.core.correlation import agrupar_eventos

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T0 = datetime.datetime(2026, 10, 9, 18, 0, 0).timestamp()


def _ev(ts, tipo="finding.raised", subject="evil-cron", uuid="a", sev="High",
        pid=None, cap=1):
    detalhe = {"pid": pid} if pid else {}
    return {"agent_uuid": uuid, "type": tipo, "severity": sev,
            "subject": subject, "corrected_ts": ts, "capture_id": cap,
            "detail": detalhe}


def test_o_mesmo_achado_de_81_capturas_vira_um_grupo():
    """REPROVA A 1.4.1: cada captura era uma linha."""
    eventos = [_ev(T0 + 40 * i, cap=i) for i in range(81)]
    grupos = agrupar_eventos(eventos)
    assert len(grupos) == 1 and len(grupos[0]) == 81


def test_o_que_muda_o_evento_separa_o_grupo():
    eventos = [_ev(T0), _ev(T0 + 1),
               _ev(T0 + 2, uuid="b"),              # outro host
               _ev(T0 + 3, subject="outro"),       # outro assunto
               _ev(T0 + 4, sev="Critical"),        # outra severidade
               _ev(T0 + 5, tipo="persistence"),    # outro tipo
               _ev(T0 + 6, tipo="process.start", subject="bash", pid=10),
               _ev(T0 + 7, tipo="process.start", subject="bash", pid=11)]
    tamanhos = [len(g) for g in agrupar_eventos(eventos)]
    assert tamanhos == [2, 1, 1, 1, 1, 1, 1], tamanhos


def test_a_lista_continua_cronologica_pela_primeira_ocorrencia():
    eventos = [_ev(T0, subject="x"), _ev(T0 + 1, subject="y"),
               _ev(T0 + 2, subject="x"), _ev(T0 + 3, subject="z")]
    primeiros = [g[0]["subject"] for g in agrupar_eventos(eventos)]
    assert primeiros == ["x", "y", "z"]


def test_linha_agrupada_diz_quantas_vezes_e_de_quando_a_quando():
    grupo = [_ev(T0 + 40 * i, cap=100 + i) for i in range(81)]
    html = calendario.render_repeticao(
        grupo, lambda e: "/agent/a?capture=%s" % e["capture_id"])
    assert "visto 81 vezes, de 18:00:00 a 18:53:20" in html
    assert "<details" in html
    assert "/agent/a?capture=100" in html
    assert "/agent/a?capture=129" in html
    assert "/agent/a?capture=130" not in html, "lista so as primeiras"
    assert "e mais 51" in html


def test_evento_unico_nao_ganha_contagem():
    assert calendario.render_repeticao([_ev(T0)]) == ""


def test_a_linha_do_tempo_usa_o_agrupamento():
    """O controlador nao importa no Windows (pwd): a ligacao e conferida na
    fonte, e o comportamento acima nas funcoes puras."""
    with io.open(os.path.join(RAIZ, "src/controllers/server_controller.py"),
                 encoding="utf-8") as fh:
        corpo = fh.read().split("def _serve_timeline(")[1].split("\n    def ")[0]
    assert "grupos_ev = agrupar_eventos(eventos)" in corpo
    assert "for grupo in grupos_ev:" in corpo
    assert "calendario.render_repeticao(" in corpo
    assert "for ev in eventos:\n            icone" not in corpo
