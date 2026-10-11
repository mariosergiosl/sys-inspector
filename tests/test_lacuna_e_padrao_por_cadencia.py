# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_lacuna_e_padrao_por_cadencia.py
# DESCRIPTION: Lacuna e padrao do calendario quando a cadencia do agente muda.
#
# WHY:         Medido nos prints de 2026-10-10, com os agentes recem-passados ao
#              modo ocioso (uma captura a cada 300 s) depois de um dia inteiro a
#              ~35 s:
#              - toda captura saia "lacuna 5min", porque o intervalo tipico era
#                a mediana do periodo inteiro, presa nos 35 s (F-274);
#              - toda captura saia "fora do padrao", porque a referencia das
#                24 h contava centenas de capturas do estado antigo contra
#                poucas do novo (F-275);
#              - a captura do cenario de teste entrava na referencia das
#                seguintes.
#              E a faixa da hora cortava a letra do Critico (F-276).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import datetime

from src.core import calendario

ONTEM = datetime.datetime(2026, 10, 9, 8, 0, 0).timestamp()


def _cap(i, ts, resumo, tipo="full"):
    return {"id": i, "agent_uuid": "g", "collected_at": ts + 2,
            "captured_at": ts, "capture_type": tipo,
            "findings_summary": resumo}


def _dia_35s_depois_ocioso(resumo_antes, resumo_depois, n_antes=300,
                           n_depois=12):
    """Um dia a cada 35 s e, logo em seguida, capturas a cada 300 s."""
    antes = [_cap(i, ONTEM + 35 * i, resumo_antes) for i in range(n_antes)]
    inicio = ONTEM + 35 * n_antes
    depois = [_cap(1000 + i, inicio + 300 * (i + 1), resumo_depois)
              for i in range(n_depois)]
    return {c["id"]: c for c in calendario.preparar(antes + depois)}


def test_modo_ocioso_nao_vira_lacuna_em_toda_captura():
    """REPROVA A 1.4.1: as doze capturas de 300 s saiam todas como lacuna."""
    itens = _dia_35s_depois_ocioso({"High": 1}, {"High": 1})
    lacunas = [i for i in range(1000, 1012) if itens[i]["lacuna_antes"]]
    assert lacunas, "a troca de cadencia e um fato e marca as primeiras"
    assert len(lacunas) <= 3, lacunas
    assert not any(itens[i]["lacuna_antes"] for i in range(1004, 1012))


def test_lacuna_de_verdade_continua_acusada_no_modo_ocioso():
    """Uma hora parada no meio da cadencia de 300 s e lacuna."""
    caps = [_cap(i, ONTEM + 300 * i, {"High": 1}) for i in range(10)]
    caps.append(_cap(50, ONTEM + 300 * 9 + 3600, {"High": 1}))
    itens = {c["id"]: c for c in calendario.preparar(caps)}
    assert itens[50]["lacuna_antes"]
    assert itens[50]["lacuna_s"] == 3600
    assert not any(itens[i]["lacuna_antes"] for i in range(10))


def test_poucos_intervalos_nao_bastam_para_acusar_lacuna():
    caps = [_cap(1, ONTEM, {}), _cap(2, ONTEM + 3600, {})]
    assert not any(c["lacuna_antes"] for c in calendario.preparar(caps))


def test_estado_novo_vira_padrao_qualquer_que_seja_a_cadencia():
    """REPROVA A 1.4.1: trezentas capturas de 35 s com A4 e, em seguida,
    capturas de 300 s com A1: todas as de 300 s saiam fora do padrao."""
    itens = _dia_35s_depois_ocioso({"High": 4}, {"High": 1})
    assert itens[1000]["fora_do_padrao"], "a primeira diferente acende"
    assert not any(itens[i]["fora_do_padrao"] for i in range(1007, 1012))


def test_captura_do_cenario_nao_entra_no_padrao_das_seguintes():
    """O cenario e anormal de proposito: ele proprio sai fora do padrao, mas
    tres capturas seguidas do cenario nao fazem do estado dele o normal."""
    caps = [_cap(i, ONTEM + 300 * i, {"High": 1}) for i in range(4)]
    caps += [_cap(10 + i, ONTEM + 1200 + 60 * i, {"Critical": 3, "High": 4},
                  tipo="chaos") for i in range(3)]
    caps.append(_cap(20, ONTEM + 1500, {"Critical": 3, "High": 4}))
    itens = {c["id"]: c for c in calendario.preparar(caps)}
    assert itens[10]["fora_do_padrao"]
    assert itens[20]["fora_do_padrao"]
    assert itens[20]["padrao"] == 1
    assert itens[20]["padrao_n"] == 4


def test_faixa_da_hora_nao_corta_a_letra():
    """REPROVA A 1.4.1: a regra min-width:0 deixava o pedaco estreito do
    Critico encolher ate a letra sumir."""
    assert ".cal-hora .cal-faixa span{min-width:0}" not in calendario.CSS
    assert ".cal-hora .cal-faixa span{min-width:max-content;flex-shrink:0}" \
        in calendario.CSS
