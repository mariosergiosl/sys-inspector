# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_calendario_legivel.py
# DESCRIPTION: Trava os ajustes pedidos pelo Mario em 2026-10-10 olhando os
#              calendarios no ar:
#              - "C3, A5, B25, Delta22, diferente 99: qual informacao e essa?":
#                palavras na celula, dicas em portugues e o "?" de ajuda;
#              - marcas com DETALHE (o que mudou, qual o padrao, a lacuna);
#              - botoes com a aparencia da Manager, nao links sublinhados;
#              - no dia de um host, a lista ia para a geral.
#              E o defeito de merito achado ao explicar os codigos: as marcas
#              contavam a variacao dos achados BAIXOS (de 4 a 23 entre capturas
#              seguidas), e 99 de ~150 capturas sairam "fora do padrao".
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import datetime
import io
import os

from src.core import calendario

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = datetime.datetime(2026, 10, 9, 17, 16, 3).timestamp()
DIA = datetime.date(2026, 10, 9)


def _cap(i, ts, resumo, tipo="full"):
    return {"id": i, "agent_uuid": "o", "collected_at": ts + 3,
            "captured_at": ts, "capture_type": tipo, "findings_summary": resumo}


def _dia_09():
    """Forma do dia 09/10 da .161: C2 A2 com o Baixo oscilando, e o cenario."""
    baixos = [5, 4, 5, 23, 10, 11, 10, 5, 4, 5]
    linhas = [_cap(i, BASE + 36 * i, {"Critical": 2, "High": 2, "Low": b})
              for i, b in enumerate(baixos)]
    linhas.append(_cap(10, BASE + 360, {"Critical": 3, "High": 4, "Low": 23},
                       tipo="chaos"))
    linhas.append(_cap(11, BASE + 396, {"Critical": 2, "High": 2, "Low": 10}))
    return calendario.preparar(linhas, {"o": "openSUSE"})


def _fonte(caminho):
    with io.open(os.path.join(RAIZ, caminho), encoding="utf-8") as fh:
        return fh.read()


def test_baixo_oscilando_nao_e_mudanca_nem_desvio():
    """REPROVA A VERSAO ANTERIOR: cada oscilacao do Baixo virava 'mudou' e
    'fora do padrao'."""
    itens = _dia_09()
    marcados = [i["id"] for i in itens if i["mudou"]]
    fora = [i["id"] for i in itens if i["fora_do_padrao"]]
    assert marcados == [10, 11], "so a entrada e a saida do cenario mudam"
    assert fora == [10], "so a captura do cenario foge do padrao C2 A2"


def test_baixo_oscilando_nao_quebra_o_grupo():
    """REPROVA A VERSAO ANTERIOR: eram 8 grupos em 63 capturas no print."""
    grupos = calendario.agrupar_iguais(_dia_09())
    assert [len(g) for g in grupos] == [10, 1, 1]


def test_o_grupo_mostra_a_variacao_do_baixo():
    html = calendario.render_lista_do_dia(DIA, _dia_09(), lambda t: t,
                                          lambda u, i: "/r")
    assert "Baixo de 4 a 23" in html


def test_marcas_dizem_o_que_mudou_e_qual_e_o_padrao():
    html = calendario.render_lista_do_dia(DIA, _dia_09(), lambda t: t,
                                          lambda u, i: "/r")
    assert "Critico 2&rarr;3" in html and "Alto 2&rarr;4" in html
    assert "7 achado(s) Medio ou acima; o comum neste host e 4" in html


def test_lacuna_diz_quanto_tempo():
    linhas = [_cap(i, BASE + 36 * i, {"Low": 1}) for i in range(5)]
    linhas.append(_cap(9, BASE + 36 * 4 + 900, {"Low": 1}))
    html = calendario.render_lista_do_dia(DIA, calendario.preparar(linhas),
                                          lambda t: t, lambda u, i: "/r")
    assert "15min sem captura antes desta" in html


def test_celula_do_dia_em_palavras_e_dicas_em_portugues():
    """REPROVA A VERSAO ANTERIOR: a celula dizia so 'Delta22 diferente99' e a
    dica da faixa dizia 'Critical: 3'."""
    dias = calendario.resumir_dias(_dia_09())
    html = calendario.render_mes(2026, 10, dias, lambda d: "/d",
                                 lambda a, m: "/m", geral=False)
    assert "2 mudaram" in html and "1 fora do padrao" in html
    assert "Critico: 3 achado(s) na pior captura do dia" in html
    assert "title='Critical:" not in html


def test_o_interrogacao_de_ajuda_esta_no_mes_nas_horas_e_na_lista():
    itens = _dia_09()
    mes = calendario.render_mes(2026, 10, calendario.resumir_dias(itens),
                                lambda d: "/d", lambda a, m: "/m", geral=False)
    lista = calendario.render_lista_do_dia(DIA, itens, lambda t: t,
                                           lambda u, i: "/r",
                                           link_hora=lambda h: "/h")
    assert "class='ajuda'" in mes and "Como ler o calendario" in mes
    assert lista.count("class='ajuda'") >= 2, "horas e marcas"


def test_links_da_lista_sao_botoes():
    html = calendario.render_lista_do_dia(
        DIA, _dia_09(), lambda t: t, lambda u, i: "/r",
        link_eventos=lambda u, i: "/e")
    assert "<a href=" not in html, "link solto sublinhado na lista"
    assert "class='cal-btn'" in html


def test_barra_do_relatorio_tem_botoes_com_estilo_proprio():
    """A classe navlink nao existe na pagina do relatorio: os botoes saiam
    sublinhados."""
    fonte = _fonte("src/controllers/server_controller.py")
    assert 'style=\\"%s;margin-left:12px\\">&#128337; Linha do tempo' in fonte
    assert "_ESTILO_BOTAO_BARRA" in fonte
    assert 'class=\\"navlink\\" href=\\"/timeline?agent' not in fonte


def test_dia_de_um_host_nao_vai_para_a_lista_geral():
    """O defeito que o Mario achou: no dia de um host, os links de filtro
    tiravam o dia, e 'ver tudo' tirava host e dia de uma vez."""
    corpo = _fonte("src/controllers/server_controller.py").split(
        "def _serve_timeline(")[1].split("\n    def ")[0]
    assert 'params = [("dia", dia_txt)]' in corpo
    assert 'params = [("capture", captura_txt)]' in corpo
    assert ">ver tudo</a>" not in corpo
    assert "todos os hosts</a>" in corpo and "todos os tipos</a>" in corpo


def test_titulo_da_lista_diz_host_e_recorte_e_o_corte_e_avisado():
    corpo = _fonte("src/controllers/server_controller.py").split(
        "def _serve_timeline(")[1].split("\n    def ")[0]
    assert 'titulo += ": " + str(nomes.get(agente' in corpo
    assert "if total_janela >= limite:" in corpo
    assert "Exibindo so os %d eventos mais recentes" in corpo
