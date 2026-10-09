# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_arraste_de_coluna.py
# DESCRIPTION: Trava a correcao do "pulo" ao arrastar a divisa de uma coluna
#              (F-250), no laudo e na Manager, que usam o mesmo nucleo.
#
# WHY:         Anotado pelo Mario avaliando a 1.3.1 em 2026-10-09: ao clicar na
#              divisa entre "Command Tree" e "PID" as colunas pulavam, o cursor
#              ficava fora da alca e o arraste seguia "no lugar errado".
#              Medido no Chrome: variaveis somando 1670px numa caixa de 1887px,
#              a coluna declarada 540px e desenhada 610px; 1px de arraste a
#              levava a 662px, com a alca 51px a direita do cursor, e 100px de
#              arraste rendiam so 66px.
#
#              Causa: a tabela ocupa a largura da caixa (F-230) e o navegador
#              distribui a sobra entre as colunas. O arraste partia da largura
#              DESENHADA e a gravava na variavel, provocando nova distribuicao.
#              O congelamento das larguras ja existia, mas so no ramo da
#              Manager sem variavel, que nao era o caminho de nenhuma das telas.
#
#              Nao ha navegador no CI, entao estes testes olham o nucleo JS
#              gerado. A prova de comportamento foi a medicao no navegador,
#              registrada no backlog.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import re

from src.exporters.web_assets import _JS_COLUNAS_CORE


def _corpo_do_mousedown():
    """Devolve o trecho do handler de mousedown do nucleo de arraste."""
    m = re.search(r"addEventListener\('mousedown', function\(e\)\{(.*?)\n    \}\);",
                  _JS_COLUNAS_CORE, re.S)
    assert m, "o nucleo de arraste perdeu o handler de mousedown"
    return m.group(1)


def _corpo_do_mousemove():
    """Devolve o trecho do handler de mousemove do nucleo de arraste."""
    m = re.search(r"addEventListener\('mousemove', function\(e\)\{(.*?)\n    \}\);",
                  _JS_COLUNAS_CORE, re.S)
    assert m, "o nucleo de arraste perdeu o handler de mousemove"
    return m.group(1)


def test_mousedown_congela_todas_as_colunas_sem_condicao():
    """O congelamento vale para as duas telas, e nao so para tabela sem variavel.

    Na versao com defeito ele estava dentro de `if (!variavel)`, e as duas
    telas tem variavel: o congelamento nunca rodava.
    """
    corpo = _corpo_do_mousedown()
    assert "linha.children" in corpo and "offsetWidth" in corpo, (
        "o clique deixou de congelar a largura desenhada das colunas")
    assert "if (!variavel)" not in corpo, (
        "o congelamento voltou a depender da ausencia de variavel, e as duas "
        "telas tem variavel: a coluna volta a pular no primeiro pixel")


def test_congelamento_mede_todas_antes_de_gravar_qualquer_uma():
    """Gravar uma coluna redistribui a tabela na hora: ler a proxima depois
    disso devolve largura ja alterada.

    Defeito da PRIMEIRA versao desta correcao, medido no Chrome em 2026-10-09:
    o laco fazia `gravar(c, c.offsetWidth)` coluna a coluna; PID desenhada com
    102px foi gravada como 83px e a coluna arrastada saltou de 917px para
    1097px no proprio clique. Todo `offsetWidth` do clique tem que vir antes
    do primeiro `gravar(`.
    """
    corpo = _corpo_do_mousedown()
    assert "gravar(" in corpo, "o clique deixou de gravar as larguras"
    ultima_leitura = corpo.rfind("offsetWidth")
    primeira_gravacao = corpo.find("gravar(")
    assert ultima_leitura < primeira_gravacao, (
        "o clique voltou a ler largura depois de ja ter gravado outra: cada "
        "leitura sai redistribuida e a coluna pula no clique")


def test_congelamento_grava_na_variavel_do_colgroup():
    """Congelar escrevendo no <th> nao adianta: com table-layout:fixed quem
    manda e o colgroup. A largura tem que ir para a variavel que ele le."""
    assert "colgroup col" in _JS_COLUNAS_CORE, (
        "o arraste deixou de descobrir a variavel pelo colgroup")
    assert "setProperty(v, largura" in _JS_COLUNAS_CORE, (
        "o arraste deixou de gravar na variavel da coluna")


def test_ultima_coluna_absorve_o_encolhimento():
    """Ao encolher uma coluna, a ultima cresce o mesmo tanto e a tabela segue
    ocupando a caixa (F-230) sem redistribuir: a coluna acompanha o cursor."""
    corpo = _corpo_do_mousemove()
    assert "gravar(ultima" in corpo, (
        "a ultima coluna deixou de absorver a diferenca ao encolher")
    assert "Math.max(0, iniW - largura - folga)" in corpo, (
        "a compensacao da ultima coluna mudou de regra")


def test_compensacao_desconta_a_folga_da_tabela():
    """Quando a tabela ja passa da caixa, encolher uma coluna nao abre vao.

    Medido no Chrome em 2026-10-09: tabela com 2939px numa caixa de 2839px;
    encolher "Command Tree" 150px fazia Alerts crescer 150px sem necessidade,
    e Alerts nao encolhia mesmo com 220px de folga.
    """
    assert "folga = Math.max(0, tabela.offsetWidth - caixa)" in _JS_COLUNAS_CORE, (
        "o clique deixou de medir quanto a tabela ja passa da caixa")
    corpo = _corpo_do_mousemove()
    assert "ultimaIni - folga" in corpo, (
        "a ultima coluna deixou de poder usar a folga ao encolher")


def test_ultima_coluna_nao_encolhe_abaixo_do_que_ocupa():
    """Encolher a propria ultima coluna abriria um vao que o navegador
    redistribuiria entre as outras, reproduzindo o pulo."""
    corpo = _corpo_do_mousemove()
    assert "alvo === ultima" in corpo and "largura < ultimaIni - folga" in corpo, (
        "a ultima coluna voltou a poder encolher abaixo da largura da caixa")


def test_o_mesmo_nucleo_segue_nas_duas_telas():
    """A correcao so vale se as duas telas continuarem usando este nucleo."""
    import io
    import os
    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def fonte(caminho):
        with io.open(os.path.join(raiz, caminho), encoding="utf-8") as fh:
            return fh.read()
    assert "JS_COLUNAS_AJUSTAVEIS" in fonte("src/controllers/server_controller.py")
    assert "_JS_COLUNAS_CORE" in fonte("src/exporters/html_report.py")
    assert "<colgroup>" in fonte("src/controllers/server_controller.py"), (
        "a Manager perdeu o colgroup de onde o arraste le as variaveis")
    assert "<colgroup>" in fonte("src/exporters/web_assets.py"), (
        "o laudo perdeu o colgroup de onde o arraste le as variaveis")
