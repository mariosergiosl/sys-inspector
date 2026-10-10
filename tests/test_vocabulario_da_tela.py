# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_vocabulario_da_tela.py
# DESCRIPTION: Trava o vocabulario da interface decidido pelo Mario (F-252).
#
# WHY:         Em 2026-10-09 o Mario decidiu: "Frota" vira "Hosts", "Laudo"
#              vira "Relatorio" (laudo e a peca que o perito assina, nao o que a
#              ferramenta gera), e "captura" e "coleta" sao coisas distintas:
#              CAPTURAR e o agente obtendo dados do host; COLETAR e o servidor
#              recebendo o que o agente capturou. Textos que descreviam o lado
#              do agente diziam "coleta" ("falha de coleta", "Momento da
#              coleta", "coletado em", "nao coletado").
#
#              Este teste le as strings do codigo pela arvore sintatica e
#              ignora docstrings, mensagens de log e comentarios CSS/HTML/JS, que
#              nao aparecem na tela. Comentario de codigo continua livre para
#              dizer "laudo": quem le o codigo nao e quem le o relatorio.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import ast
import io
import os
import re

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Arquivos que produzem o que o operador ve.
ARQUIVOS_DE_TELA = [
    "src/controllers/server_controller.py",
    "src/exporters/html_report.py",
    "src/exporters/web_assets.py",
    "src/core/correlation.py",
    "src/core/badges.py",
    "src/core/risk.py",
]

PROIBIDOS = [
    (re.compile(r"\blaudos?\b", re.I), "laudo -> relatorio"),
    (re.compile(r"\bfrota\b", re.I), "frota -> hosts"),
    (re.compile(r"falha de coleta", re.I), "captura e do agente"),
    (re.compile(r"momento da coleta", re.I), "captura e do agente"),
    # "coletado em" saiu da lista em 2026-10-10: depois que a barra passou a
    # ler a data do AGENTE na custodia, "coletado em" e o texto CERTO quando so
    # se tem a data do servidor. O teste do fim do arquivo trava onde ele pode
    # aparecer.
    (re.compile(r"\bnao coletado\b", re.I), "captura e do agente"),
]

_COMENTARIO_CSS = re.compile(r"/\*.*?\*/", re.S)
_COMENTARIO_HTML = re.compile(r"<!--.*?-->", re.S)
# Linha inteira de comentario JS. So a linha inteira: "//" no meio da linha
# pode ser uma URL (https://) dentro de texto visivel.
_COMENTARIO_JS = re.compile(r"^[ 	]*//.*$", re.M)
_METODOS_DE_LOG = {"debug", "info", "warning", "error", "critical",
                   "exception"}


def _texto(no):
    """Valor de um literal de string, em Python 3.6 (Str) e 3.8+ (Constant)."""
    if isinstance(no, ast.Constant) and isinstance(no.value, str):
        return no.value
    if hasattr(ast, "Str") and isinstance(no, getattr(ast, "Str")):
        return no.s
    return None


def _strings_de_tela(caminho):
    """Strings do arquivo que podem chegar a tela, com a linha de cada uma."""
    with io.open(os.path.join(RAIZ, caminho), encoding="utf-8") as fh:
        arvore = ast.parse(fh.read())
    ignorar = set()
    for no in ast.walk(arvore):
        corpo = getattr(no, "body", None)
        if isinstance(corpo, list) and corpo and isinstance(corpo[0], ast.Expr):
            ignorar.add(id(corpo[0].value))          # docstring
        if isinstance(no, ast.Call) and isinstance(no.func, ast.Attribute) \
                and no.func.attr in _METODOS_DE_LOG:
            for sub in ast.walk(no):
                ignorar.add(id(sub))                 # mensagem de log
    for no in ast.walk(arvore):
        valor = _texto(no)
        if valor is None or id(no) in ignorar:
            continue
        valor = _COMENTARIO_JS.sub(" ", _COMENTARIO_CSS.sub(" ", valor))
        valor = _COMENTARIO_HTML.sub(" ", valor)
        yield getattr(no, "lineno", 0), valor


def test_a_tela_usa_o_vocabulario_decidido():
    """REPROVA A VERSAO ANTERIOR: a tela dizia Frota, laudo e coleta."""
    achados = []
    for caminho in ARQUIVOS_DE_TELA:
        for linha, valor in _strings_de_tela(caminho):
            for padrao, motivo in PROIBIDOS:
                m = padrao.search(valor)
                if m:
                    achados.append("%s:%d '%s' (%s)"
                                   % (caminho, linha, m.group(0), motivo))
    assert not achados, "vocabulario antigo na tela:\n" + "\n".join(achados)


def test_o_botao_de_navegacao_diz_hosts():
    with io.open(os.path.join(RAIZ, "src/controllers/server_controller.py"),
                 encoding="utf-8") as fh:
        fonte = fh.read()
    assert '("&#127968;", "/", "Hosts")' in fonte


def test_o_log_do_servidor_tambem_deixou_frota():
    """O Mario liberou trocar tambem esta mensagem de log (2026-10-09), que
    aparece a cada partida de um servidor sem autenticacao."""
    with io.open(os.path.join(RAIZ, "src/controllers/server_controller.py"),
                 encoding="utf-8") as fh:
        fonte = fh.read()
    assert "coleta inteira da frota" not in fonte
    assert "tudo o que foi coletado de todos os hosts" in fonte


def test_coletado_em_so_quando_falta_a_data_do_agente():
    """Colisao achada em 2026-10-10: a trava proibia "coletado em" e a barra
    passou a usa-lo corretamente. Ele so pode aparecer no ramo em que a
    captura nao traz o instante do agente."""
    with io.open(os.path.join(RAIZ, "src/controllers/server_controller.py"),
                 encoding="utf-8") as fh:
        fonte = fh.read()
    assert fonte.count('rotulo = "coletado em"') == 1
    trecho = fonte.split('rotulo = "coletado em"')[0].rsplit("if capturado:", 1)[1]
    assert "else:" in trecho, "'coletado em' fora do ramo sem data do agente"


# Travessao: pedido do Mario em 2026-10-10 ("evitar o uso de travessao em
# qualquer texto"), visto em "nada preservado -- nada do artefato foi retido".
# Na primeira versao desta trava o travessao SOZINHO, como valor de campo vazio
# (estado "olhou e nao havia" da D-020), passava por ser simbolo. O Mario
# corrigiu no mesmo dia: campo vazio nunca fica sem informacao, e o travessao
# que quer dizer "nada encontrado" passa a dizer isso por extenso. A trava
# agora reprova QUALQUER travessao em texto de tela.
_TRAVESSAO = re.compile("&mdash;|&#8212;|\u2014")


def _strings_de_todo_src():
    """Strings de tela de todos os modulos de src, com o arquivo de cada uma."""
    for raiz_dir, _d, nomes in os.walk(os.path.join(RAIZ, "src")):
        for nome in sorted(nomes):
            if not nome.endswith(".py"):
                continue
            caminho = os.path.relpath(os.path.join(raiz_dir, nome), RAIZ)
            for linha, valor in _strings_de_tela(caminho):
                yield caminho, linha, valor


def test_nenhum_travessao_na_tela():
    """REPROVA AS DUAS VERSOES ANTERIORES: cinco textos usavam o travessao como
    separador, e quinze campos vazios mostravam so o travessao."""
    achados = []
    for caminho, linha, valor in _strings_de_todo_src():
        m = _TRAVESSAO.search(valor)
        if m:
            achados.append("%s:%d %r" % (caminho, linha, m.group(0)))
    assert not achados, "travessao na tela:\n" + "\n".join(achados)


def test_encaminhamento_para_analise_e_nao_bancada():
    """REPROVA A 1.4.0: o bloco de cada achado dizia "Encaminhamento a
    bancada". O Mario pediu "Encaminhamento para analise" (2026-10-10), e
    "bancada" saiu tambem dos outros textos de tela."""
    achados = []
    for caminho, linha, valor in _strings_de_todo_src():
        if re.search(r"\bbancada\b", valor, re.I):
            achados.append("%s:%d" % (caminho, linha))
    assert not achados, "'bancada' na tela:\n" + "\n".join(achados)
    with io.open(os.path.join(RAIZ, "src/exporters/html_report.py"),
                 encoding="utf-8") as fh:
        assert "Encaminhamento para analise" in fh.read()
