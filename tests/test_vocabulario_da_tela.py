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
    (re.compile(r"\bcoletado em\b", re.I), "captura e do agente"),
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
