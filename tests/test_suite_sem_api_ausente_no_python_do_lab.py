# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_suite_sem_api_ausente_no_python_do_lab.py
# DESCRIPTION: Codigo e testes nao usam argumento que o Python do lab nao tem.
#
# WHY:         Em 2026-11-10 a suite falhou na VM .161 (Python 3.6.15) com
#              "write_text() got an unexpected keyword argument 'newline'": o
#              teste do cenario que sujava o /tmp usava Path.write_text(newline=),
#              que so existe no Python 3.10+. No Windows (3.14) e na CI (3.10)
#              passava, entao nenhuma das duas acusaria. Este teste le o fonte e
#              reprova o uso, sem depender do Python que roda a suite.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Path.write_text(newline=) chegou no 3.10; Path.read_text(newline=) no 3.13.
# ".*" e nao "[^)]*": o argumento pode ter chamada com parenteses antes do
# newline= (write_text(_script_do_pivot(), newline=...) escapava assim).
PADRAO = re.compile(r"\.(write_text|read_text)\(.*\bnewline\s*=")


def _arquivos_python():
    """Todo .py de src/, tests/ e tools/."""
    for pasta in ("src", "tests", "tools"):
        for raiz, _dirs, nomes in os.walk(os.path.join(RAIZ, pasta)):
            for nome in nomes:
                if nome.endswith(".py"):
                    yield os.path.join(raiz, nome)


def _ocorrencias(texto):
    """Linhas (1-based) com write_text/read_text recebendo newline=."""
    return [n for n, linha in enumerate(texto.splitlines(), 1) if PADRAO.search(linha)]


def test_nenhum_write_text_ou_read_text_com_newline():
    """Reprova o defeito de 2026-11-10 em qualquer arquivo do projeto."""
    achados = []
    for caminho in _arquivos_python():
        if os.path.abspath(caminho) == os.path.abspath(__file__):
            continue
        with io.open(caminho, encoding="utf-8") as fh:
            for n in _ocorrencias(fh.read()):
                achados.append("%s:%d" % (os.path.relpath(caminho, RAIZ), n))
    assert achados == [], "argumento ausente no Python 3.6: %s" % achados


def test_o_padrao_reconhece_a_linha_do_defeito():
    """O detector acusa a linha exata que falhou na .161 e nao acusa a correcao."""
    assert _ocorrencias('        caminho.write_text(texto, newline="\\n")\n') == [1]
    assert _ocorrencias('    script.write_text(_script_do_pivot(), newline="\\n")\n') == [1]
    assert _ocorrencias('p.read_text(encoding="utf-8", newline="")\n') == [1]
    assert _ocorrencias('with io.open(p, "w", newline="\\n") as fh:\n') == []
    assert _ocorrencias('p.write_text(texto)\n') == []
