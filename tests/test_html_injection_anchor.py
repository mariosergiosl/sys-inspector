# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_html_injection_anchor.py
# DESCRIPTION: Protege contra a armadilha de injetar conteudo na string
#              "<body>" do relatorio.
#
#              Regressao real: o modo server passou a inserir um link de
#              retorno logo apos "<body>". Essa sequencia tambem existe DENTRO
#              do JavaScript do relatorio, na funcao de impressao
#              (win.document.write('</head><body>')), e a substituicao pegou a
#              ocorrencia errada. O link entrou dentro de uma string JS, cujas
#              aspas simples fecharam a string no meio, quebrando a sintaxe do
#              script INTEIRO: nenhuma funcao era definida e as abas, os filtros
#              e a arvore paravam de funcionar.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

from src.exporters.web_assets import HTML_TEMPLATE, JS_BLOCK

SERVER = os.path.join("src", "controllers", "server_controller.py")
LIVE = os.path.join("src", "controllers", "live_controller.py")


@pytest.fixture(scope="module")
def fontes():
    return {
        "server": io.open(SERVER, encoding="utf-8").read(),
        "live": io.open(LIVE, encoding="utf-8").read(),
    }


def test_body_string_also_exists_inside_the_script():
    """
    Documenta a causa: "<body>" nao e unico no relatorio, ele tambem aparece
    dentro do JavaScript. Por isso substituir por essa sequencia e inseguro.
    """
    assert "<body>" in JS_BLOCK


def test_no_controller_injects_on_the_body_string(fontes):
    """Nenhum controller pode ancorar injecao em "<body>"."""
    for nome, codigo in fontes.items():
        assert "replace('<body>'" not in codigo, nome
        assert 'replace("<body>"' not in codigo, nome


def test_controllers_use_a_markup_only_anchor(fontes):
    """
    A ancora usada existe apenas na marcacao do relatorio, nunca dentro do
    script, entao a injecao nao pode corromper o JavaScript.
    """
    ancora = '<div class="sticky-wrapper">'
    assert ancora in HTML_TEMPLATE
    assert ancora not in JS_BLOCK
    for nome, codigo in fontes.items():
        assert 'sticky-wrapper' in codigo, nome


def test_anchor_appears_once_in_the_template():
    """A ancora e unica, para a injecao acontecer em um unico lugar."""
    assert HTML_TEMPLATE.count('<div class="sticky-wrapper">') == 1


def test_report_javascript_stays_parseable_after_injection():
    """
    Simula a injecao sobre o esqueleto do relatorio e confere que o bloco de
    script continua integro: mesmo numero de aspas simples e nenhuma marcacao
    estranha dentro dele.
    """
    ancora = '<div class="sticky-wrapper">'
    link = ("<a href='/' style=\"position:fixed\">&larr; Fleet</a>")
    pagina = HTML_TEMPLATE.replace("{JS_BLOCK}", JS_BLOCK)
    injetada = pagina.replace(ancora, link + ancora, 1)

    inicio = injetada.index("<script")
    fim = injetada.index("</script>")
    script = injetada[inicio:fim]

    assert "Fleet</a>" not in script, "o link vazou para dentro do script"
    assert script.count("'") % 2 == 0, "aspas simples desbalanceadas no script"
