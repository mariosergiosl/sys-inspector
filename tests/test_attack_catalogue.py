# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_attack_catalogue.py
# DESCRIPTION: Toda tecnica que a ferramenta AFIRMA precisa ter verbete.
#
# WHY:         Um coletor atribuia "T1078" a uma conclusao e o catalogo local
#              nao conhecia esse identificador; a tela mostrava o codigo cru e o
#              leitor ficava sem saber o que a ferramenta estava afirmando. Sao
#              duas listas do mesmo fato mantidas em lugares diferentes, a
#              classe de defeito que ja custou caro neste projeto mais de uma
#              vez (tag_map, ARTEFATOS, legenda do score).
#
#              Este teste varre o codigo-fonte atras de `technique="..."` e
#              cobra verbete para cada um. Adicionar uma tecnica nova sem
#              explica-la quebra aqui, e nao no laudo de alguem.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re

from src.core.attack import TECHNIQUES, describe, technique_url

RAIZ = "src"
PADRAO = re.compile(r'technique\s*=\s*"(T\d{4}(?:\.\d{3})?)"')


def _tecnicas_no_codigo():
    encontradas = {}
    for pasta, _dirs, arquivos in os.walk(RAIZ):
        for nome in arquivos:
            if not nome.endswith(".py"):
                continue
            caminho = os.path.join(pasta, nome)
            texto = io.open(caminho, encoding="utf-8").read()
            for tecnica in PADRAO.findall(texto):
                encontradas.setdefault(tecnica, []).append(caminho)
    return encontradas


def test_o_codigo_afirma_alguma_tecnica():
    """Guarda contra o proprio teste passar por nao encontrar nada."""
    assert len(_tecnicas_no_codigo()) >= 10


def test_toda_tecnica_afirmada_tem_verbete():
    encontradas = _tecnicas_no_codigo()
    sem_verbete = dict((t, arqs) for t, arqs in encontradas.items()
                       if t not in TECHNIQUES)
    assert not sem_verbete, (
        "tecnicas afirmadas pelo codigo e sem verbete em src/core/attack.py: %s"
        % sem_verbete)


def test_todo_verbete_esta_completo():
    """Nome, tatica e uma frase do que a tecnica significa."""
    for tecnica, dados in TECHNIQUES.items():
        assert len(dados) == 3, tecnica
        nome, tatica, resumo = dados
        assert nome and tatica and resumo, tecnica
        assert len(resumo) > 50, tecnica


def test_a_url_da_subtecnica_usa_barra():
    assert technique_url("T1053.003").endswith("/T1053/003/")
    assert technique_url("T1014").endswith("/T1014/")


def test_tecnica_desconhecida_nao_levanta_excecao():
    """Um id novo apenas nao ganha legenda; nunca derruba a renderizacao."""
    assert describe("T9999") is None
    assert describe("") is None
    assert describe(None) is None
