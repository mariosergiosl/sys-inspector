# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_ci_actions_atuais.py
# DESCRIPTION: A CI usa versoes das actions que rodam em Node.js 24.
#
# WHY:         A CI da 1.4.0 avisou que actions/checkout@v3 e
#              actions/setup-python@v3 rodam em Node.js 20, em descontinuacao no
#              GitHub (F-270). Conferido em 2026-10-11 no action.yml de cada
#              uma: checkout roda em node24 a partir da v5, setup-python a partir
#              da v6. A CI passou a usar a v7 das duas.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MINIMO_NODE24 = {"actions/checkout": 5, "actions/setup-python": 6}


def test_actions_da_ci_rodam_em_node24():
    """REPROVA A 1.4.1: as duas estavam na v3."""
    with io.open(os.path.join(RAIZ, ".github/workflows/ci.yml"),
                 encoding="utf-8") as fh:
        usos = re.findall(r"uses:\s*([\w./-]+)@v(\d+)", fh.read())
    vistos = {nome: int(versao) for nome, versao in usos}
    for nome, minimo in MINIMO_NODE24.items():
        assert nome in vistos, nome
        assert vistos[nome] >= minimo, (nome, vistos[nome])
