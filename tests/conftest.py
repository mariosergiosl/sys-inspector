# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/conftest.py
# DESCRIPTION: Configuracao compartilhada do pytest. Garante que 'import src...'
#              funcione a partir da raiz do repositorio, independente de onde o
#              pytest e invocado.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import shutil
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

# [F-273] Temporarios da suite numa pasta so, apagada quando a suite passa.
# Medido em 2026-10-10 na VM de testes: cada rodada deixava cerca de 430
# diretorios tmpXXXX no /tmp (um banco t.db e um .agent_id em cada), porque os
# testes usam tempfile.mkdtemp sem limpar; ja eram 16833 desde agosto. Este
# arquivo e importado antes da coleta, entao o desvio pega tambem o mkdtemp
# feito no corpo de uma classe. Com falha, a pasta fica, para investigar.
TMP_DA_SESSAO = tempfile.mkdtemp(prefix="si-pytest-")
tempfile.tempdir = TMP_DA_SESSAO


def pytest_sessionfinish(session, exitstatus):
    """Apaga os temporarios da sessao se a suite passou; senao diz onde estao."""
    tempfile.tempdir = None
    if exitstatus == 0:
        shutil.rmtree(TMP_DA_SESSAO, ignore_errors=True)
    else:
        sys.stderr.write("\n[conftest] temporarios mantidos em %s\n"
                         % TMP_DA_SESSAO)
