# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_suite_nao_suja_o_tmp.py
# DESCRIPTION: Trava o desvio dos temporarios da suite para uma pasta da sessao.
#
# WHY:         Medido em 2026-10-10 na VM de testes: cada rodada da suite deixava
#              cerca de 430 diretorios tmpXXXX no /tmp, e ja eram 16833 desde
#              agosto (F-273). O conftest passou a desviar o tempfile para uma
#              pasta da sessao, apagada ao fim quando a suite passa.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import sys
import tempfile

import pytest


def test_mkdtemp_cai_na_pasta_da_sessao():
    """REPROVA A VERSAO ANTERIOR: o mkdtemp caia direto no /tmp do host."""
    sessao = os.path.realpath(tempfile.gettempdir())
    assert os.path.basename(sessao).startswith("si-pytest-"), sessao
    d = tempfile.mkdtemp()
    assert os.path.realpath(d).startswith(sessao + os.sep)


def test_o_desvio_vale_antes_da_coleta():
    """O teste de chaos cria o diretorio dele no corpo da classe, durante a
    importacao do modulo: o desvio tem de existir antes disso. Usa o modulo
    que a coleta ja carregou; importar de novo criaria o diretorio agora, com
    o desvio ja feito, e o teste passaria mesmo sem ele valer na coleta."""
    carregados = [m for n, m in list(sys.modules.items())
                  if n.split(".")[-1] == "test_chaos_failure_reporting"]
    if not carregados:
        pytest.skip("rodar junto com tests/test_chaos_failure_reporting.py")
    t = carregados[0]
    sessao = os.path.realpath(tempfile.gettempdir())
    assert os.path.basename(sessao).startswith("si-pytest-"), sessao
    assert os.path.realpath(t._Daemon.CHAOS_LOG_DIR).startswith(sessao + os.sep)
