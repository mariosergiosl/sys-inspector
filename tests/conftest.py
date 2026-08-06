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
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
