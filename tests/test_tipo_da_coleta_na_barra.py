# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_tipo_da_coleta_na_barra.py
# DESCRIPTION: Trava o tipo da captura na barra de navegacao do laudo (F-255).
#
# WHY:         Pedido do Mario em 2026-10-09, avaliando a 1.3.1: depois de rodar
#              o cenario de teste na .161, a captura do cenario (17:36:33, 284
#              processos) era visualmente igual as vizinhas, com uma captura a
#              cada ~40 s. O agente grava o tipo (completa, cenario, ociosa) e o
#              tipo chega ao banco do servidor, mas nenhuma tela o exibia:
#              get_history nem o devolvia.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile
import time

import pytest

from src.core.database import (DatabaseManager, CAPTURE_IDLE, CAPTURE_FULL,
                               CAPTURE_CHAOS)


def _controlador():
    """Modulo do servidor; exige pwd (Linux), como os demais testes da barra."""
    return pytest.importorskip(
        "src.controllers.server_controller",
        reason="o controlador importa process_tree, que exige pwd (Linux)")


def _nav(escolhido_id, historico):
    """Chama _navegacao_de_capturas sem subir a pilha HTTP."""
    mod = _controlador()

    class _Portador(object):
        _navegacao_de_capturas = mod.ServerHTTPHandler._navegacao_de_capturas

    return _Portador()._navegacao_de_capturas("uuid-x", {"id": escolhido_id},
                                              historico)


def test_get_history_devolve_o_tipo_da_captura():
    """REPROVA A VERSAO ANTERIOR: get_history nao trazia capture_type, e a
    barra nao tinha de onde tirar o tipo."""
    d = tempfile.mkdtemp()
    db = DatabaseManager(db_path=os.path.join(d, "t.db"), max_snapshots=100)
    db.insert_snapshot({"x": 1}, agent_uuid="a", capture_type=CAPTURE_CHAOS)
    time.sleep(0.02)
    db.insert_snapshot({"x": 2}, agent_uuid="a", capture_type=CAPTURE_FULL)
    tipos = [r["capture_type"] for r in db.get_history(0, time.time() + 10)]
    assert tipos == [CAPTURE_FULL, CAPTURE_CHAOS]


def test_a_barra_diz_que_a_captura_e_de_cenario():
    """REPROVA A VERSAO ANTERIOR: a captura do cenario nao se distinguia."""
    historico = [{"id": 3, "capture_type": "full"},
                 {"id": 2, "capture_type": "chaos"},
                 {"id": 1, "capture_type": "full"}]
    html = _nav(2, historico)
    assert "cenario de teste" in html
    assert 'class="tipo-captura"' in html


def test_a_barra_diz_que_a_captura_e_completa_ou_ociosa():
    historico = [{"id": 2, "capture_type": "idle"},
                 {"id": 1, "capture_type": "full"}]
    assert ">ociosa<" in _nav(2, historico)
    assert ">completa<" in _nav(1, historico)


def test_captura_unica_tambem_diz_o_tipo():
    """Sem setas, a contagem continua dita, e o tipo tambem (D-020)."""
    html = _nav(1, [{"id": 1, "capture_type": "chaos"}])
    assert "captura 1 de 1" in html
    assert "cenario de teste" in html


def test_tipo_ausente_nao_vira_completa():
    """Captura gravada antes da coluna existir: dizer que nao foi registrado,
    nunca presumir 'completa' (D-020, tres estados)."""
    html = _nav(1, [{"id": 1, "capture_type": None}, {"id": 0}])
    assert "tipo nao registrado" in html
    assert ">completa<" not in html


def test_tipo_desconhecido_aparece_e_nao_injeta_html():
    """Um tipo que esta versao nao conhece aparece pelo nome, com aviso, em vez
    de sumir; e o nome passa por filtro antes de entrar no HTML."""
    html = _nav(1, [{"id": 1, "capture_type": "<script>x"}])
    assert "<script>" not in html
    assert "scriptx" in html
    assert "desconhecido" in html


def test_a_seta_avisa_o_tipo_da_vizinha():
    """Decidir antes de clicar: a seta diz para que tipo de captura ela leva."""
    historico = [{"id": 3, "capture_type": "full"},
                 {"id": 2, "capture_type": "full"},
                 {"id": 1, "capture_type": "chaos"}]
    html = _nav(2, historico)
    assert "mais antiga que esta (cenario de teste)" in html
    assert "mais recente que esta (completa)" in html


def test_todo_tipo_gravado_tem_rotulo_na_barra():
    """Colisao entre o agente/banco e a tela: um tipo novo em database.py sem
    rotulo aqui apareceria como 'desconhecido'. Contrato lido do codigo."""
    mod = _controlador()
    assert set(mod._TIPOS_DE_CAPTURA) == {CAPTURE_IDLE, CAPTURE_FULL,
                                          CAPTURE_CHAOS}
