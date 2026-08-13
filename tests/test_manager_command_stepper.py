# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_manager_command_stepper.py
# DESCRIPTION: Testa o stepper do comando na tela Manager (_selo_comando).
#
#              O Mario relatou confundir um comando disparado (chaos) com a
#              cadencia automatica de captura, achando que nada tinha sido
#              coletado. O stepper mostra a etapa atual do comando, separada da
#              coluna Next (cadencia). Estes testes fixam: a etapa ativa por
#              status, o rotulo por comando, o desfecho, o carimbo de tempo e o
#              detalhe completo no tooltip. Nada de estado que o servidor nao
#              observa e afirmado (D-020).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import time


def _selo():
    from src.controllers.server_controller import _selo_comando
    return _selo_comando


def _cmd(status, command="chaos", result="", **kw):
    base = {"status": status, "command": command, "result": result,
            "created_at": time.time() - 120,
            "delivered_at": time.time() - 60,
            "finished_at": time.time() - 5}
    base.update(kw)
    return base


def test_empty_history_renders_nothing():
    """Sem comando, nada de stepper (nao polui a linha)."""
    assert _selo()(None) == ""
    assert _selo()({}) == ""


def test_pending_highlights_enqueued_stage():
    """PENDING: a etapa 'enfileirado' esta ativa; as demais, futuras."""
    html = _selo()(_cmd("PENDING"))
    assert "enfileirado" in html
    assert "chaos" in html
    # a etapa em curso nao pode aparecer como ja concluida (sem check nela)
    assert "no agente" in html


def test_sent_chaos_labels_scene_and_capture():
    """SENT do chaos rotula a parada 'no agente' como cenario + captura."""
    html = _selo()(_cmd("SENT"))
    assert "cenario + captura" in html
    # 'enfileirado' ja passou, entao ganha o check
    assert "&#10003; enfileirado" in html


def test_sent_collect_labels_capturing():
    """SENT do collect rotula a parada como capturando."""
    html = _selo()(_cmd("SENT", command="collect"))
    assert "capturando" in html


def test_done_shows_concluido_in_green():
    """DONE: desfecho 'concluido', com as duas etapas anteriores marcadas."""
    html = _selo()(_cmd("DONE", result="captura de 20s entregue"))
    assert "concluido" in html
    assert "&#10003; enfileirado" in html


def test_failed_shows_falhou():
    """FAILED: desfecho 'falhou'."""
    html = _selo()(_cmd("FAILED", result="chaos_maker.sh not installed"))
    assert "falhou" in html


def test_result_is_in_tooltip_and_summarized():
    """O resultado completo vai no title (ver detalhes); a linha visivel trunca."""
    longo = "x" * 200
    html = _selo()(_cmd("DONE", result=longo))
    # o tooltip carrega o resultado inteiro (o "ver detalhes")
    assert "title=" in html
    assert longo in html
    # a linha visivel (o div de resumo) fecha em 70 caracteres, nao despeja tudo
    assert ("x" * 70 + "</div>") in html


def test_in_progress_has_live_countdown_hook():
    """Etapas em curso trazem o gancho do cronometro vivo (data-since)."""
    html = _selo()(_cmd("SENT"))
    assert "cmd-live" in html
    assert "data-since=" in html


def test_finished_shows_absolute_time_not_countdown():
    """No desfecho o tempo e absoluto (as HH:MM:SS), nao um cronometro."""
    html = _selo()(_cmd("DONE", result="ok"))
    assert "as " in html
    # o desfecho nao deve ter o gancho de cronometro vivo
    assert "cmd-live" not in html


def test_unknown_command_still_renders_generic_stage():
    """Comando sem rotulo especifico ainda mostra 'no agente' generico."""
    html = _selo()(_cmd("SENT", command="algonovo"))
    assert "no agente" in html
    assert "algonovo" in html
