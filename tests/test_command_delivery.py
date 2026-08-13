# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_command_delivery.py
# DESCRIPTION: O comando recolhido do servidor tem que chegar a quem executa.
#
#              Observado em campo: TODO pedido feito pelo painel aparecia como
#              "entregue" e nunca rodava. O agente conversa duas vezes com o
#              servidor no mesmo ciclo (entrega de capturas e check-in), e as
#              duas chamadas usavam o mesmo campo: a segunda apagava o que a
#              primeira tinha recolhido. Como o servidor entrega cada comando
#              uma unica vez, o pedido sumia sem deixar rastro.
#
#              Sao os testes mais importantes deste arquivo: o defeito era
#              invisivel para o operador, que so via um estado parado.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.core.outbox import Outbox


class BancoFalso(object):
    agent_id = "agente-teste"

    def get_pending_snapshots(self, limit=10):
        return []


@pytest.fixture
def outbox():
    caixa = Outbox(BancoFalso(), {"daemon": {"server_ip": "10.0.0.1",
                                             "auth_token": "t",
                                             "server_port": 8080,
                                             "use_tls": False}})
    caixa.respostas = []
    return caixa


def _responder(caixa, sequencia):
    """Substitui o transporte: cada POST devolve a proxima resposta prevista."""
    def _post(path, payload):
        return sequencia.pop(0) if sequencia else {}
    caixa._post = _post


# ------------------------------------------------------------------------------
# O COMANDO NAO PODE SUMIR
# ------------------------------------------------------------------------------
def test_command_survives_a_second_call_in_the_same_cycle(outbox):
    """
    A entrega de capturas e o check-in acontecem no mesmo ciclo. Se a segunda
    resposta (vazia, porque o servidor ja entregou) sobrescrever a primeira, o
    pedido e perdido enquanto o painel o mostra como entregue.
    """
    _responder(outbox, [{"slots": 5, "commands": [{"id": 1, "command": "collect"}]},
                        {"slots": 5, "commands": []}])

    outbox.request_slot(0)   # o que a entrega de capturas faz
    recolhidos = outbox.check_in()

    assert [c["id"] for c in recolhidos] == [1]


def test_success_bookkeeping_does_not_discard_commands(outbox):
    """
    Registrar que a conexao deu certo cuida do backoff, nao da fila de ordens.
    Zerar comandos ali descartava exatamente o que o check-in tinha buscado.
    """
    _responder(outbox, [{"slots": 5, "commands": [{"id": 7, "command": "chaos"}]}])

    assert [c["id"] for c in outbox.check_in()] == [7]


def test_commands_from_both_calls_are_kept(outbox):
    """Nenhuma das duas conversas do ciclo pode perder a sua parte."""
    _responder(outbox, [{"commands": [{"id": 1, "command": "collect"}]},
                        {"commands": [{"id": 2, "command": "chaos"}]}])

    outbox.request_slot(0)
    assert [c["id"] for c in outbox.check_in()] == [1, 2]


# ------------------------------------------------------------------------------
# ...E NEM PODE RODAR DUAS VEZES
# ------------------------------------------------------------------------------
def test_command_is_handed_over_only_once(outbox):
    """
    O servidor nao repete um comando ja entregue. Se o agente o mantivesse na
    lista, executaria o mesmo pedido a cada ciclo: um chaos_maker reiniciando
    sozinho para sempre.
    """
    _responder(outbox, [{"commands": [{"id": 1, "command": "collect"}]}, {}])

    assert len(outbox.check_in()) == 1
    assert outbox.check_in() == []


def test_nothing_pending_returns_empty(outbox):
    """Ciclo sem pedido nenhum nao pode inventar trabalho."""
    _responder(outbox, [{"slots": 5}])
    assert outbox.check_in() == []


def test_failed_checkin_keeps_earlier_commands(outbox):
    """
    Se o check-in falhar depois de a entrega ja ter recolhido um comando, o
    pedido precisa sobreviver: ele nao sera reenviado pelo servidor.
    """
    _responder(outbox, [{"commands": [{"id": 9, "command": "collect"}]}])

    outbox.request_slot(0)

    def _explode(path, payload):
        raise IOError("rede indisponivel")
    outbox._post = _explode

    assert [c["id"] for c in outbox.check_in()] == [9]


def test_disabled_outbox_asks_for_nothing(outbox):
    """Sem destino configurado nao ha com quem falar."""
    outbox.token = ""
    assert outbox.check_in() == []
