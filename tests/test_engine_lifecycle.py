# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_engine_lifecycle.py
# DESCRIPTION: O motor e reaproveitado entre ciclos sem acumular recursos.
#
#              Observado em campo: um agente rodando ha cerca de duas horas
#              chegou ao ciclo 285 e esgotou o limite de descritores do
#              processo. A partir dali nao conseguia mais abrir nem a chave nem
#              o banco, e as capturas deixaram de ser gravadas SEM que ele
#              parasse.
#
#              Esse e o modo de falha mais perigoso que este projeto ja
#              encontrou: o agente continuava aparentando funcionar enquanto nao
#              produzia mais evidencia alguma. Um agente que morre e visivel na
#              frota; um que emudece leva horas para ser notado, e nesse
#              intervalo o operador acredita estar coletando.
#
#              A causa: _poll_loop roda em uma thread NOVA a cada captura, e
#              chamava open_perf_buffer em cada uma. O BCC abre um descritor por
#              CPU a cada chamada e nao fecha os anteriores.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

FONTE = os.path.join("src", "core", "engine.py")


@pytest.fixture(scope="module")
def codigo():
    return io.open(FONTE, encoding="utf-8").read()


# ------------------------------------------------------------------------------
# O VAZAMENTO
# ------------------------------------------------------------------------------
def test_the_perf_buffer_is_opened_only_once(codigo):
    """
    A guarda e o que impede o acumulo. Sem ela, cada ciclo abre um descritor por
    CPU que nunca sera fechado, e o agente tem prazo de validade.
    """
    bloco = codigo.split("def _poll_loop")[1].split("def start")[0]
    assert "_perf_buffer_aberto" in bloco
    assert "open_perf_buffer" in bloco

    guarda = bloco.index("if not self._perf_buffer_aberto")
    abertura = bloco.index("open_perf_buffer(")
    assert guarda < abertura, "a abertura precisa estar protegida pela guarda"


def test_the_flag_starts_false(codigo):
    """Iniciar como aberto puliaria a unica abertura legitima."""
    assert "self._perf_buffer_aberto = False" in codigo


def test_the_bpf_object_is_also_created_only_once(codigo):
    """
    A guarda do buffer so e valida porque o objeto BPF sobrevive entre ciclos.
    Se ele fosse recriado, o buffer antigo apontaria para um objeto morto.
    """
    bloco = codigo.split("def _init_bpf")[1].split("def ")[0]
    assert "if self.bpf: return" in bloco


def test_the_reason_is_written_down(codigo):
    """
    O comentario anterior ja dizia "only once" e estava errado, porque a funcao
    roda numa thread nova a cada captura. Sem explicar por que a guarda existe,
    alguem a removeria de novo pelo mesmo raciocinio.
    """
    bloco = codigo.split("def _poll_loop")[1].split("def start")[0]
    assert "thread" in bloco.lower()
    assert "descritor" in bloco.lower()


# ------------------------------------------------------------------------------
# A ARVORE, QUE TAMBEM E REAPROVEITADA
# ------------------------------------------------------------------------------
def test_the_tree_can_be_emptied_between_captures():
    """
    Mesmo motor, capturas independentes: sem reset a arvore acumulava processos
    ja encerrados e o laudo afirmava que existiam.
    """
    from src.collectors.process_tree import ProcessTree

    arvore = ProcessTree()
    arvore.add_or_update(10, 1, "x", 0, 120)
    arvore.reset()

    assert arvore.nodes == {}
