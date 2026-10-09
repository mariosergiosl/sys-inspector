# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_captura_marcada_pelo_cenario.py
# DESCRIPTION: Trava a marcacao da captura pelo cenario OBSERVADO (C-154).
#
# WHY:         Apontado pelo Mario em 2026-10-09 navegando entre capturas: "ao
#              navegar eu deveria ver uma do caos_maker, tudo esta igual, como
#              completo". Medido na .161: das 7 capturas feitas com o cenario
#              vivo (17:36:33 a 17:41:39, 284 a 348 processos) so a dedicada,
#              disparada pelo comando, saiu marcada; as outras 6 eram
#              "completa". A marca dependia de o comando ter vindo da tela.
#
#              Decisao do Mario em 2026-08-20: o cenario se identifica sempre
#              que estiver rodando, venha de onde vier. So o NOME do script
#              (D-034).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os

import pytest

dc = pytest.importorskip(
    "src.controllers.daemon_controller",
    reason="o controlador do agente importa o motor eBPF")

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _arvore(*cmds):
    """Arvore serializada minima, no formato de ProcessTree.to_json()."""
    return {str(1000 + i): {"pid": 1000 + i, "cmd": c}
            for i, c in enumerate(cmds)}


@pytest.mark.parametrize("cmd", [
    "/bin/bash /opt/sys-inspector-test/tools/chaos_maker.sh --all --duration 300",
    "bash tools/chaos_maker.sh --all",
    "/usr/bin/chaos_maker.sh --all --duration 60",
    "sh /usr/bin/chaos_maker.sh",
])
def test_cenario_vivo_e_observado(cmd):
    """Linha de comando real medida na .161 e as outras formas de rodar."""
    assert dc.cenario_observado(_arvore("sleep 30", cmd))


@pytest.mark.parametrize("cmd", [
    "vim tools/chaos_maker.sh",
    "cat /tmp/si_chaos_1791578164-16768.log",
    "grep chaos_maker /var/log/messages",
    "/usr/bin/chaos_maker.sh.bak",
    "sleep 300",
    "",
])
def test_o_que_nao_e_o_cenario_rodando(cmd):
    assert not dc.cenario_observado(_arvore(cmd))


def test_arvore_vazia_ou_ausente():
    assert not dc.cenario_observado({})
    assert not dc.cenario_observado(None)


def test_o_tipo_da_captura_considera_a_observacao():
    """REPROVA A VERSAO ANTERIOR: o tipo vinha so de cycle_id == 'chaos'."""
    with io.open(os.path.join(RAIZ, "src/controllers/daemon_controller.py"),
                 encoding="utf-8") as fh:
        fonte = fh.read()
    corpo = fonte.split("def collect_and_store(")[1]
    assert "cenario_observado(full_data.get('processes'))" in corpo
    assert 'cycle_id == "chaos" or observado' in corpo
    assert "full_data['scenario_observed'] = observado" in corpo
