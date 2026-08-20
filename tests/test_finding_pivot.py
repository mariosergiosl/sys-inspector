# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_finding_pivot.py
# DESCRIPTION: O atalho do achado para o processo na arvore (related_pids).
#
# WHY:         Achado do Mario testando a tela em 2026-08-20: os achados de
#              memoria nomeiam o PID no titulo, no alvo e na evidencia, e eram
#              justamente os unicos que NUNCA ganhavam o botao "Ver processo".
#
#              A causa era estreita e antiga: a correlacao so sabia casar
#              CAMINHO (`evidence["reference"]` contra `exe_path`/`cmd`), que e
#              a pergunta certa para um achado de persistencia ("a unit plantada
#              esta rodando agora?") e a pergunta errada para um achado de
#              runtime, que ja tem o PID na mao.
#
#              O resultado pratico era o pior possivel para quem le: o achado
#              com a identificacao MAIS precisa era o que menos ajudava a
#              navegar. Duas vias agora convivem, porque respondem perguntas
#              diferentes, e a ausencia do atalho continua significando algo em
#              cada uma delas.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.collectors.manager import correlate_findings_with_processes


def _proc(pid, cmd="/usr/bin/python3 script.py", exe="/usr/bin/python3"):
    return {str(pid): {"cmd": cmd, "exe_path": exe}}


def _achado(**kw):
    base = {"title": "achado", "target": "", "evidence": {}}
    base.update(kw)
    return base


# ------------------------------------------------------------------------------
# VIA 1: O PID QUE O ACHADO JA NOMEIA
# ------------------------------------------------------------------------------
def test_achado_de_processo_ganha_o_atalho_pelo_alvo():
    """O caso do relato: alvo "pid:NNNN" e o processo existe na captura."""
    achados = [_achado(target="pid:2271",
                       evidence={"pid": 2271, "cmd": "python3"})]
    correlate_findings_with_processes(achados, _proc(2271))
    assert achados[0]["related_pids"] == [2271]


def test_o_pid_tambem_e_lido_da_evidencia():
    """Nem todo coletor usa o alvo no formato pid:NNNN; a evidencia serve."""
    achados = [_achado(target="memoria", evidence={"pid": 2271})]
    correlate_findings_with_processes(achados, _proc(2271))
    assert achados[0]["related_pids"] == [2271]


def test_chave_de_processo_como_texto_ou_inteiro_da_no_mesmo():
    """
    A captura chega com as chaves em TEXTO quando vem do JSON e em INTEIRO
    quando vem do objeto vivo. Um atalho que some por causa do tipo da chave e
    o tipo de defeito que ninguem procura quando "o botao nao aparece".
    """
    achados = [_achado(target="pid:99", evidence={})]
    correlate_findings_with_processes(achados, {99: {"cmd": "x", "exe_path": "y"}})
    assert achados[0]["related_pids"] == [99]


def test_processo_que_ja_terminou_nao_ganha_atalho():
    """
    Ausencia continua significando alguma coisa: o processo morreu entre a
    deteccao e a montagem do laudo. Apontar para um PID que nao esta na arvore
    daria um botao que leva a lugar nenhum.
    """
    achados = [_achado(target="pid:4242", evidence={"pid": 4242})]
    correlate_findings_with_processes(achados, _proc(2271))
    assert "related_pids" not in achados[0]


def test_achado_que_nao_e_sobre_processo_continua_sem_atalho():
    """
    Um achado de kernel ou de arquivo nao tem PID, e isso nao e dado ausente:
    e a natureza do achado. Inventar um atalho ali seria pior que nao ter.
    """
    achados = [_achado(target="kernel", evidence={"taint_bits": []}),
               _achado(target="/etc/cron.d/evil", evidence={"content": "x"})]
    correlate_findings_with_processes(achados, _proc(2271))
    assert all("related_pids" not in a for a in achados)


def test_alvo_malformado_nao_quebra_a_captura():
    """Dado do host inspecionado e nao confiavel por definicao."""
    for alvo in ("pid:", "pid:abc", "pid:-1", "pid:99999999999999999999"):
        achados = [_achado(target=alvo)]
        correlate_findings_with_processes(achados, _proc(2271))
        assert "related_pids" not in achados[0], alvo


# ------------------------------------------------------------------------------
# VIA 2: O CAMINHO DENUNCIADO, QUE CONTINUA VALENDO
# ------------------------------------------------------------------------------
def test_persistencia_em_execucao_continua_ganhando_o_atalho():
    """
    A via antiga nao foi substituida. Ela responde outra pergunta: a unit
    plantada esta sendo executada AGORA? E isso e o que transforma persistencia
    teorica em atividade em curso.
    """
    achados = [_achado(target="/etc/systemd/system/evil.service",
                       evidence={"reference": "/tmp/evil-payload"})]
    processos = {"777": {"cmd": "/bin/bash /tmp/evil-payload", "exe_path": "/bin/bash"}}
    correlate_findings_with_processes(achados, processos)
    assert achados[0]["related_pids"] == [777]


def test_persistencia_plantada_e_nao_executada_nao_ganha_atalho():
    """
    O caso que o Mario viu na tela: o cron estava plantado e nao rodando, entao
    o botao nao aparecia -- e isso esta certo. Sem essa distincao, o atalho
    deixaria de informar se o artefato ja executou.
    """
    achados = [_achado(target="/etc/cron.d/evil-cron",
                       evidence={"reference": "/tmp/nunca-executado"})]
    correlate_findings_with_processes(achados, _proc(2271))
    assert "related_pids" not in achados[0]


def test_as_duas_vias_somam_sem_duplicar():
    """Achado que casa pelas duas vias lista cada PID uma vez so."""
    achados = [_achado(target="pid:555",
                       evidence={"pid": 555, "reference": "/tmp/payload"})]
    processos = {"555": {"cmd": "/tmp/payload", "exe_path": "/tmp/payload"},
                 "666": {"cmd": "/bin/sh /tmp/payload", "exe_path": "/bin/sh"}}
    correlate_findings_with_processes(achados, processos)
    assert achados[0]["related_pids"] == [555, 666]


# ------------------------------------------------------------------------------
# DA CORRELACAO ATE A TELA
# ------------------------------------------------------------------------------
def test_o_atalho_chega_ao_laudo():
    """
    Ponta a ponta: correlacionar sem desenhar o botao nao resolve nada, e foi
    exatamente esse trecho do caminho que o relato apontou.
    """
    from src.exporters.html_report import render_findings_panel

    achados = [_achado(title="Memoria gravavel e executavel em python3 (PID 2271)",
                       severity="Low", source="heuristic", rank=1,
                       target="pid:2271", description="d",
                       evidence={"pid": 2271})]
    correlate_findings_with_processes(achados, _proc(2271))
    html = render_findings_panel(achados)
    assert "fnd-pivot" in html
    assert "pivotToProcess('2271')" in html
    assert "Ver processo" in html


def test_varios_processos_dizem_quantos_sao():
    from src.exporters.html_report import render_findings_panel

    achados = [_achado(title="t", severity="Low", source="heuristic", rank=1,
                       target="/etc/x", description="d",
                       evidence={"reference": "/tmp/payload"})]
    processos = {"1": {"cmd": "/tmp/payload", "exe_path": "/tmp/payload"},
                 "2": {"cmd": "sh /tmp/payload", "exe_path": "/bin/sh"}}
    correlate_findings_with_processes(achados, processos)
    html = render_findings_panel(achados)
    assert "Ver 2 processos" in html
