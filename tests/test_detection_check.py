# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_detection_check.py
# DESCRIPTION: Afericao do termometro.
#
#              O cenario de teste e o instrumento com que se mede se a deteccao
#              funciona. Um instrumento que nunca e aferido nao mede nada: se um
#              artefato deixa de ser detectado, o resultado continua parecendo
#              normal e a conclusao errada fica indistinguivel da certa.
#
#              A distincao central destes testes: "o modulo nao rodou porque
#              falta gcc" e legitimo; "o artefato existe no host e a captura nao
#              o viu" e falha. Tratar os dois como falha esconderia justamente o
#              caso que importa, e foi essa confusao que atrasou o diagnostico
#              da diferenca entre os agentes do laboratorio.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

from src.core.detection_check import (check_detection, format_report,
                                      ARTEFATOS, OK, NAO_GERADO, NAO_VISTO,
                                      SEM_ROTULO)


def _arvore(entradas):
    """entradas: lista de (cmd, [rotulos])."""
    return dict((i, {"pid": 100 + i, "cmd": cmd, "context_tags": tags,
                     "anomaly_score": 0})
                for i, (cmd, tags) in enumerate(entradas))


def _estado(conferencia, artefato):
    for r in conferencia["results"]:
        if r["artifact"] == artefato:
            return r["state"]
    raise AssertionError("artefato ausente do relatorio: %s" % artefato)


# ------------------------------------------------------------------------------
# A DISTINCAO QUE IMPORTA
# ------------------------------------------------------------------------------
def test_artifact_present_and_captured_is_ok():
    ps = "1 /tmp/chaos/kryptominer"
    arvore = _arvore([("/tmp/chaos/kryptominer", ["MINER"])])

    assert _estado(check_detection(ps, arvore), "kryptominer") == OK


def test_artifact_present_but_not_captured_is_a_failure():
    """
    O unico caso que condena a ferramenta: o host tem, e a captura nao viu.
    """
    ps = "1 /tmp/chaos/kryptominer"
    conferencia = check_detection(ps, _arvore([]))

    assert _estado(conferencia, "kryptominer") == NAO_VISTO
    assert conferencia["summary"]["missed"] == 1
    assert conferencia["failures"]


def test_module_that_never_ran_is_not_a_failure():
    """
    Um agente sem gcc nao gera os artefatos compilados. Contar isso como falha
    de deteccao acusaria a ferramenta por algo que ela fez certo, e o ruido
    esconderia a falha verdadeira.
    """
    conferencia = check_detection("", _arvore([]))

    assert _estado(conferencia, "kryptominer") == NAO_GERADO
    assert conferencia["summary"]["missed"] == 0
    assert not conferencia["failures"]


def test_captured_without_the_expected_signal_is_a_failure():
    """
    Ver o processo nao basta. Foi assim que DELETED se perdeu: o processo
    aparecia na arvore, mas sem o sinal que explicava por que ele importava.
    """
    ps = "1 /tmp/chaos/deleted_sleep"
    arvore = _arvore([("/tmp/chaos/deleted_sleep", ["UNSAFE"])])

    conferencia = check_detection(ps, arvore)
    assert _estado(conferencia, "deleted_sleep") == SEM_ROTULO
    assert conferencia["summary"]["unlabelled"] == 1


def test_an_artifact_without_expected_signal_only_needs_to_be_seen():
    """
    Nem todo artefato existe para disparar um sinal: alguns geram carga ou
    ruido. Exigir rotulo deles produziria falha onde nao ha.
    """
    ps = "1 /tmp/chaos/artifact_io.py"
    arvore = _arvore([("python3 /tmp/chaos/artifact_io.py", [])])

    assert _estado(check_detection(ps, arvore), "artifact_io.py") == OK


# ------------------------------------------------------------------------------
# COBERTURA DO CENARIO
# ------------------------------------------------------------------------------
def test_every_artifact_of_the_scenario_is_checked():
    """
    A conferencia precisa cobrir o cenario inteiro. Um artefato ausente desta
    lista nunca seria cobrado, e a lacuna passaria despercebida exatamente como
    a que motivou esta analise.
    """
    nomes = [a[0] for a in ARTEFATOS]
    for esperado in ("kryptominer", "deleted_sleep", "artifact_zombie.py",
                     "artifact_unsafe.py", "fake_edr"):
        assert esperado in nomes


def test_signals_expected_from_the_scenario_are_real_labels():
    """
    Cobrar um rotulo que o coletor nunca produz criaria falha permanente e
    treinaria o operador a ignorar o relatorio.
    """
    import io
    import os
    import re
    fonte = io.open(os.path.join("src", "collectors", "process_tree.py"),
                    encoding="utf-8").read()
    produzidos = set(re.findall(
        r'(?:context_tags\.append|context_tags\.add|tags_accumulated\.add)'
        r'\(\s*"([^"]+)"', fonte))

    for _, rotulo, _d in ARTEFATOS:
        if rotulo:
            assert rotulo in produzidos, "sinal inexistente cobrado: %s" % rotulo


def test_dependencies_are_declared_for_compiled_artifacts():
    """
    Sem declarar a dependencia, um agente sem gcc apareceria como falha de
    deteccao, que foi a leitura errada feita no laboratorio.
    """
    from src.core.detection_check import DEPENDENCIAS
    assert DEPENDENCIAS.get("fake_edr") == "gcc"


# ------------------------------------------------------------------------------
# O RELATORIO
# ------------------------------------------------------------------------------
def test_report_separates_skipped_from_missed():
    ps = "1 /tmp/chaos/kryptominer"
    texto = format_report(check_detection(ps, _arvore([])))

    assert "NAO VISTO" in texto
    assert "nao gerado" in texto


def test_report_names_the_missing_tool():
    """Dizer apenas "nao gerado" deixaria o operador sem saber o que fazer."""
    texto = format_report(check_detection("", _arvore([]), ferramentas=set()))
    assert "nao tem gcc" in texto


def test_a_present_tool_is_not_blamed_for_the_absence():
    """
    Observado ao aferir o laboratorio: o relatorio dizia que o artefato faltou
    "por exigir gcc" num host que TEM gcc. Apontar a causa errada e pior do que
    nao apontar nenhuma, porque manda o operador instalar o que ja esta la.
    """
    texto = format_report(check_detection("", _arvore([]), ferramentas={"gcc"}))
    assert "nao tem gcc" not in texto
    assert "nao estava em execucao" in texto


def test_report_states_plainly_when_nothing_slipped_through():
    ps = "1 /tmp/chaos/kryptominer"
    arvore = _arvore([("/tmp/chaos/kryptominer", ["MINER"])])

    assert "Termometro aferido" in format_report(check_detection(ps, arvore))


def test_report_shows_what_came_instead_of_the_expected_signal():
    """Saber o que veio no lugar e o que permite diagnosticar sem repetir tudo."""
    ps = "1 /tmp/chaos/deleted_sleep"
    arvore = _arvore([("/tmp/chaos/deleted_sleep", ["UNSAFE"])])

    assert "esperava DELETED" in format_report(check_detection(ps, arvore))
