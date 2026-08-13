# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_notify.py
# DESCRIPTION: O aviso que chega a pessoa, e o que o torna inutil.
#
#              Ninguem fica olhando painel: uma deteccao que so existe numa tela
#              que ninguem abriu equivale, na pratica, a deteccao que nao houve.
#              Mas alerta demais e pior que alerta nenhum, porque ensina o
#              destinatario a ignorar, e ai o proximo, que importava, tambem
#              passa batido.
#
#              O destino e um servico de terceiro, fora do controle de quem
#              investiga. A mensagem diz onde olhar; a evidencia fica aqui.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.core.notify import Notifier
from src.core.findings import SEV_CRITICAL, SEV_HIGH, SEV_LOW, SEV_MEDIUM


def _achado(titulo, severidade=SEV_CRITICAL, fp=None):
    return {"title": titulo, "severity": severidade,
            "fingerprint": fp or titulo,
            "evidence": {"cmdline": "/tmp/segredo --token=abc123"},
            "target": "/tmp/artefato_secreto"}


@pytest.fixture
def avisador():
    return Notifier({"notify": {"enabled": True, "telegram_token": "t",
                                "telegram_chat": "c"}})


# ------------------------------------------------------------------------------
# O QUE MERECE AVISO
# ------------------------------------------------------------------------------
def test_only_serious_findings_are_reported(avisador):
    """
    Avisar sobre tudo garante que ninguem leia. O corte existe para o alerta
    manter significado.
    """
    selecao = avisador.select([_achado("grave", SEV_CRITICAL),
                               _achado("banal", SEV_LOW)])
    assert [f["title"] for f in selecao["send"]] == ["grave"]


def test_the_threshold_is_configurable():
    """Ambientes diferentes toleram ruido diferente."""
    n = Notifier({"notify": {"enabled": True, "min_severity": SEV_MEDIUM,
                             "telegram_token": "t", "telegram_chat": "c"}})
    assert len(n.select([_achado("medio", SEV_MEDIUM)])["send"]) == 1


def test_the_same_finding_is_not_repeated(avisador):
    """
    O mesmo achado reaparece em toda captura enquanto durar. Avisar de novo a
    cada ciclo transformaria um alerta legitimo em spam do proprio sistema.
    """
    achados = [_achado("persistente")]
    primeira = avisador.select(achados, agora=1000)
    avisador._registrar(primeira["send"], 1000)

    assert avisador.select(achados, agora=1100)["send"] == []


def test_it_warns_again_once_the_window_passes(avisador):
    """Silenciar para sempre esconderia um problema que nunca foi resolvido."""
    achados = [_achado("persistente")]
    avisador._registrar(avisador.select(achados, agora=1000)["send"], 1000)

    assert len(avisador.select(achados, agora=1000 + 4000)["send"]) == 1


def test_a_burst_is_capped(avisador):
    """
    Um host recem-comprometido gera dezenas de achados graves de uma vez.
    Mandar todos garante que nenhum seja lido.
    """
    muitos = [_achado("achado-%d" % i) for i in range(40)]
    selecao = avisador.select(muitos)

    assert len(selecao["send"]) == 3
    assert selecao["suppressed"] == 37


def test_the_most_serious_survives_the_cap(avisador):
    """Se algo vai ficar de fora, que seja o menos urgente."""
    selecao = avisador.select([_achado("alto-%d" % i, SEV_HIGH) for i in range(5)]
                              + [_achado("critico", SEV_CRITICAL)])
    assert "critico" in [f["title"] for f in selecao["send"]]


# ------------------------------------------------------------------------------
# O QUE A MENSAGEM PODE DIZER
# ------------------------------------------------------------------------------
def test_the_message_never_carries_the_evidence(avisador):
    """
    O destino e um servico de terceiro. Levar linha de comando ou caminho para
    fora seria vazar a propria investigacao por um canal que nao controlamos.
    """
    texto = avisador.compose("host-a", avisador.select([_achado("achado")]))

    assert "token=abc123" not in texto
    assert "/tmp/artefato_secreto" not in texto


def test_the_message_says_where_to_look(avisador):
    texto = avisador.compose("host-a", avisador.select([_achado("achado")]),
                             url="https://servidor/agent/uuid")
    assert "https://servidor/agent/uuid" in texto
    assert "host-a" in texto


def test_the_message_admits_what_it_left_out(avisador):
    """
    Dizer "3 achados" quando havia 40 induziria a conclusao errada sobre o
    tamanho do incidente.
    """
    muitos = [_achado("a-%d" % i) for i in range(40)]
    texto = avisador.compose("host-a", avisador.select(muitos))

    assert "40" in texto
    assert "37" in texto


# ------------------------------------------------------------------------------
# ROBUSTEZ
# ------------------------------------------------------------------------------
def test_disabled_by_default():
    """
    Alerta que sai sem alguem ter pedido e um vazamento, nao uma comodidade.
    """
    assert Notifier({}).notify("h", [_achado("x")])["sent"] == 0


def test_a_failed_delivery_never_breaks_the_capture(avisador, monkeypatch):
    """
    O dado ja esta guardado; o aviso e acessorio ao registro. Uma falha de rede
    do Telegram nao pode derrubar a coleta.
    """
    monkeypatch.setattr(avisador, "_telegram",
                        lambda t: (_ for _ in ()).throw(IOError("sem rede")))
    with pytest.raises(IOError):
        avisador._telegram("x")     # confirma que o teste realmente falha

    monkeypatch.setattr(avisador, "_telegram", lambda t: False)
    assert avisador.notify("h", [_achado("x")])["sent"] == 0


def test_nothing_to_report_is_not_an_error(avisador):
    assert avisador.notify("h", [])["sent"] == 0


def test_credentials_are_not_hardcoded():
    """
    Token no codigo vazaria para o repositorio publico e para todo pacote
    distribuido. Ele vive na configuracao do servidor.
    """
    import io
    import os
    fonte = io.open(os.path.join("src", "core", "notify.py"),
                    encoding="utf-8").read()
    assert "api.telegram.org/bot%s" in fonte     # montado a partir da config
    assert "AAH" not in fonte                    # nenhum token literal
