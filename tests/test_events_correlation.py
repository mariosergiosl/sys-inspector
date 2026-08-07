# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_events_correlation.py
# DESCRIPTION: O evento como entidade, e o que so ele torna possivel.
#
#              Ate aqui a ferramenta guardava ESTADO: como o host estava num
#              instante. Estado responde "o que existe"; a pericia precisa de
#              "o que aconteceu, e em que ordem". A frase que decide um laudo e
#              do tipo "o cron foi plantado quatro segundos DEPOIS de o shell
#              abrir", e nenhuma captura isolada a produz, por mais completa que
#              seja, porque ordem nao e propriedade de um retrato.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.core.events import (EventStore, make_event, corrected_ts,
                             events_from_capture, event_fingerprint,
                             EV_PROCESS_START, EV_CONNECTION, EV_PERSISTENCE,
                             EV_FINDING, EV_CAPTURE)
from src.core.correlation import (correlate, rule_active_c2,
                                  rule_persistence_after_activity,
                                  rule_fleet_campaign, MIN_RECORRENCIA)
from src.core.findings import SEV_CRITICAL, SEV_HIGH


@pytest.fixture
def loja(tmp_path):
    return EventStore(str(tmp_path / "ev.db"))


def _proc(ts, cmd, agente="a", score=0, offset=0.0):
    return make_event(ts, EV_PROCESS_START, agente, subject=cmd,
                      detail={"cmd": cmd, "score": score}, clock_offset=offset)


# ------------------------------------------------------------------------------
# O RELOGIO
# ------------------------------------------------------------------------------
def test_ordering_uses_the_corrected_clock():
    """
    Doze segundos de defasagem bastam para inverter causa e efeito entre hosts.
    A ordem so vale se calculada sobre o instante corrigido.
    """
    adiantado = make_event(1000, EV_PROCESS_START, "a", clock_offset=12.0)
    atrasado = make_event(995, EV_PROCESS_START, "b", clock_offset=0.0)

    # Pelo instante bruto, 'adiantado' parece posterior; corrigido, e anterior.
    assert adiantado["ts"] > atrasado["ts"]
    assert corrected_ts(adiantado) < corrected_ts(atrasado)


def test_the_timeline_is_ordered_by_the_corrected_clock(loja):
    loja.add([make_event(1000, EV_PROCESS_START, "a", subject="depois",
                         clock_offset=12.0),
              make_event(995, EV_PROCESS_START, "b", subject="antes")])

    assert [e["subject"] for e in loja.timeline()] == ["depois", "antes"]


def test_the_offset_travels_with_the_event(loja):
    """
    Guardar so o instante corrigido tornaria a ordenacao inauditavel: ninguem
    poderia conferir a premissa depois.
    """
    loja.add([make_event(1000, EV_PROCESS_START, "a", clock_offset=3.5)])
    ev = loja.timeline()[0]
    assert ev["clock_offset"] == 3.5
    assert ev["ts"] == 1000


# ------------------------------------------------------------------------------
# O ARMAZENAMENTO
# ------------------------------------------------------------------------------
def test_the_same_event_is_not_duplicated(loja):
    """
    Reprocessar uma captura nao pode inventar repeticao: repeticao no tempo e
    justamente o que a correlacao usa para distinguir acao pontual de
    persistencia ativa.
    """
    ev = _proc(1000, "/tmp/x")
    loja.add([ev])
    loja.add([ev])

    assert len(loja.timeline()) == 1


def test_the_same_command_at_different_times_are_distinct_events():
    """Duas execucoes sao dois fatos; agrupa-las apagaria a recorrencia."""
    assert event_fingerprint(_proc(1000, "/tmp/x")) != \
           event_fingerprint(_proc(2000, "/tmp/x"))


def test_the_timeline_can_cross_the_whole_fleet(loja):
    """
    Sem filtro de agente a linha atravessa a frota, que e onde aparece o
    encadeamento que uma maquina sozinha nao mostra.
    """
    loja.add([_proc(1000, "x", agente="a"), _proc(1001, "y", agente="b")])
    assert len(loja.timeline()) == 2
    assert len(loja.timeline(agent_uuid="a")) == 1


def test_a_window_can_be_isolated(loja):
    loja.add([_proc(100, "antigo"), _proc(5000, "recente")])
    assert [e["subject"] for e in loja.timeline(inicio=4000)] == ["recente"]


# ------------------------------------------------------------------------------
# DERIVACAO A PARTIR DA CAPTURA
# ------------------------------------------------------------------------------
def test_events_are_derived_without_collecting_anything_new():
    """
    O modelo e aditivo: le como sequencia o que ja estava guardado como estado.
    Por isso capturas ANTIGAS tambem alimentam a linha do tempo.
    """
    payload = {"timestamp": 5000,
               "processes": {"1": {"pid": 1, "cmd": "/tmp/x",
                                   "start_time": 4990, "anomaly_score": 90,
                                   "connections": ["10.0.0.1:4444"]}},
               "findings": [{"title": "achado", "severity": "High"}]}

    tipos = [e["type"] for e in events_from_capture(payload, "a", 7)]
    assert EV_PROCESS_START in tipos
    assert EV_CONNECTION in tipos
    assert EV_FINDING in tipos
    assert EV_CAPTURE in tipos


def test_a_process_keeps_its_own_instant():
    """O processo tem hora propria; usar a da captura apagaria a sequencia."""
    payload = {"timestamp": 5000,
               "processes": {"1": {"pid": 1, "cmd": "x", "start_time": 4990}}}
    inicio = [e for e in events_from_capture(payload, "a")
              if e["type"] == EV_PROCESS_START][0]
    assert inicio["ts"] == 4990


def test_a_finding_is_marked_as_observed_not_originated():
    """
    Um achado nao tem instante proprio: herda o da captura, que e quando passou
    a ser OBSERVADO, nao quando o artefato surgiu. Confundir os dois faria o
    laudo afirmar mais do que se sabe.
    """
    payload = {"timestamp": 5000, "findings": [{"title": "x", "severity": "High"}]}
    ev = [e for e in events_from_capture(payload, "a")
          if e["type"] == EV_FINDING][0]
    assert ev["ts"] == 5000
    assert ev["detail"]["observed_only"] is True


# ------------------------------------------------------------------------------
# CORRELACAO: A CONCLUSAO QUE NENHUM SINAL SUSTENTA SOZINHO
# ------------------------------------------------------------------------------
def test_three_weak_signals_become_one_conclusion():
    """
    Processo em /tmp acontece; conexao de saida acontece; reaparecer acontece.
    Os tres no MESMO processo nao sao tres observacoes, sao uma, e tem nome.
    """
    eventos = [_proc(1000 + i, "/tmp/miner") for i in range(MIN_RECORRENCIA)]
    eventos.append(make_event(1001, EV_CONNECTION, "a", subject="10.0.0.9:4444",
                              detail={"cmd": "/tmp/miner"}))

    achado = rule_active_c2(eventos)[0]
    assert achado.severity == SEV_CRITICAL
    assert achado.technique == "T1071"


def test_a_single_execution_is_not_persistence():
    """Rodar uma vez e acao pontual; chamar de persistencia seria exagero."""
    eventos = [_proc(1000, "/tmp/x"),
               make_event(1001, EV_CONNECTION, "a", subject="1.2.3.4:80",
                          detail={"cmd": "/tmp/x"})]
    assert rule_active_c2(eventos) == []


def test_a_recurring_process_without_network_is_not_c2():
    """Sem canal de saida nao ha comando e controle a alegar."""
    eventos = [_proc(1000 + i, "/tmp/x") for i in range(5)]
    assert rule_active_c2(eventos) == []


def test_a_legitimate_path_is_not_flagged():
    """Servico do sistema que reinicia e reconecta nao pode virar incidente."""
    eventos = [_proc(1000 + i, "/usr/sbin/sshd") for i in range(5)]
    eventos.append(make_event(1001, EV_CONNECTION, "a", subject="1.2.3.4:22",
                              detail={"cmd": "/usr/sbin/sshd"}))
    assert rule_active_c2(eventos) == []


def test_sequence_turns_proximity_into_a_finding():
    """
    A regra que so o modelo de eventos torna possivel: depende de ORDEM, nao de
    estado. "O cron surgiu 4s depois do shell abrir" nenhuma captura produz.
    """
    eventos = [_proc(1000, "/tmp/shell", score=90),
               make_event(1004, EV_PERSISTENCE, "a",
                          subject="/etc/cron.d/evil")]

    achado = rule_persistence_after_activity(eventos)[0]
    assert achado.evidence["intervalo_s"] == 4
    assert "4 segundo" in achado.description


def test_distant_events_are_not_related():
    """
    Janela larga demais faz coincidencia entrar como causa, e uma correlacao
    que aceita qualquer coisa deixa de informar.
    """
    eventos = [_proc(1000, "/tmp/shell", score=90),
               make_event(99000, EV_PERSISTENCE, "a", subject="/etc/cron.d/x")]
    assert rule_persistence_after_activity(eventos) == []


def test_persistence_before_the_process_is_not_attributed():
    """Efeito nao precede causa; sem isso a regra inventaria relacao."""
    eventos = [make_event(1000, EV_PERSISTENCE, "a", subject="/etc/cron.d/x"),
               _proc(2000, "/tmp/shell", score=90)]
    assert rule_persistence_after_activity(eventos) == []


def test_the_same_artefact_on_two_hosts_is_a_campaign():
    """
    Um host comprometido e incidente; varios com o mesmo artefato mudam a
    resposta inteira, de limpar maquina para achar o vetor comum.
    """
    eventos = [_proc(1000, "/tmp/implant", agente="a"),
               _proc(1000, "/tmp/implant", agente="b")]

    achado = rule_fleet_campaign(eventos)[0]
    assert achado.severity == SEV_HIGH
    assert achado.evidence["quantidade"] == 2


def test_one_host_alone_is_not_a_campaign():
    eventos = [_proc(1000, "/tmp/implant", agente="a"),
               _proc(2000, "/tmp/implant", agente="a")]
    assert rule_fleet_campaign(eventos) == []


# ------------------------------------------------------------------------------
# ROBUSTEZ E HONESTIDADE
# ------------------------------------------------------------------------------
def test_a_broken_rule_does_not_silence_the_others(monkeypatch):
    """
    Sao leituras independentes do mesmo material; perder todas por causa de uma
    seria trocar analise parcial por nenhuma.
    """
    import src.core.correlation as c

    def _explode(eventos):
        raise RuntimeError("regra defeituosa")

    monkeypatch.setattr(c, "REGRAS", (_explode, c.rule_fleet_campaign))
    eventos = [_proc(1000, "/tmp/x", agente="a"),
               _proc(1000, "/tmp/x", agente="b")]

    assert len(c.correlate(eventos)) == 1


def test_no_rule_claims_compromise():
    """
    Nenhuma regra afirma comprometimento: diz o que foi observado e o que
    verificar. A decisao continua com o analista.
    """
    eventos = [_proc(1000 + i, "/tmp/miner") for i in range(MIN_RECORRENCIA)]
    eventos.append(make_event(1001, EV_CONNECTION, "a", subject="1.2.3.4:1",
                              detail={"cmd": "/tmp/miner"}))

    for achado in correlate(eventos):
        assert achado.recommendation
        texto = achado.description.lower()
        assert "comprometido" not in texto and "invadido" not in texto


def test_an_empty_timeline_produces_nothing():
    assert correlate([]) == []
    assert correlate(None) == []


# ------------------------------------------------------------------------------
# A LIGACAO COM O SERVIDOR
# ------------------------------------------------------------------------------
def test_events_are_derived_at_ingestion():
    """
    Derivar na ingestao e o unico momento em que o servidor tem a chave e o dado
    juntos. Fazer sob demanda obrigaria a decifrar tudo de novo a cada abertura
    da tela.
    """
    import io
    import os
    fonte = io.open(os.path.join("src", "controllers", "server_controller.py"),
                    encoding="utf-8").read()
    assert "_registrar_eventos" in fonte
    assert "on_stored=_registrar_eventos" in fonte


def test_the_hook_runs_before_the_entry_is_closed():
    """
    Se a derivacao falhar, a entrada nao pode ser dada por processada: o dado
    se perderia em silencio, que e a classe de defeito que mais custou aqui.
    """
    import io
    import os
    fonte = io.open(os.path.join("src", "core", "ingest.py"),
                    encoding="utf-8").read()
    bloco = fonte.split("def process_batch")[1]
    assert bloco.index("on_stored(") < bloco.index('queue.mark_done')


def test_a_failing_hook_does_not_lose_the_capture():
    """A captura ja esta gravada; a linha do tempo e leitura, nao o registro."""
    import io
    import os
    fonte = io.open(os.path.join("src", "core", "ingest.py"),
                    encoding="utf-8").read()
    bloco = fonte.split("if on_stored:")[1][:400]
    assert "except Exception" in bloco


def test_the_timeline_page_exists():
    import io
    import os
    fonte = io.open(os.path.join("src", "controllers", "server_controller.py"),
                    encoding="utf-8").read()
    assert "'/timeline'" in fonte
    assert "_serve_timeline" in fonte


def test_the_page_shows_the_gap_between_events():
    """
    "+4s" transforma uma lista de horarios em sequencia legivel, e sequencia e
    o que a tela existe para mostrar.
    """
    import io
    import os
    fonte = io.open(os.path.join("src", "controllers", "server_controller.py"),
                    encoding="utf-8").read()
    bloco = fonte.split("def _serve_timeline")[1].split("def _serve_capabilities")[0]
    assert "+%ds" in bloco


def test_the_page_marks_a_corrected_clock():
    """
    O analista precisa saber que aquele horario foi ajustado, senao a correcao
    vira premissa invisivel.
    """
    import io
    import os
    fonte = io.open(os.path.join("src", "controllers", "server_controller.py"),
                    encoding="utf-8").read()
    bloco = fonte.split("def _serve_timeline")[1].split("def _serve_capabilities")[0]
    assert "corrigido" in bloco
    assert "corrected_ts" in bloco


def test_correlation_runs_over_what_is_displayed():
    """
    Uma conclusao tirada de material que o analista nao ve seria impossivel de
    conferir.
    """
    import io
    import os
    fonte = io.open(os.path.join("src", "controllers", "server_controller.py"),
                    encoding="utf-8").read()
    bloco = fonte.split("def _serve_timeline")[1].split("def _serve_capabilities")[0]
    assert "correlate(eventos)" in bloco


# ------------------------------------------------------------------------------
# CAMINHO GRAVAVEL: OS DOIS ERROS OPOSTOS, APRENDIDOS EM CAMPO
# ------------------------------------------------------------------------------
def test_a_writable_directory_as_argument_is_not_execution():
    """
    Falso positivo real: `/usr/lib/gvfs/gvfsd-fuse /run/user/0/gvfs -f`, servico
    legitimo, foi acusado em quatro hosts de uma vez porque o caminho gravavel
    aparecia como argumento de DIRETORIO de trabalho. Nesta regra o custo e
    especifico: ela afirma "campanha", e uma campanha inventada manda o analista
    procurar vetor comum que nao existe.
    """
    from src.core.correlation import _e_caminho_gravavel
    assert not _e_caminho_gravavel("/usr/lib/gvfs/gvfsd-fuse /run/user/0/gvfs -f")


def test_an_executable_in_a_writable_directory_is_flagged():
    from src.core.correlation import _e_caminho_gravavel
    assert _e_caminho_gravavel("/tmp/chaos/miner --threads 4")


def test_running_through_an_interpreter_is_still_caught():
    """
    O erro oposto, tambem observado em campo: olhar so o executavel deixa passar
    `/bin/bash /dev/shm/miner.sh`, porque o binario e legitimo e o codigo esta
    no argumento. Evasao trivial se a regra so olhasse o primeiro token.
    """
    from src.core.correlation import _e_caminho_gravavel
    assert _e_caminho_gravavel("/bin/bash /dev/shm/miner.sh")
    assert _e_caminho_gravavel("python3 /tmp/x/artifact.py")


def test_a_system_service_with_no_writable_path_is_quiet():
    from src.core.correlation import _e_caminho_gravavel
    assert not _e_caminho_gravavel("/usr/sbin/sshd -D")
    assert not _e_caminho_gravavel("")


def test_the_campaign_rule_no_longer_fires_on_the_real_false_positive():
    """Verificacao de ponta a ponta do caso que apareceu no laboratorio."""
    linha = "/usr/lib/gvfs/gvfsd-fuse /run/user/0/gvfs -f"
    eventos = [_proc(1000, linha, agente=h) for h in ("a", "b", "c", "d")]
    assert rule_fleet_campaign(eventos) == []
