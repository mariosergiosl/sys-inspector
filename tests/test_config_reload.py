# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_config_reload.py
# DESCRIPTION: O agente rele a propria configuracao sem reiniciar.
#
#              Observado em campo: trocar o transporte do agente exigia reiniciar
#              o processo, e quem esquecia ficava com um agente tentando o
#              endereco antigo em backoff, sem erro visivel, enquanto o arquivo
#              ja dizia outra coisa. Reiniciar tambem descarta a janela de
#              captura em andamento, que numa investigacao pode ser justamente a
#              que interessa.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import time

import pytest
import yaml

from src.controllers.daemon_controller import DaemonController


class BancoFalso(object):
    agent_id = "agente-teste"

    def get_pending_snapshots(self, limit=10):
        return []


def _escrever(caminho, destino="10.0.0.1", intervalo=15, captura=15):
    dados = {"general": {"mode": "daemon"},
             "security": {"public_key_path": "chave.pub",
                          "private_key_path": "chave.pem"},
             "daemon": {"interval": intervalo, "capture_duration": captura,
                        "server_ip": destino, "auth_token": "t",
                        "server_port": 8080, "use_tls": False}}
    with io.open(caminho, "w", encoding="utf-8") as fh:
        yaml.safe_dump(dados, fh)


@pytest.fixture
def controller(tmp_path, monkeypatch):
    caminho = str(tmp_path / "config.yaml")
    _escrever(caminho)

    # A chave publica nao participa deste comportamento; carregar de verdade so
    # traria um arquivo a mais para o teste manter.
    monkeypatch.setattr("src.controllers.daemon_controller.load_public_key",
                        lambda p: "chave")

    from src.utils.config_loader import load_config
    ctrl = DaemonController(load_config(caminho), BancoFalso(), None)
    return ctrl, caminho


# ------------------------------------------------------------------------------
# RELEITURA
# ------------------------------------------------------------------------------
def test_untouched_file_is_not_reread(controller):
    """
    Reler a cada ciclo sem necessidade gastaria E/S no host inspecionado, que e
    justamente onde a ferramenta deve pesar o minimo.
    """
    ctrl, _ = controller
    assert ctrl.reload_config_if_changed() is False


def test_new_interval_takes_effect_without_restart(controller):
    ctrl, caminho = controller
    time.sleep(0.01)
    _escrever(caminho, intervalo=90, captura=45)
    os.utime(caminho, None)

    assert ctrl.reload_config_if_changed() is True
    assert ctrl.interval == 90
    assert ctrl.capture_duration == 45


def test_new_destination_takes_effect_without_restart(controller):
    """
    Era a falha silenciosa mais cara: o agente seguia falando com o servidor
    antigo enquanto o operador achava que ja tinha migrado.
    """
    ctrl, caminho = controller
    assert "10.0.0.1" in ctrl.outbox._base_url()

    _escrever(caminho, destino="10.0.0.9")
    os.utime(caminho, None)
    ctrl.reload_config_if_changed()

    assert "10.0.0.9" in ctrl.outbox._base_url()


def test_reload_clears_backoff_from_the_old_destination(controller):
    """
    O backoff pertence ao destino que falhou. Herda-lo faria o agente esperar
    minutos antes da primeira tentativa contra o endereco novo, que pode estar
    perfeitamente saudavel.
    """
    ctrl, caminho = controller
    ctrl.outbox._failures = 5
    ctrl.outbox._next_attempt = time.time() + 300

    _escrever(caminho, destino="10.0.0.9")
    os.utime(caminho, None)
    ctrl.reload_config_if_changed()

    assert ctrl.outbox._failures == 0
    assert ctrl.outbox._should_wait() is False


# ------------------------------------------------------------------------------
# ROBUSTEZ
# ------------------------------------------------------------------------------
def test_broken_file_does_not_stop_collection(controller):
    """
    Um erro de digitacao no arquivo nao pode derrubar a coleta: o agente segue
    com o que ja estava valendo e avisa.
    """
    ctrl, caminho = controller
    intervalo_anterior = ctrl.interval

    with io.open(caminho, "w", encoding="utf-8") as fh:
        fh.write("isto: nao: e: yaml: valido:\n  - [")
    os.utime(caminho, None)

    ctrl.reload_config_if_changed()
    assert ctrl.interval == intervalo_anterior


def test_broken_file_is_not_retried_every_cycle(controller):
    """Reprocessar o mesmo arquivo quebrado a cada ciclo so encheria o log."""
    ctrl, caminho = controller
    with io.open(caminho, "w", encoding="utf-8") as fh:
        fh.write("[[[")
    os.utime(caminho, None)

    ctrl.reload_config_if_changed()
    assert ctrl.reload_config_if_changed() is False


def test_config_records_its_own_origin(tmp_path):
    """
    Sem saber de qual arquivo veio, um processo de longa duracao nao teria como
    reler nada.
    """
    from src.utils.config_loader import load_config
    caminho = str(tmp_path / "config.yaml")
    _escrever(caminho)
    assert load_config(caminho).get("_source_path", "").endswith("config.yaml")


def test_a_typo_in_the_file_never_kills_a_running_agent(controller):
    """
    load_config encerra o processo quando o YAML nao parseia. Na partida isso e
    correto; num agente em operacao seria um erro de digitacao do operador
    derrubando a coleta de um host sob investigacao.
    """
    ctrl, caminho = controller
    with io.open(caminho, "w", encoding="utf-8") as fh:
        fh.write("chave: [sem fechar\n")
    os.utime(caminho, None)

    ctrl.reload_config_if_changed()   # nao pode levantar SystemExit
