# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_conteiner_por_formato.py
# DESCRIPTION: Trava a deteccao de conteiner pelo FORMATO do ID no cgroup
#              (C-166), e nao por substring.
#
# WHY:         _get_container_info fazia `"docker" in line`. O dockerd e o
#              containerd do host tem `0::/system.slice/docker.service`, e
#              viravam "conteiner docker" com id 'service' em QUALQUER host com
#              Docker. Medindo na .161 em 2026-10-09 apareceu um segundo caso:
#              o conmon do Podman, que roda no HOST, tem
#              `libpod-conmon-<hex>.scope` e virava conteiner podman com id
#              'conmon2026ed'. Esse badge e a porta de entrada da analise de
#              fuga de conteiner: marcar processo do host como conteiner apaga
#              justamente a fronteira que essa analise precisa enxergar.
#
#              As linhas abaixo sao as MEDIDAS na .161 (cgroup v2, Docker
#              28.5.1, Podman 4.9.5), mais a forma do cgroup v1.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io

import pytest

pt = pytest.importorskip(
    "src.collectors.process_tree",
    reason="process_tree importa pwd, que so existe em Linux")

DOCKER_HEX = "7319d8e0c61ef24d54bf18294adf90c6c1fbba3f82ea77328f205b047c395bc0"
PODMAN_HEX = "2026edd24ff22110810b8efefb788bb0c0a281016d6101a8a03ef65effcc5ad2"


def _info(monkeypatch, conteudo):
    """Roda _get_container_info entregando `conteudo` como /proc/PID/cgroup."""
    def _abrir(caminho, *args, **kwargs):
        assert caminho.endswith("/cgroup")
        return io.StringIO(conteudo)
    monkeypatch.setattr(pt, "open", _abrir, raising=False)
    return pt._get_container_info(1234)


def test_dockerd_do_host_nao_e_conteiner(monkeypatch):
    """REPROVA A VERSAO ANTERIOR: virava docker com id 'service'."""
    assert _info(monkeypatch, "0::/system.slice/docker.service\n") == (
        None, "host")


def test_conmon_do_podman_nao_e_conteiner(monkeypatch):
    """REPROVA A VERSAO ANTERIOR: virava podman com id 'conmon2026ed'."""
    linha = "0::/machine.slice/libpod-conmon-%s.scope\n" % PODMAN_HEX
    assert _info(monkeypatch, linha) == (None, "host")


def test_conteiner_docker_cgroup_v2(monkeypatch):
    linha = "0::/system.slice/docker-%s.scope\n" % DOCKER_HEX
    assert _info(monkeypatch, linha) == (DOCKER_HEX[:12], "docker")


def test_conteiner_docker_cgroup_v1(monkeypatch):
    conteudo = ("12:pids:/docker/%s\n11:memory:/docker/%s\n"
                % (DOCKER_HEX, DOCKER_HEX))
    assert _info(monkeypatch, conteudo) == (DOCKER_HEX[:12], "docker")


def test_conteiner_podman(monkeypatch):
    linha = "0::/machine.slice/libpod-%s.scope\n" % PODMAN_HEX
    assert _info(monkeypatch, linha) == (PODMAN_HEX[:12], "podman")


def test_processo_comum_do_host(monkeypatch):
    linha = "0::/user.slice/user-0.slice/session-86.scope\n"
    assert _info(monkeypatch, linha) == (None, "host")


def test_nome_parecido_sem_id_nao_e_conteiner(monkeypatch):
    """Unidade do systemd que so CITA docker no nome nao e conteiner."""
    linha = "0::/system.slice/docker-cleanup.service\n"
    assert _info(monkeypatch, linha) == (None, "host")
