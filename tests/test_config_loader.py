# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_config_loader.py
# DESCRIPTION: Testa o carregamento de configuracao. Um arquivo ausente,
#              incompleto ou malformado nao pode derrubar o agente nem, pior,
#              fazer a coleta rodar com opcoes de seguranca silenciosamente
#              desligadas.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

import pytest

pytest.importorskip("yaml", reason="requer PyYAML")

from src.utils.config_loader import load_config, DEFAULT_CONFIG, _merge_defaults


def _write(content):
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as handle:
        handle.write(content)
    return path


def test_missing_file_falls_back_to_defaults():
    """Arquivo inexistente nao quebra: o agente usa os padroes."""
    cfg = load_config("/nonexistent/config.yaml")
    assert cfg is not None
    assert "general" in cfg


def test_partial_config_gets_the_missing_defaults():
    """
    Configuracao parcial e completada com os padroes, para uma secao ausente
    nao virar KeyError no meio de uma coleta.
    """
    path = _write("general:\n  mode: snapshot\n")
    try:
        cfg = load_config(path)
        assert cfg["general"]["mode"] == "snapshot"
        for section in DEFAULT_CONFIG:
            assert section in cfg, section
    finally:
        os.unlink(path)


def test_user_values_win_over_defaults():
    """O que o operador definiu prevalece sobre o padrao."""
    path = _write("storage:\n  sqlite_path: /tmp/custom.db\n")
    try:
        assert load_config(path)["storage"]["sqlite_path"] == "/tmp/custom.db"
    finally:
        os.unlink(path)


def test_empty_file_is_handled():
    """Arquivo vazio equivale a usar os padroes."""
    path = _write("")
    try:
        cfg = load_config(path)
        assert cfg is not None and "general" in cfg
    finally:
        os.unlink(path)


def test_merge_fills_only_what_is_missing():
    """A fusao completa lacunas sem sobrescrever o que ja existe."""
    merged = _merge_defaults({"a": {"x": 1}}, {"a": {"x": 9, "y": 2}, "b": 3})
    assert merged["a"]["x"] == 1
    assert merged["a"]["y"] == 2
    assert merged["b"] == 3


def test_defaults_keep_security_options_off():
    """
    Autenticacao e TLS vem desligados por padrao, e essa e uma decisao
    consciente: ligar sem o operador saber quebraria instalacoes existentes.
    O teste registra a escolha para que uma mudanca seja deliberada.
    """
    net = DEFAULT_CONFIG.get("network", {})
    assert net.get("tls_enabled", False) is False
    assert (net.get("auth", {}) or {}).get("enabled", False) is False
