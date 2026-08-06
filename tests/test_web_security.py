# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_web_security.py
# DESCRIPTION: Testes de seguranca do painel web, o modulo mais exposto do
#              produto e o que estava sem cobertura nenhuma: autenticacao,
#              allowlist de identificadores e TLS.
#
#              O painel serve evidencia forense e pode ficar acessivel na rede
#              (o bind padrao e 0.0.0.0, por escolha explicita), entao uma falha
#              aqui expoe a coleta inteira.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import tempfile

import pytest

flask = pytest.importorskip("flask", reason="requer Flask")
werkzeug_security = pytest.importorskip("werkzeug.security")

from werkzeug.security import generate_password_hash

from src.core.crypto import ensure_crypto_environment
from src.core.database import DatabaseManager
from src.controllers.web_controller import WebController, SAFE_ID_PATTERN


SENHA = "senha-de-teste"


def _config(tmpdir, auth=None, tls=False):
    """Configuracao minima para instanciar o painel."""
    pub = os.path.join(tmpdir, "public_key.pem")
    priv = os.path.join(tmpdir, "private_key.pem")
    ensure_crypto_environment(pub, priv)
    return {
        "security": {"public_key_path": pub, "private_key_path": priv},
        "network": {"bind_address": "127.0.0.1", "bind_port": 8080,
                    "auth": auth or {}, "tls_enabled": tls,
                    "ssl_cert": os.path.join(tmpdir, "cert.pem"),
                    "ssl_key": os.path.join(tmpdir, "key.pem")},
        "storage": {"sqlite_path": os.path.join(tmpdir, "test.db")},
        "server": {},
    }


def _controller(auth=None, tls=False):
    tmpdir = tempfile.mkdtemp()
    cfg = _config(tmpdir, auth=auth, tls=tls)
    db = DatabaseManager(db_path=cfg["storage"]["sqlite_path"])
    return WebController(cfg, db), tmpdir



def _basic(user, password):
    """
    Monta o cabecalho Basic manualmente: o parametro auth= do cliente de teste
    so existe em versoes recentes do Werkzeug, e o alvo suporta Python 3.6.
    """
    import base64
    token = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8"))
    return {"Authorization": "Basic " + token.decode("ascii")}


# ------------------------------------------------------------------------------
# Allowlist de identificadores
# ------------------------------------------------------------------------------
def test_allowlist_accepts_normal_agent_ids():
    """UUID de agente passa pela allowlist."""
    for value in ("03baa956-51c6-4af0-bb2d-e3d9850a50aa", "local", "AGENT-01"):
        assert SAFE_ID_PATTERN.match(value)


def test_allowlist_rejects_path_traversal_and_injection():
    """
    O identificador vai para consulta e para a pagina; qualquer coisa fora de
    letras, numeros e hifen e recusada antes de ser usada.
    """
    for value in ("../../etc/passwd", "a/b", "a'; DROP TABLE snapshots;--",
                  "<script>alert(1)</script>", "a b", "a;b", "a\x00b",
                  "%2e%2e%2f", ""):
        assert not SAFE_ID_PATTERN.match(value), value


def test_allowlist_rejects_overlong_input():
    """Identificador absurdamente longo e recusado."""
    assert not SAFE_ID_PATTERN.match("a" * 65)
    assert SAFE_ID_PATTERN.match("a" * 64)


# ------------------------------------------------------------------------------
# Autenticacao
# ------------------------------------------------------------------------------
def test_dashboard_is_open_when_auth_is_disabled():
    """
    Sem autenticacao configurada o painel continua aberto, preservando o
    comportamento de instalacoes existentes.
    """
    ctrl, _ = _controller()
    assert ctrl.auth_enabled is False
    resp = ctrl.app.test_client().get("/")
    assert resp.status_code == 200


def test_request_without_credentials_is_rejected():
    """Com autenticacao ligada, requisicao sem credencial recebe 401."""
    ctrl, _ = _controller(auth={"enabled": True, "username": "admin",
                                "password_hash": generate_password_hash(SENHA)})
    resp = ctrl.app.test_client().get("/")
    assert resp.status_code == 401
    assert "Basic" in resp.headers.get("WWW-Authenticate", "")


def test_correct_credentials_are_accepted():
    """Credencial correta passa pelo portao."""
    ctrl, _ = _controller(auth={"enabled": True, "username": "admin",
                                "password_hash": generate_password_hash(SENHA)})
    resp = ctrl.app.test_client().get("/", headers=_basic("admin", SENHA))
    assert resp.status_code == 200


def test_wrong_password_is_rejected():
    """Senha errada nao entra."""
    ctrl, _ = _controller(auth={"enabled": True, "username": "admin",
                                "password_hash": generate_password_hash(SENHA)})
    resp = ctrl.app.test_client().get("/", headers=_basic("admin", "errada"))
    assert resp.status_code == 401


def test_wrong_username_is_rejected():
    """Usuario errado nao entra, mesmo com a senha certa."""
    ctrl, _ = _controller(auth={"enabled": True, "username": "admin",
                                "password_hash": generate_password_hash(SENHA)})
    resp = ctrl.app.test_client().get("/", headers=_basic("outro", SENHA))
    assert resp.status_code == 401


def test_auth_enabled_without_hash_fails_closed():
    """
    Autenticacao ligada sem hash configurado precisa REJEITAR tudo. Falhar
    aberto aqui exporia a evidencia por um erro de configuracao.
    """
    ctrl, _ = _controller(auth={"enabled": True, "username": "admin",
                                "password_hash": ""})
    client = ctrl.app.test_client()
    assert client.get("/").status_code == 401
    assert client.get("/", headers=_basic("admin", "")).status_code == 401
    assert client.get("/", headers=_basic("admin", "qualquer")).status_code == 401


def test_password_is_never_stored_in_clear():
    """O painel guarda apenas o hash, nunca a senha."""
    hash_value = generate_password_hash(SENHA)
    ctrl, _ = _controller(auth={"enabled": True, "username": "admin",
                                "password_hash": hash_value})
    assert SENHA not in str(vars(ctrl))
    assert ctrl.auth_hash.startswith(("pbkdf2:", "scrypt:"))


def test_api_routes_are_also_protected():
    """O portao cobre a API, nao apenas a pagina inicial."""
    ctrl, _ = _controller(auth={"enabled": True, "username": "admin",
                                "password_hash": generate_password_hash(SENHA)})
    client = ctrl.app.test_client()
    for route in ("/", "/api/agents"):
        assert client.get(route).status_code == 401, route


# ------------------------------------------------------------------------------
# TLS
# ------------------------------------------------------------------------------
def test_no_ssl_context_when_tls_is_disabled():
    """Sem TLS configurado, o servidor sobe em HTTP simples."""
    ctrl, _ = _controller()
    assert ctrl._build_ssl_context() is None


def test_self_signed_certificate_is_generated_on_demand():
    """
    Com TLS ligado e sem certificado, um autoassinado e gerado, para o operador
    nao precisar preparar PKI antes de proteger o painel.
    """
    ctrl, tmpdir = _controller(tls=True)
    context = ctrl._build_ssl_context()
    assert context is not None
    assert os.path.exists(ctrl.ssl_cert)
    assert os.path.exists(ctrl.ssl_key)


def test_generated_key_is_not_world_readable():
    """A chave privada do servidor nao pode ficar legivel por outros usuarios."""
    ctrl, _ = _controller(tls=True)
    ctrl._build_ssl_context()
    if os.name != "nt":
        mode = os.stat(ctrl.ssl_key).st_mode & 0o077
        assert mode == 0, oct(mode)
