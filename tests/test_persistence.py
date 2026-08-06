# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_persistence.py
# DESCRIPTION: Testa a heuristica do coletor de persistencia: deteccao de
#              caminhos inseguros, escalonamento de severidade por indicadores
#              forenses e robustez do coletor completo.
#
# NOTA: usa arquivos temporarios; roda em Linux (VM/CI).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import time
import tempfile

from src.collectors import persistence as P
from src.core.findings import SEV_INFO, SEV_LOW, SEV_MEDIUM, SEV_HIGH, SRC_PERSISTENCE


# ------------------------------------------------------------------------------
# Deteccao de caminho inseguro
# ------------------------------------------------------------------------------
def test_detects_unsafe_execution_paths():
    """Referencias a diretorios graváveis por usuario sao detectadas."""
    assert P._has_unsafe_path("ExecStart=/tmp/evil.sh") == "/tmp/evil.sh"
    assert P._has_unsafe_path("* * * * * root /dev/shm/x.py") == "/dev/shm/x.py"
    assert P._has_unsafe_path("bash /var/tmp/backdoor") == "/var/tmp/backdoor"


def test_returns_only_the_path_not_surrounding_text():
    """O achado devolve o caminho, sem a diretiva que o antecede."""
    assert P._has_unsafe_path("ExecStart=/tmp/evil.sh") == "/tmp/evil.sh"


def test_prefix_must_be_on_a_path_boundary():
    """
    '/tmp' nao pode casar dentro de '/var/tmp/...', senao o achado reportaria
    um caminho que nao existe no host.
    """
    assert P._has_unsafe_path("bash /var/tmp/backdoor") == "/var/tmp/backdoor"
    assert P._has_unsafe_path("/opt/mytmp/app") is None


def test_ignores_legitimate_system_paths():
    """Caminhos normais de sistema nao disparam alerta (evita falso-positivo)."""
    assert P._has_unsafe_path("ExecStart=/usr/bin/sshd -D") is None
    assert P._has_unsafe_path("ExecStart=/usr/lib/systemd/systemd-logind") is None
    assert P._has_unsafe_path("") is None
    assert P._has_unsafe_path(None) is None


# ------------------------------------------------------------------------------
# Escalonamento de severidade
# ------------------------------------------------------------------------------
def test_world_writable_raises_to_high():
    """Arquivo de persistencia gravavel por qualquer usuario e critico o bastante."""
    severity, reasons = P._escalate({"path": "/etc/x", "world_writable": True})
    assert severity == SEV_HIGH
    assert "world-writable" in reasons


def test_hidden_name_raises_to_high():
    """Nome oculto em mecanismo de persistencia e indicador de evasao."""
    severity, reasons = P._escalate({"path": "/etc/cron.d/.hidden"})
    assert severity == SEV_HIGH
    assert "hidden name" in reasons


def test_recent_modification_raises_from_low_to_medium():
    """Alteracao nas ultimas 24h eleva a atencao sobre o item."""
    severity, reasons = P._escalate({"path": "/etc/x", "mtime": time.time()})
    assert severity == SEV_MEDIUM
    assert any("24h" in r for r in reasons)


def test_old_untouched_file_stays_at_base():
    """Arquivo antigo e sem indicadores permanece na severidade base."""
    old = time.time() - (90 * 24 * 3600)
    severity, reasons = P._escalate({"path": "/etc/x", "mtime": old}, base=SEV_INFO)
    assert severity == SEV_INFO
    assert reasons == []


# ------------------------------------------------------------------------------
# Metadados forenses
# ------------------------------------------------------------------------------
def test_stat_info_collects_forensic_metadata():
    """MAC times, dono e permissoes sao capturados para a cadeia de custodia."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    meta = P._stat_info(path)
    for key in ("path", "size", "uid", "gid", "mode", "mtime", "ctime", "atime"):
        assert key in meta
    os.unlink(path)


def test_symlink_is_not_reported_world_writable():
    """
    Em Linux todo symlink tem modo 0777. A permissao deve ser avaliada no ALVO,
    senao cada unit habilitada em /etc/systemd/system (symlink para /usr/lib)
    viraria falso-positivo "world-writable".
    """
    tmpdir = tempfile.mkdtemp()
    target = os.path.join(tmpdir, "real.conf")
    with open(target, "w") as handle:
        handle.write("x")
    os.chmod(target, 0o644)
    link = os.path.join(tmpdir, "link.conf")
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        return  # symlink indisponivel (ex.: Windows sem privilegio)

    meta = P._stat_info(link)
    assert meta["is_symlink"] is True
    assert meta["world_writable"] is False
    assert P._escalate(meta, base=SEV_INFO)[0] != SEV_HIGH


def test_masked_systemd_unit_is_not_flagged():
    """
    Unit mascarada (symlink para /dev/null) e servico DESATIVADO. Como
    /dev/null tem modo 0666, sem tratamento ela apareceria como
    "world-writable" e viraria falso-positivo.
    """
    if not os.path.exists("/dev/null"):
        return  # ambiente sem /dev/null (Windows)
    tmpdir = tempfile.mkdtemp()
    link = os.path.join(tmpdir, "masked.service")
    try:
        os.symlink("/dev/null", link)
    except (OSError, NotImplementedError):
        return

    meta = P._stat_info(link)
    assert meta["link_target"] == "/dev/null"
    # O coletor deve pular esse caso; aqui garantimos que o dado necessario
    # para reconhece-lo esta presente nos metadados.
    assert meta["is_symlink"] is True


def test_stat_info_on_missing_path_is_empty():
    """Caminho inexistente nao quebra o coletor."""
    assert P._stat_info("/nonexistent/path/xyz") == {}


def test_read_text_is_truncated_and_safe():
    """A leitura e limitada, para nao inflar o payload da captura."""
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as handle:
        handle.write("A" * 50000)
    assert len(P._read_text(path, limit=100)) == 100
    os.unlink(path)
    assert P._read_text("/nonexistent/file") == ""


# ------------------------------------------------------------------------------
# Coletor completo
# ------------------------------------------------------------------------------
def test_collect_persistence_runs_and_returns_findings():
    """O coletor roda no host real sem levantar excecao e produz Findings."""
    findings = P.collect_persistence()
    assert isinstance(findings, list)
    for f in findings:
        assert f.source == SRC_PERSISTENCE
        assert f.severity in ("Info", "Low", "Medium", "High", "Critical")
        assert f.title
