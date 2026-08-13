# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_integrity.py
# DESCRIPTION: Testa a proveniencia e a integridade de arquivos: quem e o dono
#              (pacote) e se o conteudo ainda confere com o que foi instalado.
#
#              Caso real que motivou o modulo: bootmsg.service aparecia como
#              Critical por referenciar /dev/shm, sendo um symlink para
#              /usr/lib/systemd/system/klog.service, que pertence ao pacote
#              syslog-service. Perguntar ao rpm pelo LINK responde "sem dono";
#              e preciso resolver o caminho antes.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import shutil
import tempfile

import pytest

from src.collectors import integrity
from src.collectors.persistence import _apply_provenance
from src.core.findings import (Finding, SEV_INFO, SEV_LOW, SEV_CRITICAL,
                               SRC_PERSISTENCE)


@pytest.fixture(autouse=True)
def _clean_cache():
    """Cada teste comeca sem memorizacao de consultas anteriores."""
    integrity.clear_cache()


def _finding(severity=SEV_CRITICAL):
    return Finding(title="t", severity=severity, source=SRC_PERSISTENCE,
                   description="Base description.")


# ------------------------------------------------------------------------------
# Consulta ao gerenciador de pacotes
# ------------------------------------------------------------------------------
def test_unknown_path_has_no_owner():
    """Caminho inexistente nao pertence a pacote nenhum."""
    assert integrity.package_owner("/nonexistent/xyz/file") is None


def test_empty_path_is_safe():
    """Entrada vazia nao quebra a consulta."""
    assert integrity.package_owner("") is None
    assert integrity.package_owner(None) is None
    assert integrity.verify_file("") is None


def test_temp_file_is_not_packaged():
    """Arquivo criado agora nao pode pertencer a pacote."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        assert integrity.package_owner(path) is None
    finally:
        os.unlink(path)


@pytest.mark.skipif(not shutil.which("rpm"), reason="requer rpm")
def test_system_binary_is_owned_by_a_package():
    """Um binario de sistema tem dono identificavel."""
    for candidate in ("/bin/sh", "/usr/bin/env", "/bin/cat"):
        if os.path.exists(candidate):
            assert integrity.package_owner(candidate)
            return
    pytest.skip("nenhum binario de sistema encontrado")


@pytest.mark.skipif(not shutil.which("rpm"), reason="requer rpm")
def test_symlink_resolves_to_the_real_owner():
    """
    O dono e consultado no ALVO do symlink. Sem isso, toda unit habilitada em
    /etc/systemd/system responderia "sem dono" (era a causa do falso-positivo).
    """
    target = None
    for candidate in ("/bin/sh", "/bin/cat", "/usr/bin/env"):
        if os.path.exists(candidate):
            target = candidate
            break
    if not target:
        pytest.skip("nenhum binario de sistema encontrado")

    tmpdir = tempfile.mkdtemp()
    link = os.path.join(tmpdir, "link")
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink indisponivel")

    assert integrity.package_owner(link) == integrity.package_owner(target)


# ------------------------------------------------------------------------------
# Efeito no achado
# ------------------------------------------------------------------------------
def test_unpackaged_artifact_keeps_its_severity():
    """
    Artefato que nao pertence a pacote e o sinal real: mantem a gravidade e a
    descricao registra que foi colocado fora do gerenciamento de pacotes.
    """
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        finding = _apply_provenance(_finding(SEV_CRITICAL), path)
        assert finding.severity == SEV_CRITICAL
        assert "does not belong to any installed package" in finding.description
        assert finding.evidence["provenance"]["packaged"] is False
    finally:
        os.unlink(path)


@pytest.mark.skipif(not shutil.which("rpm"), reason="requer rpm")
def test_packaged_intact_artifact_is_downgraded():
    """
    Arquivo que pertence a um pacote e confere com ele e software esperado:
    deixa de ser Critical. Corrige o caso bootmsg.service.
    """
    target = None
    for candidate in ("/bin/cat", "/bin/sh", "/usr/bin/env"):
        if os.path.exists(candidate) and integrity.package_owner(candidate):
            target = candidate
            break
    if not target:
        pytest.skip("nenhum binario empacotado encontrado")

    finding = _apply_provenance(_finding(SEV_CRITICAL), target)
    assert finding.severity == SEV_LOW
    assert "expected system software" in finding.description
    assert finding.evidence["provenance"]["packaged"] is True


def test_info_findings_are_not_annotated():
    """Achado informativo nao recebe texto de proveniencia desnecessario."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        finding = _apply_provenance(_finding(SEV_INFO), path)
        assert "does not belong" not in finding.description
    finally:
        os.unlink(path)


def test_provenance_is_attached_as_evidence():
    """A proveniencia acompanha o achado como evidencia auditavel."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    try:
        finding = _apply_provenance(_finding(), path)
        prov = finding.evidence["provenance"]
        for key in ("package", "packaged", "verified", "issues"):
            assert key in prov
    finally:
        os.unlink(path)


def test_describe_provenance_never_raises():
    """A descricao de proveniencia e resiliente a caminhos invalidos."""
    for path in ("", None, "/nonexistent/a/b/c", "\x00bad"):
        info = integrity.describe_provenance(path)
        assert "packaged" in info
