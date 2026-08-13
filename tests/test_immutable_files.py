# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_immutable_files.py
# DESCRIPTION: Deteccao de ARQUIVOS imutaveis em diretorios gravaveis.
#
# WHY:         O detector so olhava o atributo do PROPRIO diretorio (lsattr -d),
#              e por isso nao via o caso comum: um arquivo tornado imutavel
#              dentro de um diretorio gravavel, tecnica de anti-remocao.
#
#              A certificacao do chaos revelou uma cadeia de buracos, cada um
#              corrigido: (1) `lsattr -R` estourava o timeout num /tmp cheio;
#              (2) um socket no lote travava o lsattr; (3) varrer tudo antes do
#              lsattr consumia o orcamento; (4) o artefato recem-criado ficava
#              para o fim da varredura. A versao atual visita RECENTES PRIMEIRO
#              (os.scandir ordenado por mtime) e fecha o lote ao fim de cada
#              diretorio, para o artefato ir num lote pequeno e limpo.
#
# NOTES:       Nao depende de root nem de chattr real: injeta a arvore (scandir)
#              e a saida do lsattr.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import stat as stat_mod

import pytest

from src.collectors import process_tree as pt


class _FakeStat(object):
    def __init__(self, mode, mtime=0.0):
        self.st_mode = mode
        self.st_mtime = mtime


class _FakeEntry(object):
    """Imita os.DirEntry: path, is_dir/is_file/is_symlink e stat."""

    def __init__(self, path, kind="file", mtime=0.0):
        self.path = path
        self.name = path.rstrip("/").rsplit("/", 1)[-1]
        self._kind = kind
        self._mtime = mtime

    def is_symlink(self):
        return self._kind == "symlink"

    def is_dir(self, follow_symlinks=True):
        return self._kind == "dir"

    def is_file(self, follow_symlinks=True):
        return self._kind == "file"

    def stat(self, follow_symlinks=True):
        modo = {"dir": stat_mod.S_IFDIR, "file": stat_mod.S_IFREG,
                "socket": stat_mod.S_IFSOCK}.get(self._kind, stat_mod.S_IFREG)
        return _FakeStat(modo | 0o644, self._mtime)


class _FakeProc(object):
    def __init__(self, saida):
        self._saida = saida

    def communicate(self, timeout=None):
        return (self._saida, "")

    def kill(self):
        pass


@pytest.fixture
def lab(monkeypatch):
    """
    lsattr existe; a arvore e um mapa dir -> lista de _FakeEntry; o Popen falso
    devolve uma linha de lsattr por caminho consultado, de um mapa attrs.
    """
    monkeypatch.setattr(pt.shutil, "which", lambda _n: "/usr/bin/lsattr")
    monkeypatch.setattr(pt.os.path, "isdir", lambda _d: True)

    estado = {"arvore": {}, "attrs": {}}

    def _scandir(d):
        return list(estado["arvore"].get(d, []))

    def _popen(cmd, **kwargs):
        # Agora e "lsattr -d <arquivo>", um por vez.
        caminhos = [c for c in cmd[1:] if c != "-d"]
        linhas = []
        for c in caminhos:
            a = estado["attrs"].get(c, "--------------e----")
            linhas.append("%s %s" % (a, c))
        return _FakeProc("\n".join(linhas))

    monkeypatch.setattr(pt.os, "scandir", _scandir)
    monkeypatch.setattr(pt.subprocess, "Popen", _popen)
    return estado


def test_arquivo_imutavel_em_subdiretorio_e_detectado(lab):
    """O caso que o cenario plantava e que passava despercebido."""
    lab["arvore"]["/tmp"] = [_FakeEntry("/tmp/chaos_artifacts", "dir")]
    lab["arvore"]["/tmp/chaos_artifacts"] = [
        _FakeEntry("/tmp/chaos_artifacts/immutable.dat", "file"),
        _FakeEntry("/tmp/chaos_artifacts/normal.txt", "file")]
    lab["attrs"]["/tmp/chaos_artifacts/immutable.dat"] = "----i---------e----"
    lab["attrs"]["/tmp/chaos_artifacts/normal.txt"] = "--------------e----"

    achados = pt._immutable_files_in(["/tmp"])
    assert any("immutable.dat" in a for a in achados)
    assert all("normal.txt" not in a for a in achados)


def test_recentes_sao_visitados_primeiro(lab):
    """
    O artefato recem-criado (mtime alto) e checado antes dos diretorios antigos,
    para a deteccao nao depender de quantos arquivos velhos enchem o /tmp.
    """
    lab["arvore"]["/tmp"] = [
        _FakeEntry("/tmp/antigo", "dir", mtime=1),
        _FakeEntry("/tmp/chaos_artifacts", "dir", mtime=9999)]
    lab["arvore"]["/tmp/chaos_artifacts"] = [
        _FakeEntry("/tmp/chaos_artifacts/immutable.dat", "file", mtime=9999)]
    lab["arvore"]["/tmp/antigo"] = [
        _FakeEntry("/tmp/antigo/x", "file", mtime=1)]
    lab["attrs"]["/tmp/chaos_artifacts/immutable.dat"] = "----i---------e----"

    achados = pt._immutable_files_in(["/tmp"])
    assert any("immutable.dat" in a for a in achados)


def test_append_only_tambem_conta(lab):
    lab["arvore"]["/var/tmp"] = [_FakeEntry("/var/tmp/log.dat", "file")]
    lab["attrs"]["/var/tmp/log.dat"] = "-----a--------e----"
    achados = pt._immutable_files_in(["/var/tmp"])
    assert any("log.dat" in a for a in achados)


def test_arquivo_normal_nao_dispara(lab):
    """O flag 'e' (extents) esta em quase todo arquivo ext4 e nao e alarme."""
    lab["arvore"]["/tmp"] = [_FakeEntry("/tmp/qualquer.txt", "file")]
    lab["attrs"]["/tmp/qualquer.txt"] = "--------------e----"
    assert pt._immutable_files_in(["/tmp"]) == []


def test_socket_e_ignorado_e_nao_trava(lab):
    """
    Um socket (dbus) em /tmp fazia o lsattr do lote travar ate o timeout.
    Imutabilidade nao se aplica a socket; ele nao pode nem chegar ao lsattr.
    """
    lab["arvore"]["/tmp"] = [
        _FakeEntry("/tmp/dbus-ABC", "socket"),
        _FakeEntry("/tmp/immutable.dat", "file")]
    lab["attrs"]["/tmp/immutable.dat"] = "----i---------e----"
    achados = pt._immutable_files_in(["/tmp"])
    assert any("immutable.dat" in a for a in achados)
    assert all("dbus-ABC" not in a for a in achados)


def test_symlink_e_ignorado(lab):
    lab["arvore"]["/tmp"] = [_FakeEntry("/tmp/link", "symlink")]
    assert pt._immutable_files_in(["/tmp"]) == []


def test_o_teto_de_resultados_limita(lab):
    """Um atacante nao pode afogar a deteccao com milhares de imutaveis."""
    entradas = []
    for i in range(100):
        p = "/tmp/f%d" % i
        entradas.append(_FakeEntry(p, "file"))
        lab["attrs"][p] = "----i---------e----"
    lab["arvore"]["/tmp"] = entradas
    achados = pt._immutable_files_in(["/tmp"], cap=20)
    assert len(achados) == 20


def test_sem_lsattr_nao_quebra(monkeypatch):
    monkeypatch.setattr(pt.shutil, "which", lambda _n: None)
    assert pt._immutable_files_in(["/tmp"]) == []


def test_timeout_do_lsattr_nao_derruba_a_coleta(lab, monkeypatch):
    """lsattr pode travar; timeout nao pode propagar."""
    lab["arvore"]["/tmp"] = [_FakeEntry("/tmp/x", "file")]
    lab["attrs"]["/tmp/x"] = "----i---------e----"

    def _trava(cmd, **kwargs):
        class _T(object):
            def communicate(self, timeout=None):
                raise pt.subprocess.TimeoutExpired("lsattr", timeout)
            def kill(self):
                pass
        return _T()

    monkeypatch.setattr(pt.subprocess, "Popen", _trava)
    assert pt._immutable_files_in(["/tmp"]) == []


def test_diretorio_inacessivel_nao_quebra(lab, monkeypatch):
    """scandir num diretorio sem permissao nao pode derrubar a coleta."""
    def _scandir_erro(_d):
        raise OSError("permission denied")
    monkeypatch.setattr(pt.os, "scandir", _scandir_erro)
    assert pt._immutable_files_in(["/tmp"]) == []
