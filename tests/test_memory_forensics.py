# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_memory_forensics.py
# DESCRIPTION: O que a memoria do processo denuncia.
#
#              A arvore responde "o que esta rodando". A pericia precisa de
#              outra resposta: "esse processo ainda e o que dizia ser?". Um
#              atacante que ja executou nao precisa de processo novo: injeta em
#              um legitimo, troca o binario no disco, ou executa de memoria sem
#              tocar em arquivo. Nos tres casos a lista de processos continua
#              parecendo normal.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import pytest

from src.collectors import memory_forensics as mf
from src.core.findings import SEV_HIGH, SEV_MEDIUM, SEV_LOW


def _mapa(entradas):
    """entradas: lista de (perms, inode, caminho)."""
    linhas = []
    base = 0x400000
    for i, (perms, inode, caminho) in enumerate(entradas):
        ini = base + i * 0x1000
        linhas.append("%x-%x %s 00000000 08:01 %d    %s"
                      % (ini, ini + 0x1000, perms, inode, caminho))
    return "\n".join(linhas) + "\n"


@pytest.fixture
def proc_falso(tmp_path, monkeypatch):
    raiz = tmp_path / "proc"
    (raiz / "42").mkdir(parents=True)
    monkeypatch.setattr(mf, "PROC", str(raiz))
    return raiz


# ------------------------------------------------------------------------------
# 1. MEMORIA GRAVAVEL E EXECUTAVEL
# ------------------------------------------------------------------------------
def test_writable_and_executable_region_is_found(proc_falso):
    """
    Um binario compilado nao precisa disso: codigo fica em regiao so de leitura.
    W+X e a assinatura de codigo escrito e executado em tempo de execucao.
    """
    (proc_falso / "42" / "maps").write_text(
        _mapa([("r-xp", 100, "/usr/bin/app"), ("rwxp", 0, "")]))

    assert len(mf.find_wx_regions(42)) == 1


def test_normal_regions_raise_nothing(proc_falso):
    (proc_falso / "42" / "maps").write_text(
        _mapa([("r-xp", 100, "/usr/bin/app"), ("rw-p", 0, "[heap]")]))

    assert mf.find_wx_regions(42) == []


def test_an_interpreter_is_explained_not_accused(proc_falso):
    """
    JIT de Java, Python e navegadores usa W+X legitimamente. Acusar todos
    encheria o laudo de ruido e treinaria o analista a ignorar o sinal.
    """
    (proc_falso / "42" / "maps").write_text(_mapa([("rwxp", 0, "")]))
    achados = mf.collect_memory_forensics({42: {"cmd": "/usr/bin/java -jar x"}})

    assert achados[0].severity == SEV_LOW
    assert "JIT" in achados[0].description


def test_an_unexplained_wx_region_is_serious(proc_falso):
    (proc_falso / "42" / "maps").write_text(_mapa([("rwxp", 0, "")]))
    achados = mf.collect_memory_forensics({42: {"cmd": "/usr/sbin/sshd"}})

    assert achados[0].severity == SEV_HIGH
    assert achados[0].technique == "T1055"


def test_it_says_to_capture_memory_before_acting(proc_falso):
    """
    Encerrar o processo apaga exatamente o conteudo que provaria a injecao. A
    recomendacao existe para a primeira reacao nao destruir a evidencia.
    """
    (proc_falso / "42" / "maps").write_text(_mapa([("rwxp", 0, "")]))
    achados = mf.collect_memory_forensics({42: {"cmd": "/usr/sbin/sshd"}})

    assert "memoria" in achados[0].recommendation.lower()


# ------------------------------------------------------------------------------
# 2. BINARIO SUBSTITUIDO
# ------------------------------------------------------------------------------
def test_a_replaced_binary_is_detected(proc_falso, tmp_path, monkeypatch):
    """
    O caminho aponta hoje para OUTRO arquivo: o binario foi trocado com o
    processo ainda rodando. Uma verificacao feita so no disco nao perceberia,
    porque o disco ja mostra o arquivo novo, coerente consigo mesmo.
    """
    binario = tmp_path / "app"
    binario.write_text("novo")

    (proc_falso / "42" / "maps").write_text(
        _mapa([("r-xp", 999999, str(binario))]))
    monkeypatch.setattr(mf.os, "readlink", lambda p: str(binario))

    resultado = mf.check_executable_backing(42)
    assert resultado["replaced"] is True


def test_an_untouched_binary_is_not_flagged(proc_falso, tmp_path, monkeypatch):
    import os as _os
    binario = tmp_path / "app"
    binario.write_text("original")
    inode = _os.stat(str(binario)).st_ino

    (proc_falso / "42" / "maps").write_text(
        _mapa([("r-xp", inode, str(binario))]))
    monkeypatch.setattr(mf.os, "readlink", lambda p: str(binario))

    assert mf.check_executable_backing(42)["replaced"] is False


def test_a_deleted_executable_is_reported_as_such(proc_falso, monkeypatch):
    """Apagado e trocado sao coisas diferentes e nao podem se confundir."""
    (proc_falso / "42" / "maps").write_text(_mapa([("r-xp", 1, "/tmp/x")]))
    monkeypatch.setattr(mf.os, "readlink", lambda p: "/tmp/x (deleted)")

    resultado = mf.check_executable_backing(42)
    assert resultado["deleted"] is True
    assert resultado["replaced"] is False


# ------------------------------------------------------------------------------
# 3. BIBLIOTECA DE FORA DO SISTEMA
# ------------------------------------------------------------------------------
def test_a_world_writable_library_is_flagged(proc_falso, tmp_path):
    """
    Quem pode escrever nesse arquivo executa codigo dentro do processo, com os
    privilegios dele.
    """
    import os as _os
    lib = tmp_path / "mal.so"
    lib.write_text("x")
    _os.chmod(str(lib), 0o777)

    (proc_falso / "42" / "maps").write_text(_mapa([("r-xp", 5, str(lib))]))
    achadas = mf.find_foreign_libraries(42)

    assert achadas[0]["world_writable"] is True


def test_system_libraries_are_not_noise(proc_falso):
    """Listar toda libc do sistema tornaria o achado inutil."""
    (proc_falso / "42" / "maps").write_text(
        _mapa([("r-xp", 5, "/usr/lib64/libc.so.6"),
               ("r-xp", 6, "/lib64/ld-linux-x86-64.so.2")]))

    assert mf.find_foreign_libraries(42) == []


def test_a_safe_foreign_library_does_not_become_a_finding(proc_falso, tmp_path):
    """
    Software instalado em diretorio proprio e comum. So vira achado o que
    qualquer um pode escrever, ou o que ja nao existe.
    """
    import os as _os
    lib = tmp_path / "ok.so"
    lib.write_text("x")
    _os.chmod(str(lib), 0o644)

    (proc_falso / "42" / "maps").write_text(_mapa([("r-xp", 5, str(lib))]))
    achados = mf.collect_memory_forensics({42: {"cmd": "/opt/app/bin/app"}})

    assert achados == []


# ------------------------------------------------------------------------------
# ROBUSTEZ
# ------------------------------------------------------------------------------
def test_a_process_that_ended_does_not_break_the_capture(proc_falso):
    """Ler um processo que acabou de morrer e comum e nao prova nada."""
    assert mf.find_wx_regions(999) == []
    assert mf.check_executable_backing(999) is None
    assert mf.collect_memory_forensics({999: {"cmd": "x"}}) == []


def test_a_malformed_maps_file_is_ignored(proc_falso):
    (proc_falso / "42" / "maps").write_text("lixo\nmais lixo\n")
    assert mf.find_wx_regions(42) == []


def test_nothing_is_presented_as_proof(proc_falso):
    """
    Isto produz indicio, nao prova. Prova exige captura de memoria com
    ferramenta dedicada, e o modulo diz isso em vez de sugerir garantia que o
    metodo nao da.
    """
    import io
    import os
    fonte = io.open(os.path.join("src", "collectors", "memory_forensics.py"),
                    encoding="utf-8").read()
    assert "LIMITS:" in fonte
    assert "nao e prova" in fonte or "nao ha prova" in fonte or "INDICIO" in fonte
