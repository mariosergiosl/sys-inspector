# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_cenario_nao_suja_o_tmp.py
# DESCRIPTION: O teste de pivot_root do cenario nao deixa diretorio no host.
#
# WHY:         Medido em 2026-10-10 na limpeza das VMs: 1742 diretorios vazios
#              tmp.XXXXXXXXXX no /tmp da .161, criados pelo laco do
#              probe_pivot_root do chaos_maker.sh, que fazia "mktemp -d" dentro
#              do unshare a cada 6 s (F-277). O teste roda o script de verdade,
#              extraido do chaos_maker.sh, com unshare, mount e sleep
#              substituidos: sem root, sem namespace, sem tocar no host, e conta
#              o que sobrou.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import shutil
import subprocess

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHAOS = os.path.join(RAIZ, "tools", "chaos_maker.sh")
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="exige bash")

# Substitutos. O unshare roda o comando depois do "--" sem namespace; o mount
# falha como falharia sem root; o sleep encerra o laco na terceira volta.
STUBS = {
    "unshare": "#!/bin/bash\nwhile [ \"$1\" != \"--\" ]; do shift; done\n"
               "shift\nexec \"$@\"\n",
    "mount": "#!/bin/bash\nexit 1\n",
    "sleep": "#!/bin/bash\nN=$(cat \"$CONTA\" 2>/dev/null || echo 0)\n"
             "N=$((N + 1))\necho \"$N\" > \"$CONTA\"\n"
             "[ \"$N\" -ge 6 ] && kill \"$PPID\"\nexit 0\n",
}


def _script_do_pivot():
    """O probe_pivot_root.sh exatamente como o chaos_maker.sh o escreve."""
    with io.open(CHAOS, encoding="utf-8") as fh:
        fonte = fh.read()
    inicio = fonte.index('> "${TEMP_DIR}/probe_pivot_root.sh"')
    corpo = fonte[fonte.index("\n", inicio) + 1:]
    return corpo[:corpo.index("\nEOF\n") + 1]


def _rodar(tmp_path):
    cenario = tmp_path / "chaos_artifacts"
    tmp_do_host = tmp_path / "tmp_do_host"
    stubs = tmp_path / "stubs"
    for d in (cenario, tmp_do_host, stubs):
        d.mkdir()
    for nome, texto in STUBS.items():
        caminho = stubs / nome
        caminho.write_text(texto, newline="\n")
        os.chmod(str(caminho), 0o755)
    script = cenario / "probe_pivot_root.sh"
    script.write_text(_script_do_pivot(), newline="\n")
    env = dict(os.environ)
    env["PATH"] = str(stubs) + os.pathsep + env.get("PATH", "")
    env["TMPDIR"] = str(tmp_do_host)
    env["CONTA"] = str(tmp_path / "conta")
    subprocess.run([BASH, str(script)], env=env, timeout=60,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cenario, tmp_do_host, tmp_path / "conta"


def test_o_laco_do_pivot_nao_deixa_diretorio_no_tmp_do_host(tmp_path):
    """REPROVA A 1.4.1: cada volta deixava um diretorio vazio no /tmp."""
    cenario, tmp_do_host, conta = _rodar(tmp_path)
    assert int(conta.read_text().strip()) >= 3, "o laco nao chegou a girar"
    assert os.listdir(str(tmp_do_host)) == []
    assert os.listdir(str(cenario)) == ["probe_pivot_root.sh"]


def test_o_pivot_continua_no_script():
    """O que o teste existe para disparar (pivot_root, mount e o namespace)
    continua no script: a correcao nao pode tirar o sinal."""
    script = _script_do_pivot()
    for trecho in ("unshare --mount --fork", "mount -t tmpfs",
                   "pivot_root . raiz_antiga"):
        assert trecho in script
