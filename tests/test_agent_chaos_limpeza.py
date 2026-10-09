# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_agent_chaos_limpeza.py
# DESCRIPTION: Trava a limpeza do tools/agent_chaos.sh ao terminar a rodada e a
#              preservacao de um /etc/ld.so.preload que o host ja tinha.
#
# WHY:         Medido em 2026-10-09: os artefatos plantados em 2026-08-12
#              (/etc/cron.d/evil-cron, /etc/cron.d/.hidden-cron,
#              /etc/systemd/system/evil-backdoor.service) continuavam nas tres
#              VMs do laboratorio, e toda captura desses hosts acusava a
#              persistencia plantada. O script so limpava no COMECO da proxima
#              rodada. O Mario: "o agent_chaos.sh deveria limpar tudo o que ele
#              usa, ao finalizar".
#
#              E a limpeza fazia "rm -f /etc/ld.so.preload": num host com um
#              preload legitimo, perda de dado.
#
#              O teste roda o script de verdade, em bash, numa copia com todas as
#              constantes de caminho apontando para um diretorio temporario. Nada
#              toca o /etc real nem os processos do host.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import io
import os
import re
import shutil
import subprocess

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(RAIZ, "tools", "agent_chaos.sh")

pytestmark = pytest.mark.skipif(shutil.which("bash") is None
                                or os.name == "nt",
                                reason="exige bash de Linux")


def _caixa(tmp_path):
    """Copia do script com todo caminho do host dentro de tmp_path."""
    with io.open(SCRIPT, encoding="ascii") as fh:
        texto = fh.read()
    # Sem a opcao --cleanup, o script trata o argumento como DURACAO e planta
    # de verdade. Medido em 2026-10-09: a primeira versao deste teste, rodada
    # contra o script antigo na .161, lancou o chaos_maker real --all quatro
    # vezes (achou uma copia em /tmp), truncou o /tmp/chaos.log real e deixou
    # quatro miner.sh em laco. Reprovar ANTES de executar.
    if "--cleanup)" not in texto:
        pytest.fail("agent_chaos.sh sem a opcao --cleanup: nao executo, "
                    "porque o argumento viraria duracao e o script plantaria")
    raiz = str(tmp_path)
    # Onde o script procura o chaos_maker e onde escreve o log da rodada:
    # tudo para dentro da caixa, para nada real ser encontrado nem truncado.
    for real in ("/usr/bin/chaos_maker.sh", "/tmp/chaos_maker.sh",
                 "/usr/lib/python3.6/site-packages/tools/chaos_maker.sh",
                 "/tmp/chaos.log"):
        texto = texto.replace(real, raiz + "/nada" + real.replace("/", "_"))
    for nome, caminho in (("MARK", "mark"), ("SYS_LIB_DIR", "usrlocallib"),
                          ("SHM_LIB", "shm/libinject.so"),
                          ("PRELOAD_FILE", "etc/ld.so.preload"),
                          ("SVC_FILE", "etc/systemd/evil-backdoor.service"),
                          ("CRON_EVIL", "etc/cron.d/evil-cron"),
                          ("CRON_HIDDEN", "etc/cron.d/.hidden-cron"),
                          ("MINER", "shm/miner.sh"),
                          ("CHAOS_HOME", "chaos_home")):
        texto, n = re.subn(r'^%s="[^"]*"' % nome,
                           '%s="%s/%s"' % (nome, raiz, caminho), texto,
                           flags=re.M)
        assert n == 1, nome
    # Nunca matar um chaos_maker real do host que roda a suite.
    texto, n = re.subn(r'^\s*ps -eo pid,args \| grep "\[c\]haos_maker".*$',
                       "    :", texto, flags=re.M)
    assert n == 1
    for d in ("mark", "usrlocallib", "shm", "etc/systemd", "etc/cron.d"):
        os.makedirs(os.path.join(raiz, d), exist_ok=True)
    copia = os.path.join(raiz, "agent_chaos.sh")
    with io.open(copia, "w", encoding="ascii", newline="\n") as fh:
        fh.write(texto)
    return copia, raiz


def _rodar(copia, *args):
    return subprocess.run(["bash", copia] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, timeout=30)


def _escreve(caminho, conteudo):
    with io.open(caminho, "w", encoding="ascii") as fh:
        fh.write(conteudo)


def test_cleanup_remove_a_persistencia_plantada(tmp_path):
    """REPROVA A VERSAO ANTERIOR: nao existia --cleanup."""
    copia, raiz = _caixa(tmp_path)
    plantados = ["etc/cron.d/evil-cron", "etc/cron.d/.hidden-cron",
                 "etc/systemd/evil-backdoor.service"]
    for rel in plantados:
        _escreve(os.path.join(raiz, rel), "x\n")
    saida = _rodar(copia, "--cleanup")
    assert saida.returncode == 0, saida.stdout
    assert "AGENT_CHAOS_CLEANED" in saida.stdout
    for rel in plantados:
        assert not os.path.exists(os.path.join(raiz, rel)), rel


def test_preload_que_o_host_ja_tinha_volta_intacto(tmp_path):
    """REPROVA A VERSAO ANTERIOR: a limpeza apagava o arquivo inteiro."""
    copia, raiz = _caixa(tmp_path)
    preload = os.path.join(raiz, "etc/ld.so.preload")
    _escreve(preload, "/usr/lib64/libsnoopy.so\n")
    _escreve(preload + ".agent_chaos.bak", "/usr/lib64/libsnoopy.so\n")
    _escreve(preload, os.path.join(raiz, "usrlocallib/libhealthcheck.so"))
    _rodar(copia, "--cleanup")
    with io.open(preload, encoding="ascii") as fh:
        assert fh.read() == "/usr/lib64/libsnoopy.so\n"
    assert not os.path.exists(preload + ".agent_chaos.bak")


def test_preload_alheio_sem_copia_nao_e_apagado(tmp_path):
    copia, raiz = _caixa(tmp_path)
    preload = os.path.join(raiz, "etc/ld.so.preload")
    _escreve(preload, "/usr/lib64/outra.so\n")
    saida = _rodar(copia, "--cleanup")
    assert os.path.exists(preload), saida.stdout
    assert "left untouched" in saida.stdout


def test_preload_so_nosso_e_removido(tmp_path):
    copia, raiz = _caixa(tmp_path)
    preload = os.path.join(raiz, "etc/ld.so.preload")
    _escreve(preload, os.path.join(raiz, "usrlocallib/libhealthcheck.so"))
    _rodar(copia, "--cleanup")
    assert not os.path.exists(preload)


def test_a_rodada_agenda_a_limpeza_ao_terminar():
    """O script volta logo depois de plantar; a limpeza tem que estar
    agendada depois do cenario E no caminho sem chaos_maker."""
    with io.open(SCRIPT, encoding="ascii") as fh:
        texto = fh.read()
    corpo = texto.split("run_chaos() {")[1].split("\n}\n")[0]
    assert corpo.count("schedule_cleanup ") == 2, (
        "a limpeza ao fim deixou de ser agendada num dos dois caminhos")
    assert "--cleanup\" " in texto or "--cleanup\"" in texto
    assert 'setsid nohup bash "${maker}"' not in texto, (
        "voltou a lancar o cenario sem a limpeza ao fim")


def test_versao_do_script_acompanha_o_cabecalho():
    """REPROVA A VERSAO ANTERIOR: --version respondia 1.0.1 num 1.3.1."""
    from src.version import __version__
    saida = subprocess.run(["bash", SCRIPT, "--version"],
                           stdout=subprocess.PIPE, universal_newlines=True)
    assert saida.stdout.strip() == "agent_chaos.sh %s" % __version__


def test_a_caixa_nao_deixa_nada_real_ao_alcance(tmp_path):
    """Defeito do proprio material de teste: a copia nao pode conter nenhum
    caminho real que o script escreva, apague ou execute."""
    copia, raiz = _caixa(tmp_path)
    with io.open(copia, encoding="ascii") as fh:
        # O caminho INTEIRO dentro da caixa vira um marcador: "<caixa>/etc/x"
        # contem "/etc/" e nao e o /etc real.
        texto = re.sub(re.escape(raiz) + r"[^\s\"']*", "<CAIXA>", fh.read())
    for real in ("/etc/", "/dev/shm/", "/usr/local/lib", "/tmp/chaos",
                 "/usr/bin/chaos_maker.sh", "/opt/sys-inspector"):
        linhas = [l for l in texto.splitlines()
                  if real in l and not l.lstrip().startswith("#")
                  and not l.lstrip().startswith("echo")]
        assert not linhas, (real, linhas)


def test_prefere_o_chaos_maker_ao_lado_do_script():
    """Na .161 havia uma copia velha em /tmp, que vinha antes no laco."""
    with io.open(SCRIPT, encoding="ascii") as fh:
        texto = fh.read()
    corpo = texto.split("find_chaos_maker() {")[1].split("\n}\n")[0]
    primeiro = corpo.index('"$(dirname "${SELF}")/chaos_maker.sh"')
    assert primeiro < corpo.index("/tmp/chaos_maker.sh")
    assert primeiro < corpo.index("/usr/bin/chaos_maker.sh")
