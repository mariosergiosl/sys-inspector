# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tests/test_shell_scripts_sanity.py
# DESCRIPTION: Todo script de shell do repositorio tem que ser EXECUTAVEL no
#              alvo: sem CR, com shebang, e sintaticamente valido.
#
# WHY:         Em 2026-08-20 o chaos_maker.sh chegou na VM com finais de linha
#              CRLF. O bash nao interpreta `\r`: o script morria na linha 81, no
#              primeiro `{`, sem executar UMA linha. O comando de chaos disparado
#              pela tela respondia "setup nao confirmado, capturando mesmo
#              assim", a captura vinha vazia, e a leitura obvia era "a ferramenta
#              nao detecta" -- quando a verdade e que a cena nunca existiu.
#
#              O chaos_maker e a REGUA da deteccao (D-025): e ele que prova que o
#              que a ferramenta diz detectar, ela detecta. Uma regua que nao roda
#              nao mede nada, e pior, mede zero e parece resposta.
#
#              O git estava certo: `.gitattributes` declara `*.sh text eol=lf` e
#              o INDICE tinha LF. Quem reintroduziu o CR foi uma ferramenta do
#              Windows escrevendo na copia de trabalho depois do checkout, e o
#              deploy copia a copia de trabalho. Por isso o teste olha o arquivo
#              NO DISCO, e nao o que o git guarda: e o disco que vai para a VM.
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


def _scripts():
    """Todo .sh do repositorio, fora de diretorios que nao sao nossos."""
    ignorar = {".git", "__pycache__", "venv", ".venv", "build", "dist"}
    achados = []
    for pasta, subdirs, arquivos in os.walk(RAIZ):
        subdirs[:] = [d for d in subdirs if d not in ignorar]
        for nome in arquivos:
            if nome.endswith(".sh"):
                achados.append(os.path.join(pasta, nome))
    return sorted(achados)


SCRIPTS = _scripts()


def test_existe_pelo_menos_um_script():
    """
    Guarda contra o teste passar por vacuidade. Se a varredura parar de achar
    scripts (mudanca de layout, bug no walk), os testes abaixo passariam sem
    verificar nada, que e o pior desfecho de um teste de contrato.
    """
    assert SCRIPTS, "nenhum .sh encontrado: a varredura quebrou"
    nomes = [os.path.basename(s) for s in SCRIPTS]
    assert "chaos_maker.sh" in nomes, (
        "o chaos_maker sumiu da varredura, e e justamente o script que motivou "
        "este teste")


@pytest.mark.parametrize("caminho", SCRIPTS, ids=os.path.basename)
def test_sem_carriage_return(caminho):
    """
    Nenhum CR, em lugar nenhum. Nao basta checar o fim de linha: um `\\r` solto
    no meio de uma linha quebra igual.
    """
    with open(caminho, "rb") as fh:
        conteudo = fh.read()
    assert b"\r" not in conteudo, (
        "%s tem CR. O bash no alvo le isso como comando e o script morre antes "
        "de rodar. Converter para LF: "
        "python -c \"p='%s';d=open(p,'rb').read();"
        "open(p,'wb').write(d.replace(b'\\r\\n',b'\\n'))\""
        % (os.path.relpath(caminho, RAIZ), os.path.relpath(caminho, RAIZ)))


@pytest.mark.parametrize("caminho", SCRIPTS, ids=os.path.basename)
def test_tem_shebang(caminho):
    """Sem shebang o script depende de quem o invoca, e isso muda por host."""
    with io.open(caminho, encoding="utf-8", errors="replace") as fh:
        primeira = fh.readline()
    assert primeira.startswith("#!"), (
        "%s nao comeca com shebang" % os.path.relpath(caminho, RAIZ))


@pytest.mark.skipif(shutil.which("bash") is None,
                    reason="bash ausente neste host")
@pytest.mark.parametrize("caminho", SCRIPTS, ids=os.path.basename)
def test_sintaxe_valida(caminho):
    """
    `bash -n` le o script inteiro sem executar nada. E exatamente a verificacao
    que teria pego o CRLF: o erro que apareceu na VM foi
    "syntax error near unexpected token `$'{\\r''".
    """
    r = subprocess.run(["bash", "-n", caminho],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert r.returncode == 0, (
        "%s nao passa em `bash -n`:\n%s"
        % (os.path.relpath(caminho, RAIZ),
           r.stdout.decode("utf-8", "replace")))


@pytest.mark.skipif(shutil.which("bash") is None,
                    reason="bash ausente neste host")
def test_chaos_maker_responde_a_help():
    """
    A regua tem que RODAR, e nao apenas passar no analisador de sintaxe.
    `--help` e a prova mais barata disso: exercita o parsing de argumentos, as
    funcoes declaradas ate ali e a saida, sem plantar artefato nenhum no host
    que roda o teste.
    """
    script = os.path.join(RAIZ, "tools", "chaos_maker.sh")
    r = subprocess.run(["bash", script, "--help"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=30)
    saida = r.stdout.decode("utf-8", "replace")
    assert r.returncode == 0, "chaos_maker --help falhou:\n%s" % saida
    assert saida.strip(), "chaos_maker --help nao imprimiu nada"


@pytest.mark.skipif(shutil.which("bash") is None,
                    reason="bash ausente neste host")
def test_chaos_maker_declara_o_marcador_de_pronto():
    """
    O daemon espera uma string EXATA no log para saber que a cena subiu. Se o
    script deixar de imprimi-la, ou mudar o texto, a espera nunca termina e toda
    rodada vira falha. Duas fontes do mesmo fato: aqui elas sao amarradas.
    """
    # A constante e LIDA DA FONTE, e nao importada: daemon_controller puxa o
    # motor eBPF, que exige bcc, ausente no Windows e em qualquer host sem
    # kernel Linux. Um contrato entre dois arquivos de texto nao deveria exigir
    # um modulo de kernel para ser conferido.
    controlador = os.path.join(RAIZ, "src", "controllers",
                               "daemon_controller.py")
    with io.open(controlador, encoding="utf-8", errors="replace") as fh:
        py = fh.read()
    achado = re.search(r'CHAOS_READY_MARK\s*=\s*["\'](.+?)["\']', py)
    assert achado, "CHAOS_READY_MARK nao encontrado em daemon_controller.py"
    marcador = achado.group(1)

    script = os.path.join(RAIZ, "tools", "chaos_maker.sh")
    with io.open(script, encoding="utf-8", errors="replace") as fh:
        fonte = fh.read()
    assert marcador in fonte, (
        "o chaos_maker nao imprime mais o marcador %r que o daemon espera; "
        "a espera do cenario nunca terminaria e toda rodada viraria falha"
        % marcador)
