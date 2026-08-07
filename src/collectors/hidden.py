# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/collectors/hidden.py
# DESCRIPTION: Procura processos e portas que o sistema esconde de si mesmo.
#
# WHY:         Um rootkit de espaco de usuario nao apaga o processo: apaga a
#              resposta que as ferramentas dao sobre ele. `ps` le /proc, e um
#              /proc adulterado (ou um ps trocado) omite o que interessa. A
#              deteccao aqui nao confia em uma unica resposta: pergunta a mesma
#              coisa por caminhos independentes e trata a DIVERGENCIA como o
#              achado.
#
# METHOD:      Um processo que o kernel escalona mas que nao aparece na
#              listagem de /proc so pode ser explicado por ocultacao. O mesmo
#              raciocinio vale para uma porta que esta em uso mas nao consta na
#              tabela de conexoes.
#
# LIMITS:      Isto detecta INCONSISTENCIA, nao rootkit. Um processo que nasce
#              ou morre entre as duas leituras produz divergencia legitima, e
#              por isso a confirmacao exige que a discrepancia persista. Um
#              rootkit de kernel que mente para os dois caminhos ao mesmo tempo
#              nao e pego aqui, e dize-lo e mais honesto do que sugerir uma
#              garantia que o metodo nao da.
#
# NOTES:       Compativel com Python 3.6. Somente leitura, sem dependencia
#              externa: roda no host sob investigacao sem alterar estado.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.92.0
# ==============================================================================

import os
import errno
import logging

from src.core.findings import (Finding, SEV_HIGH, SEV_MEDIUM, SRC_HEURISTIC)

LOG = logging.getLogger("Hidden")

PROC = "/proc"

# Faixa varrida na segunda leitura. Cobre o espaco usual de PIDs sem transformar
# a verificacao num custo perceptivel no host inspecionado.
PID_MAX_PADRAO = 65536

# Quantas vezes a divergencia precisa se repetir para virar achado. Processo que
# nasce ou morre entre as leituras diverge uma vez de forma legitima; o que
# esconde continua divergindo.
CONFIRMACOES = 2


def _pids_listados():
    """PIDs que /proc admite ter, que e o que `ps` enxerga."""
    try:
        return set(int(nome) for nome in os.listdir(PROC) if nome.isdigit())
    except OSError as exc:
        LOG.error("Listing %s failed: %s", PROC, exc)
        return set()


def _tarefas_conhecidas():
    """
    Todo identificador que o sistema admite: processos E threads.

    O kernel responde a sinal tanto para um processo quanto para uma thread, mas
    /proc so lista no topo o lider do grupo. Comparar com a listagem de topo,
    portanto, marcava como escondida cada thread de cada processo com mais de
    uma, o que num host comum sao dezenas de acusacoes falsas. Um falso positivo
    aqui e caro: leva o analista a tratar um host integro como comprometido.
    """
    conhecidos = _pids_listados()
    for pid in list(conhecidos):
        try:
            for tid in os.listdir("%s/%d/task" % (PROC, pid)):
                if tid.isdigit():
                    conhecidos.add(int(tid))
        except OSError:
            # Processo terminou durante a varredura; nada a concluir dai.
            continue
    return conhecidos


def _pid_existe(pid):
    """
    Pergunta ao kernel se o PID existe, sem passar pela listagem de /proc.

    O sinal 0 nao entrega nada ao processo: serve so para o kernel responder se
    ele existe e se ha permissao. EPERM confirma existencia tanto quanto o
    sucesso, e a distincao importa: um processo de outro usuario existe mesmo
    que nao possa ser sinalizado.
    """
    try:
        os.kill(pid, 0)
        return True
    except OSError as exc:
        if exc.errno == errno.EPERM:
            return True
        if exc.errno == errno.ESRCH:
            return False
        return False


def _detalhe(pid):
    """
    Tudo que ainda se consegue saber de um PID escondido da listagem.

    Um rootkit costuma esconder o diretorio da listagem sem conseguir remover o
    acesso direto, entao ler o caminho exato frequentemente devolve justamente o
    que se queria esconder.
    """
    dados = {"pid": pid}
    for campo, caminho in (("cmdline", "cmdline"), ("comm", "comm"),
                           ("status", "status")):
        try:
            with open("%s/%d/%s" % (PROC, pid, caminho), "rb") as fh:
                bruto = fh.read(4096).replace(b"\x00", b" ").strip()
                dados[campo] = bruto.decode("utf-8", "replace")[:400]
        except (IOError, OSError):
            continue
    try:
        dados["exe"] = os.readlink("%s/%d/exe" % (PROC, pid))
    except (IOError, OSError):
        pass
    return dados


def find_hidden_pids(pid_max=PID_MAX_PADRAO, confirmacoes=CONFIRMACOES):
    """
    Varre a faixa de PIDs e devolve os que existem para o kernel mas nao para
    a listagem de /proc.

    PARAMETER pid_max: maior PID testado.
    PARAMETER confirmacoes: quantas rodadas a divergencia precisa se repetir.

    Cada rodada re-testa apenas os suspeitos da anterior, e nao a faixa inteira:
    o custo da confirmacao fica proximo de zero, e o que sobrevive a todas as
    rodadas nao pode ser explicado por processo de vida curta.
    """
    suspeitos = None
    for _ in range(max(1, confirmacoes)):
        listados = _tarefas_conhecidas()
        faixa = range(1, pid_max + 1) if suspeitos is None else sorted(suspeitos)
        rodada = set(pid for pid in faixa
                     if pid not in listados and _pid_existe(pid))
        suspeitos = rodada if suspeitos is None else (suspeitos & rodada)
        if not suspeitos:
            return []
    return sorted(suspeitos)


def find_hidden_threads():
    """
    Processos cujo numero de threads declarado nao bate com o que ha em task/.

    Esconder uma thread e mais barato para o atacante do que esconder o processo
    inteiro, e passa despercebido por qualquer ferramenta que so conte processos.
    """
    divergentes = []
    for pid in _pids_listados():
        try:
            with open("%s/%d/status" % (PROC, pid), "r") as fh:
                declarado = 0
                for linha in fh:
                    if linha.startswith("Threads:"):
                        declarado = int(linha.split()[1])
                        break
            reais = len(os.listdir("%s/%d/task" % (PROC, pid)))
        except (IOError, OSError, ValueError, IndexError):
            # Processo que terminou durante a leitura: nao e evidencia de nada.
            continue
        if declarado and reais and declarado != reais:
            divergentes.append({"pid": pid, "declared": declarado,
                                "listed": reais})
    return divergentes


def collect_hidden():
    """
    Converte as divergencias encontradas em Findings.

    A severidade e alta para PID oculto porque nao existe configuracao legitima
    que produza esse estado, e media para divergencia de threads, onde uma
    corrida de leitura ainda e explicacao plausivel.
    """
    achados = []

    try:
        for pid in find_hidden_pids():
            detalhe = _detalhe(pid)
            achados.append(Finding(
                title="Processo ativo ausente da listagem de /proc (PID %d)" % pid,
                severity=SEV_HIGH,
                source=SRC_HEURISTIC,
                category="hidden",
                target="pid:%d" % pid,
                description=(
                    "O kernel confirma que este PID existe, mas ele nao aparece "
                    "na listagem de /proc, que e a fonte usada por ps e top. "
                    "Nao ha configuracao legitima que produza essa divergencia; "
                    "ocultacao deliberada e a explicacao esperada. A divergencia "
                    "foi confirmada em leituras sucessivas, o que descarta um "
                    "processo de vida curta."),
                evidence=detalhe,
                technique="T1014",
                recommendation=(
                    "Preservar a memoria do host ANTES de qualquer intervencao: "
                    "matar o processo destroi a evidencia. Comparar com uma "
                    "listagem obtida por outro caminho e verificar a integridade "
                    "dos binarios de ps, top e do proprio modulo de /proc.")))
    except Exception as exc:
        LOG.error("Hidden PID scan failed: %s", exc)

    try:
        for item in find_hidden_threads():
            achados.append(Finding(
                title="Contagem de threads divergente no PID %d" % item["pid"],
                severity=SEV_MEDIUM,
                source=SRC_HEURISTIC,
                category="hidden",
                target="pid:%d" % item["pid"],
                description=(
                    "O processo declara %d threads mas %d aparecem em task/. "
                    "Esconder uma thread custa menos ao atacante do que esconder "
                    "o processo inteiro e escapa de qualquer ferramenta que so "
                    "conte processos. Uma leitura feita durante criacao ou "
                    "termino de thread tambem produz essa diferenca, entao o "
                    "achado pede confirmacao antes de conclusao."
                    % (item["declared"], item["listed"])),
                evidence=item,
                technique="T1014",
                recommendation=(
                    "Repetir a leitura: se a diferenca persistir em capturas "
                    "sucessivas, deixa de ser explicavel por corrida de leitura.")))
    except Exception as exc:
        LOG.error("Hidden thread scan failed: %s", exc)

    return achados
