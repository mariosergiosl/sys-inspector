# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/collectors/memory_forensics.py
# DESCRIPTION: O que o processo carrega em memoria, e o que isso denuncia.
#
# WHY:         A arvore de processos responde "o que esta rodando". A pericia
#              precisa de outra resposta: "esse processo ainda e o que dizia
#              ser?". Um atacante que ja executou nao precisa de processo novo:
#              ele injeta codigo em um legitimo, troca o binario no disco, ou
#              executa a partir de memoria sem tocar em arquivo nenhum. Nos tres
#              casos a lista de processos continua parecendo normal.
#
# METHOD:      Tudo aqui vem de /proc, so leitura, sem parar nem alterar o
#              processo observado. Uma ferramenta forense que interfere no
#              objeto sob analise destroi a propria evidencia.
#
# THREE SIGNALS:
#              1. Regiao de memoria gravavel E executavel ao mesmo tempo. Um
#                 programa compilado normalmente nao precisa disso: codigo fica
#                 em regiao so de leitura. W+X e a assinatura de codigo escrito
#                 em tempo de execucao, que e o que shellcode e injecao fazem.
#              2. Executavel mapeado que ja nao existe no disco, ou que passou a
#                 ser outro arquivo. Denuncia substituicao de binario e execucao
#                 a partir de arquivo apagado.
#              3. Biblioteca carregada de fora dos diretorios do sistema, com o
#                 dono e a permissao do arquivo, para separar o caso legitimo do
#                 sequestro por LD_PRELOAD.
#
# LIMITS:      Nada disto e prova de comprometimento. Interpretadores (JIT de
#              Java, Python, navegadores) usam W+X legitimamente, e o modulo diz
#              isso em vez de acusar. Prova exige captura de memoria com
#              ferramenta dedicada; aqui se produz o INDICIO que justifica ir
#              buscar essa prova.
#
# NOTES:       Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import re
import logging

from src.core.findings import (Finding, SEV_HIGH, SEV_MEDIUM, SEV_LOW,
                               SRC_HEURISTIC, CONF_PROBABLE, CONF_HEURISTIC,
                               CUSTODY_NONE, CUSTODY_METADATA)

LOG = logging.getLogger("MemForensics")

PROC = "/proc"

# Diretorios de onde o sistema legitimamente carrega codigo. Fora daqui, uma
# biblioteca merece explicacao.
DIRETORIOS_DO_SISTEMA = ("/lib", "/lib64", "/usr/lib", "/usr/lib64",
                         "/usr/local/lib", "/opt")

# Programas que geram codigo em tempo de execucao por natureza. Nao sao
# isentados: a severidade cai e o motivo aparece, para o analista decidir.
GERADORES_DE_CODIGO = ("java", "python", "node", "chrome", "firefox", "mono",
                       "dotnet", "ruby", "perl", "php", "wine", "qemu")

LINHA_MAPA = re.compile(
    r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+(\S+)\s+(\d+)\s*(.*)$")


def _ler_mapas(pid):
    """
    Regioes de memoria de um processo.

    Falhar aqui e comum e esperado: processos terminam durante a varredura e
    processos de outro usuario podem ser ilegiveis. Nenhum dos dois casos e
    evidencia de coisa alguma.
    """
    regioes = []
    try:
        with open("%s/%d/maps" % (PROC, pid), "r") as fh:
            for linha in fh:
                m = LINHA_MAPA.match(linha.strip())
                if not m:
                    continue
                inicio, fim, perms, dev, inode, caminho = m.groups()
                regioes.append({
                    "start": inicio, "end": fim, "perms": perms,
                    "inode": int(inode), "path": (caminho or "").strip(),
                    "size": int(fim, 16) - int(inicio, 16),
                })
    except (IOError, OSError):
        return []
    return regioes


def _gerador_de_codigo(cmd):
    alvo = (cmd or "").lower()
    return any(nome in alvo for nome in GERADORES_DE_CODIGO)


# ------------------------------------------------------------------------------
# 1. MEMORIA GRAVAVEL E EXECUTAVEL
# ------------------------------------------------------------------------------
def find_wx_regions(pid):
    """
    Regioes que aceitam escrita E execucao simultaneas.

    Um binario compilado nao precisa disso: o codigo fica em regiao apenas de
    leitura e execucao. W+X significa que algo pode ser escrito e imediatamente
    executado, que e exatamente o que shellcode injetado precisa.
    """
    achadas = []
    for r in _ler_mapas(pid):
        if "w" in r["perms"] and "x" in r["perms"]:
            achadas.append(r)
    return achadas


# ------------------------------------------------------------------------------
# 2. EXECUTAVEL QUE MUDOU OU SUMIU
# ------------------------------------------------------------------------------
def check_executable_backing(pid):
    """
    Confere se o executavel mapeado ainda corresponde ao arquivo em disco.

    Compara o inode do mapeamento com o do caminho atual. Divergencia significa
    que o caminho aponta hoje para OUTRO arquivo: o binario foi substituido
    enquanto o processo continuava rodando com o original em memoria. E uma
    troca que nenhuma verificacao feita so no disco perceberia, porque o disco
    ja mostra o arquivo novo, coerente consigo mesmo.
    """
    try:
        alvo = os.readlink("%s/%d/exe" % (PROC, pid))
    except (IOError, OSError):
        return None

    apagado = alvo.endswith(" (deleted)")
    caminho = alvo[:-10] if apagado else alvo

    resultado = {"path": caminho, "deleted": apagado,
                 "replaced": False, "mapped_inode": None, "disk_inode": None}

    if apagado:
        return resultado

    inode_mapeado = None
    for r in _ler_mapas(pid):
        if r["path"] == caminho and "x" in r["perms"]:
            inode_mapeado = r["inode"]
            break
    if not inode_mapeado:
        return resultado

    try:
        inode_disco = os.stat(caminho).st_ino
    except OSError:
        return resultado

    resultado["mapped_inode"] = inode_mapeado
    resultado["disk_inode"] = inode_disco
    resultado["replaced"] = inode_mapeado != inode_disco
    return resultado


# ------------------------------------------------------------------------------
# 3. BIBLIOTECA DE FORA DO SISTEMA
# ------------------------------------------------------------------------------
def find_foreign_libraries(pid):
    """
    Bibliotecas carregadas de diretorios que nao sao os do sistema.

    Traz dono e permissao do arquivo porque e isso que separa o caso legitimo
    (software instalado em /opt proprio) do sequestro: uma biblioteca gravavel
    por qualquer usuario, carregada de /tmp, e outra conversa.
    """
    vistos = set()
    achadas = []
    for r in _ler_mapas(pid):
        caminho = r["path"]
        if (not caminho or not caminho.startswith("/")
                or ".so" not in caminho or caminho in vistos):
            continue
        if caminho.startswith(DIRETORIOS_DO_SISTEMA):
            continue
        vistos.add(caminho)

        item = {"path": caminho, "world_writable": False, "uid": None}
        try:
            st = os.stat(caminho)
            item["uid"] = st.st_uid
            item["world_writable"] = bool(st.st_mode & 0o002)
        except OSError:
            item["missing"] = True
        achadas.append(item)
    return achadas


# ------------------------------------------------------------------------------
# COMPOSICAO
# ------------------------------------------------------------------------------
def collect_memory_forensics(processos):
    """
    Converte os tres sinais em Findings.

    PARAMETER processos: dict pid -> dados, como a arvore ja produziu. Reusar a
                         arvore evita uma segunda varredura de /proc e mantem o
                         custo no host inspecionado proximo de zero.
    """
    achados = []

    for pid, dados in (processos or {}).items():
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        cmd = (dados or {}).get("cmd") or ""

        # --- 1. W+X ---
        try:
            regioes = find_wx_regions(pid)
        except Exception:
            regioes = []
        if regioes:
            interpretador = _gerador_de_codigo(cmd)
            total = sum(r["size"] for r in regioes)
            achados.append(Finding(
                title="Memoria gravavel e executavel em %s (PID %d)"
                      % (os.path.basename(cmd.split()[0]) if cmd else "?", pid),
                severity=SEV_LOW if interpretador else SEV_HIGH,
                source=SRC_HEURISTIC,
                category="memory",
                target="pid:%d" % pid,
                description=(
                    "%d regiao(oes), %d KB no total, aceitam escrita e execucao "
                    "ao mesmo tempo. Um programa compilado nao precisa disso: "
                    "seu codigo fica em regiao apenas de leitura. %s"
                    % (len(regioes), total // 1024,
                       "Este processo gera codigo em tempo de execucao por "
                       "natureza (JIT), o que explica o achado sem inocenta-lo."
                       if interpretador else
                       "Nao ha explicacao legitima aparente: e a assinatura de "
                       "codigo escrito e executado em tempo de execucao, como "
                       "faz shellcode injetado.")),
                evidence={"pid": pid, "cmd": cmd[:300],
                          "regions": regioes[:10],
                          "total_kb": total // 1024,
                          "jit_capable": interpretador},
                technique="T1055",
                confidence=CONF_HEURISTIC if interpretador else CONF_PROBABLE,
                custody={"level": CUSTODY_NONE},
                recommendation=(
                    "Capturar a memoria do processo ANTES de qualquer acao: "
                    "encerra-lo apaga exatamente o conteudo que provaria a "
                    "injecao. Comparar as regioes com as de um processo "
                    "equivalente sabidamente integro.")))

        # --- 2. executavel trocado ---
        try:
            lastro = check_executable_backing(pid)
        except Exception:
            lastro = None
        if lastro and lastro.get("replaced"):
            achados.append(Finding(
                title="Binario em execucao foi substituido no disco (PID %d)" % pid,
                severity=SEV_HIGH,
                source=SRC_HEURISTIC,
                category="memory",
                target=lastro["path"],
                description=(
                    "O processo executa o arquivo de inode %s, mas o caminho "
                    "aponta hoje para o inode %s: o binario foi trocado com o "
                    "processo ainda rodando. Uma verificacao feita apenas no "
                    "disco nao perceberia, porque o disco ja mostra o arquivo "
                    "novo, coerente consigo mesmo."
                    % (lastro["mapped_inode"], lastro["disk_inode"])),
                evidence=lastro,
                technique="T1036",
                confidence=CONF_PROBABLE,
                custody={"level": CUSTODY_METADATA},
                recommendation=(
                    "Preservar o arquivo atual e, se possivel, extrair o "
                    "original ainda mapeado em memoria. Comparar com a versao "
                    "do pacote e conferir o horario da troca contra o log.")))

        # --- 3. biblioteca estranha ---
        try:
            libs = find_foreign_libraries(pid)
        except Exception:
            libs = []
        arriscadas = [l for l in libs
                      if l.get("world_writable") or l.get("missing")]
        if arriscadas:
            achados.append(Finding(
                title="Biblioteca carregada de local nao confiavel (PID %d)" % pid,
                severity=SEV_MEDIUM,
                source=SRC_HEURISTIC,
                category="memory",
                target="pid:%d" % pid,
                description=(
                    "O processo carregou codigo de fora dos diretorios do "
                    "sistema, a partir de arquivo gravavel por qualquer usuario "
                    "ou que ja nao existe. Quem pode escrever nesse arquivo "
                    "executa codigo dentro deste processo, com os privilegios "
                    "dele."),
                evidence={"pid": pid, "cmd": cmd[:300], "libraries": arriscadas[:10]},
                technique="T1574.006",
                confidence=CONF_HEURISTIC,
                custody={"level": CUSTODY_NONE},
                recommendation=(
                    "Conferir a procedencia do arquivo e quem pode escrever "
                    "nele. Verificar LD_PRELOAD e /etc/ld.so.preload no "
                    "ambiente do processo.")))

    return achados
