# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/collectors/manager.py
# DESCRIPTION: Pecas compartilhadas da coleta: resumo de metricas, composicao de
#              achados e a ligacao entre achado estatico e processo em execucao.
#
# [2026-08-19] A classe CollectionManager saiu daqui junto com os modos
#              snapshot, live e local-live (C-134). Ela era a TERCEIRA
#              implementacao do ato de coletar, ao lado de
#              LiveController._collection_loop e DaemonController
#              .collect_and_store, e as tres divergiram: o C-132 foi o sintoma
#              -- collect_findings() recebia a arvore de processos no daemon e
#              NAO recebia nos outros dois, que por isso pulavam a forense de
#              memoria em silencio. Com um caminho so, esse defeito deixa de
#              existir em vez de precisar de conserto.
#
#              O que sobrou neste arquivo sao FUNCOES, nao um orquestrador:
#              cada uma faz uma coisa e o daemon as compoe.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import re
import time
import logging
from src.collectors.system_inventory import collect_full_inventory
from src.collectors.persistence import collect_persistence
from src.core.findings import sort_findings, dedupe_findings, summarize_by_severity


def summarize_metrics(processes):
    """
    Resume as metricas quentes de uma captura a partir da arvore ja agregada
    (aggregate_stats roda em engine.stop). Alimenta as colunas estruturadas da
    tabela 'snapshots' (cpu_avg, mem_used_mb, pids_count, alert_score), usadas
    para timeline e ordenacao por alerta sem descriptografar o blob. Helper
    compartilhado por snapshot e daemon para manter um unico modelo.

    PARAMETER processes: dict pid -> dados do processo (data['processes']).
    Retorna dict com chaves cpu, mem, pids, score.
    """
    nodes = list(processes.values()) if processes else []

    pids = len(nodes)

    def _number(value, cast):
        """
        Converte um valor da captura, tolerando dado ausente ou malformado.

        Este resumo roda em TODA captura: deixar uma excecao escapar por causa
        de um unico processo com valor estranho custaria a coleta inteira, que
        e justamente o que nao se pode perder numa pericia.
        """
        try:
            return cast(value or 0)
        except (TypeError, ValueError):
            return cast(0)

    # CPU: utilizacao media por core no periodo. cpu_usage_pct ja vem calculado
    # na janela de captura; somamos por processo e dividimos pelo numero de
    # cores para obter um percentual medio de ocupacao.
    total_cpu = sum(_number(p.get("cpu_usage_pct"), float) for p in nodes)
    ncpu = os.cpu_count() or 1
    cpu_avg = round(total_cpu / ncpu, 1)

    # Score de alerta: pico de anomaly_score na arvore (processo mais suspeito).
    score = max((_number(p.get("anomaly_score"), int) for p in nodes), default=0)

    # Memoria usada (MB) via /proc/meminfo: MemTotal - MemAvailable.
    mem_used = 0
    try:
        info = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    info[parts[0].strip()] = int(parts[1].strip().split()[0])
        if "MemTotal" in info and "MemAvailable" in info:
            mem_used = int((info["MemTotal"] - info["MemAvailable"]) / 1024)
    except Exception:
        mem_used = 0

    return {"cpu": cpu_avg, "mem": mem_used, "pids": pids, "score": score}


# Alvo de achado que aponta um processo: "pid:1234".
_ALVO_PID = re.compile(r'^pid:(\d+)$')


def _pid_declarado(finding):
    """
    O PID que o proprio achado ja nomeia, quando existe.

    Duas fontes, nesta ordem: o campo `target` no formato "pid:NNNN", que e
    como os coletores de runtime identificam o objeto, e `evidence["pid"]`.
    Devolve None quando o achado nao e sobre um processo (um achado de kernel,
    de arquivo ou de frota nao tem PID, e isso nao e ausencia de dado).
    """
    alvo = str(finding.get("target") or "")
    m = _ALVO_PID.match(alvo)
    if m:
        return int(m.group(1))
    pid = (finding.get("evidence") or {}).get("pid")
    try:
        return int(pid) if pid is not None else None
    except (TypeError, ValueError):
        return None


def correlate_findings_with_processes(findings, processes):
    """
    Liga cada achado aos processos a que ele se refere, por DUAS vias.

    1. Por PID declarado. Um achado de runtime (memoria gravavel-e-executavel,
       binario substituido, biblioteca estranha) JA sabe o PID: ele esta no
       titulo, no alvo e na evidencia. Este caminho existe desde 2026-08-20 e
       corrige uma lacuna que vinha de antes: o achado com a identificacao mais
       precisa possivel era justamente o unico que nunca ganhava o atalho para
       a arvore, porque a correlacao so sabia casar CAMINHO.

    2. Por caminho denunciado. Um achado de persistencia aponta para um
       ARQUIVO (a unit, a entrada de cron), nao para um PID. O valor pericial
       aparece quando esse caminho esta de fato rodando: a persistencia deixa
       de ser teorica e passa a ser atividade em curso.

    As duas vias respondem perguntas diferentes e por isso convivem. A ausencia
    do atalho continua significando alguma coisa: no caso 2, que o artefato
    plantado nao esta em execucao agora; no caso 1, que o processo ja terminou
    entre a deteccao e a montagem do laudo.

    PARAMETER findings: lista de dicts (Finding.to_dict).
    PARAMETER processes: dict pid -> dados do processo (data['processes']).
    """
    if not findings or not processes:
        return findings

    # As chaves da captura chegam como texto no JSON e como int no objeto vivo.
    # Normalizar uma vez evita o atalho sumir por causa do tipo da chave, que e
    # o tipo de defeito que ninguem procura quando "o botao nao aparece".
    por_pid = {}
    for pid, proc in processes.items():
        try:
            por_pid[int(pid)] = proc
        except (TypeError, ValueError):
            continue

    for finding in findings:
        matches = []

        # --- 1. PID que o achado ja nomeia -----------------------------------
        declarado = _pid_declarado(finding)
        if declarado is not None and declarado in por_pid:
            matches.append(declarado)

        # --- 2. Caminho denunciado, executado por alguem ---------------------
        evidence = finding.get("evidence") or {}
        candidates = []
        reference = evidence.get("reference")
        if reference:
            candidates.append(str(reference))

        if candidates:
            for pid, proc in por_pid.items():
                exe = str(proc.get("exe_path") or "")
                cmd = str(proc.get("cmd") or "")
                for path in candidates:
                    if not path or len(path) < 4:
                        continue
                    if exe == path or path in cmd:
                        matches.append(pid)
                        break

        if matches:
            finding["related_pids"] = sorted(set(matches))

    return findings


def collect_findings(processos=None, config=None):
    """
    Executa os coletores de achados estaticos e devolve a lista normalizada,
    deduplicada e ordenada por severidade (mais grave primeiro).

    Hoje cobre a enumeracao de persistencia; novas fontes (integridade, SCAP)
    entram aqui e herdam automaticamente a deduplicacao e a ordenacao, mantendo
    um unico ponto de composicao de Findings.

    PARAMETER config: configuracao do agente. Serve a aquisicao dirigida
              (C-043): o Acquirer nasce AQUI, um por captura, porque o orcamento
              total de bytes e por captura. Um objeto de vida longa acumularia
              gasto entre capturas e desligaria a aquisicao sozinho depois de
              algumas horas, sem avisar (a falha do agente que emudece, D-015).
    """
    findings = []
    acquirer = None
    try:
        from src.core.acquisition import Acquirer
        acquirer = Acquirer(config)
    except Exception as exc:
        logging.getLogger("CollectorMgr").error(
            f"[COLLECT] Acquirer indisponivel: {exc}")
    try:
        findings.extend(collect_persistence())
    except Exception as exc:
        logging.getLogger("CollectorMgr").error(f"[COLLECT] Persistence failed: {exc}")
    try:
        from src.collectors.hidden import collect_hidden
        findings.extend(collect_hidden())
    except Exception as exc:
        logging.getLogger("CollectorMgr").error(f"[COLLECT] Hidden scan failed: {exc}")
    # [C-037] Rootkit: o detector de processo oculto acima pega quem esconde
    # PROCESSO; este pega quem esconde a si mesmo dentro do kernel, cruzando as
    # tres listas de modulos e o taint. Sao perguntas diferentes, e por isso dois
    # coletores e nao um.
    try:
        from src.collectors.rootkit import collect_rootkit
        findings.extend(collect_rootkit(acquirer=acquirer))
    except Exception as exc:
        logging.getLogger("CollectorMgr").error(f"[COLLECT] Rootkit scan failed: {exc}")
    # Reusa a arvore ja coletada em vez de varrer /proc de novo: o custo extra
    # no host inspecionado fica proximo de zero.
    if processos:
        try:
            from src.collectors.memory_forensics import collect_memory_forensics
            findings.extend(collect_memory_forensics(processos, acquirer))
        except Exception as exc:
            logging.getLogger("CollectorMgr").error(
                f"[COLLECT] Memory forensics failed: {exc}")
    return sort_findings(dedupe_findings(findings))
