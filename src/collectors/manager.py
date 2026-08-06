# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/collectors/manager.py
# DESCRIPTION: Central Orchestrator for Data Collection (v0.70).
#              Unifies the collection logic so Snapshot, Live, and Agent modes
#              use the exact same workflow to gather data.
#
# USAGE:
#   mgr = CollectionManager(config)
#   data = mgr.collect_snapshot(duration=30)
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.90.16
# ==============================================================================

import os
import time
import logging
from src.core.engine import SysInspectorEngine
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

    # CPU: utilizacao media por core no periodo. cpu_usage_pct ja vem calculado
    # na janela de captura; somamos por processo e dividimos pelo numero de
    # cores para obter um percentual medio de ocupacao.
    total_cpu = sum(float(p.get("cpu_usage_pct", 0.0) or 0.0) for p in nodes)
    ncpu = os.cpu_count() or 1
    cpu_avg = round(total_cpu / ncpu, 1)

    # Score de alerta: pico de anomaly_score na arvore (processo mais suspeito).
    score = max((int(p.get("anomaly_score", 0) or 0) for p in nodes), default=0)

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


def correlate_findings_with_processes(findings, processes):
    """
    Liga cada achado aos processos que estao executando o caminho que ele
    denuncia.

    Um achado de persistencia aponta para um ARQUIVO (a unit, a entrada de
    cron), nao para um PID. O valor pericial aparece quando esse caminho esta
    de fato rodando: a persistencia deixa de ser teorica e passa a ser
    atividade em curso. Preenche 'related_pids' nos achados correlacionados.

    PARAMETER findings: lista de dicts (Finding.to_dict).
    PARAMETER processes: dict pid -> dados do processo (data['processes']).
    """
    if not findings or not processes:
        return findings

    for finding in findings:
        # Caminho denunciado pelo achado: a referencia encontrada na evidencia
        # (ex.: o binario que a unit executa) e, como apoio, o proprio alvo.
        evidence = finding.get("evidence") or {}
        candidates = []
        reference = evidence.get("reference")
        if reference:
            candidates.append(str(reference))

        matches = []
        for pid, proc in processes.items():
            exe = str(proc.get("exe_path") or "")
            cmd = str(proc.get("cmd") or "")
            for path in candidates:
                if not path or len(path) < 4:
                    continue
                if exe == path or path in cmd:
                    matches.append(int(pid))
                    break

        if matches:
            finding["related_pids"] = sorted(set(matches))

    return findings


def collect_findings():
    """
    Executa os coletores de achados estaticos e devolve a lista normalizada,
    deduplicada e ordenada por severidade (mais grave primeiro).

    Hoje cobre a enumeracao de persistencia; novas fontes (integridade, SCAP)
    entram aqui e herdam automaticamente a deduplicacao e a ordenacao, mantendo
    um unico ponto de composicao de Findings.
    """
    findings = []
    try:
        findings.extend(collect_persistence())
    except Exception as exc:
        logging.getLogger("CollectorMgr").error(f"[COLLECT] Persistence failed: {exc}")
    return sort_findings(dedupe_findings(findings))


class CollectionManager:
    """
    Standardizes the data collection process across all modes.
    """
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger("CollectorMgr")
        # Initialize the BPF/Heuristics Engine
        self.engine = SysInspectorEngine(config)

    def collect_snapshot(self, duration=30):
        """
        Performs a full collection cycle:
        1. Starts BPF Engine (Traffic/Process monitoring).
        2. Waits for 'duration' seconds (sampling window).
        3. Collects Static Inventory (Hardware/Network).
        4. Merges everything into a standardized Dictionary.
        5. Stops Engine.

        Returns:
            dict: The complete forensic data structure ready for Encryption/Storage.
        """
        try:
            self.logger.info(f"[COLLECT] Starting capture window ({duration}s)...")

            # 1. Start Dynamic Analysis (eBPF + Pollers)
            self.engine.start()

            # 2. Sampling Loop
            # We sleep in small chunks to remain responsive to interrupts if needed
            start_time = time.time()
            while (time.time() - start_time) < duration:
                time.sleep(1)

            # 3. Stop Engine (Freeze state)
            self.engine.stop()

            # 4. Static Collection
            self.logger.info("[COLLECT] Gathering static system inventory...")
            full_data = collect_full_inventory()

            # 5. Merge Dynamic Data
            # This calls the updated ProcessTree logic (Duration, EDR Wchan, etc.)
            full_data['processes'] = self.engine.tree.to_json()

            # 6. Static forensic findings (persistence mechanisms).
            # Roda depois da janela eBPF para nao competir com a captura.
            self.logger.info("[COLLECT] Enumerating persistence mechanisms...")
            findings = collect_findings()
            serialized = [f.to_dict() for f in findings]
            # Liga o achado estatico ao runtime: a persistencia esta ativa?
            correlate_findings_with_processes(serialized, full_data['processes'])
            full_data['findings'] = serialized
            full_data['findings_summary'] = summarize_by_severity(findings)

            # 7. Metadata
            full_data['capture_duration'] = duration
            full_data['mode'] = self.config.get('general', {}).get('mode', 'unknown')

            self.logger.info(f"[COLLECT] Capture complete. {len(full_data['processes'])} processes tracked, "
                             f"{len(findings)} findings.")
            return full_data

        except Exception as e:
            self.logger.error(f"[COLLECT] Critical failure during collection: {e}")
            # Ensure engine stops even on error to release BPF probes
            try: self.engine.stop()
            except: pass
            raise e
