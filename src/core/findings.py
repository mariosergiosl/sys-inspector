# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/findings.py
# DESCRIPTION: Finding entity: the single normalized unit of evidence produced
#              by any collector (eBPF runtime heuristics, persistence
#              enumeration, integrity checks and, later, SCAP/OVAL).
#
#              A Finding always carries WHO produced it (source), so the analyst
#              can tell a runtime observation apart from a static configuration
#              check when reading the report.
#
# NOTES:       Kept compatible with Python 3.6 (no dataclasses).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.90.16
# ==============================================================================

import hashlib


# ------------------------------------------------------------------------------
# SEVERITY SCALE (unica para todo o produto)
# ------------------------------------------------------------------------------
SEV_INFO = "Info"
SEV_LOW = "Low"
SEV_MEDIUM = "Medium"
SEV_HIGH = "High"
SEV_CRITICAL = "Critical"

# Ordem para ranqueamento/ordenacao (maior = mais grave).
SEVERITY_ORDER = {
    SEV_INFO: 0,
    SEV_LOW: 1,
    SEV_MEDIUM: 2,
    SEV_HIGH: 3,
    SEV_CRITICAL: 4,
}


# ------------------------------------------------------------------------------
# SOURCES (quem produziu o achado; exibido na interface)
# ------------------------------------------------------------------------------
SRC_EBPF = "ebpf"                 # heuristicas de runtime via probes eBPF
SRC_PERSISTENCE = "persistence"   # enumeracao de mecanismos de persistencia
SRC_INTEGRITY = "integrity"       # verificacao de integridade (rpm -Va, hashes)
SRC_SCAP = "scap"                 # OpenSCAP/OVAL/XCCDF (futuro)
SRC_HEURISTIC = "heuristic"       # regras locais genericas


class Finding(object):
    """
    Unidade normalizada de achado.

    Um Finding responde: o que foi encontrado, quao grave e, quem encontrou
    (source), onde (target) e qual a evidencia bruta que sustenta a conclusao.
    A evidencia e mantida junto do achado para a cadeia de custodia: o analista
    deve conseguir refazer o raciocinio sem confiar apenas no rotulo.
    """

    def __init__(self, title, severity, source, category=None, target=None,
                 description=None, evidence=None, technique=None,
                 references=None, recommendation=None):
        """
        PARAMETER title: resumo curto do achado (aparece na lista).
        PARAMETER severity: um dos SEV_* (escala unica do produto).
        PARAMETER source: um dos SRC_* (quem produziu; visivel na interface).
        PARAMETER category: agrupamento logico (ex.: "persistence", "network").
        PARAMETER target: objeto afetado (caminho de arquivo, PID, unit, usuario).
        PARAMETER description: explicacao do porque isso importa.
        PARAMETER evidence: dict com a prova bruta (conteudo, mtime, hash, etc.).
        PARAMETER technique: tecnica MITRE ATT&CK (ex.: "T1053.003").
        PARAMETER references: lista de referencias (CVE/CWE/controle/URL).
        PARAMETER recommendation: acao sugerida ao responder o incidente.
        """
        self.title = title
        self.severity = severity if severity in SEVERITY_ORDER else SEV_INFO
        self.source = source
        self.category = category or "general"
        self.target = target or ""
        self.description = description or ""
        self.evidence = evidence or {}
        self.technique = technique or ""
        self.references = references or []
        self.recommendation = recommendation or ""

    @property
    def fingerprint(self):
        """
        Identificador estavel do achado, usado para deduplicar entre capturas
        e correlacionar o mesmo achado em varios agentes. Baseado nos campos
        que definem a identidade (nao inclui a evidencia, que pode variar).
        """
        raw = "|".join([str(self.source), str(self.category),
                        str(self.title), str(self.target)])
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def rank(self):
        """Peso numerico da severidade, para ordenar do mais grave ao menos."""
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self):
        """Serializa o achado para o payload da captura (JSON-friendly)."""
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "rank": self.rank,
            "source": self.source,
            "category": self.category,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "technique": self.technique,
            "references": self.references,
            "recommendation": self.recommendation,
        }

    def __repr__(self):
        return "<Finding %s [%s] %s: %s>" % (self.fingerprint, self.severity,
                                             self.source, self.title)


def sort_findings(findings):
    """
    Ordena achados do mais grave para o menos grave; empate resolvido por
    categoria e titulo, para a saida ser estavel entre execucoes.
    """
    return sorted(findings,
                  key=lambda f: (-f.rank, f.category, f.title))


def dedupe_findings(findings):
    """Remove achados repetidos pelo fingerprint, preservando a ordem."""
    seen = set()
    unique = []
    for f in findings:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        unique.append(f)
    return unique


def summarize_by_severity(findings):
    """Conta achados por severidade (para cabecalho/painel de resumo)."""
    counts = {}
    for level in SEVERITY_ORDER:
        counts[level] = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
