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


# ------------------------------------------------------------------------------
# CONFIDENCE (quao seguro e o achado; honestidade pericial, D-022)
# ------------------------------------------------------------------------------
# Separa fato de indicio de hipotese, para o laudo nao apresentar heuristica como
# verdade. E o direcionamento "confianca" do contrato de resposta do achado.
CONF_CONFIRMED = "confirmed"   # fato verificado (o objeto existe, foi lido)
CONF_PROBABLE = "probable"     # forte indicio, coerente, mas nao confirmado
CONF_HEURISTIC = "heuristic"   # regra local; admite falso positivo conhecido

CONFIDENCE_ORDER = {
    CONF_HEURISTIC: 0,
    CONF_PROBABLE: 1,
    CONF_CONFIRMED: 2,
}

# Rotulo em PT para a interface (o codigo/dado fica em ingles).
CONFIDENCE_LABELS = {
    CONF_CONFIRMED: "confirmado",
    CONF_PROBABLE: "provavel",
    CONF_HEURISTIC: "heuristico",
}


# ------------------------------------------------------------------------------
# CUSTODY (o que foi preservado do artefato; forense-first, D-022)
# ------------------------------------------------------------------------------
# Declara o quanto da evidencia foi de fato retido. Hoje a ferramenta coleta so
# metadado; hash e copia do artefato entram no roadmap. O campo existe para o
# laudo dizer a verdade sobre o que tem em maos, em vez de deixar o leitor supor.
CUSTODY_NONE = "none"          # nada preservado (ex.: achado de runtime sem arquivo)
CUSTODY_METADATA = "metadata"  # so metadado (mtime, tamanho, dono) -- estado atual
CUSTODY_HASH = "hash"          # metadado + hash do conteudo do artefato
CUSTODY_FULL = "full"          # metadado + hash + copia preservada do artefato

CUSTODY_ORDER = {
    CUSTODY_NONE: 0,
    CUSTODY_METADATA: 1,
    CUSTODY_HASH: 2,
    CUSTODY_FULL: 3,
}

CUSTODY_LABELS = {
    CUSTODY_NONE: "nada preservado",
    CUSTODY_METADATA: "so metadado",
    CUSTODY_HASH: "metadado + hash",
    CUSTODY_FULL: "metadado + hash + copia",
}


# ------------------------------------------------------------------------------
# REFERRAL / ENCAMINHAMENTO A BANCADA (C-044, decisoes D-028 e D-032)
# ------------------------------------------------------------------------------
# O campo que impede a fronteira de escopo de virar omissao.
#
# A D-032 fixou que esta ferramenta coleta o suficiente para IDENTIFICAR e
# DIRECIONAR, e nao a massa que PROVA: nada de gigabytes de memoria ou de
# trafego. Essa e uma decisao de produto defensavel, mas ela so e honesta se
# vier acompanhada da outra metade -- dizer quem termina o servico. Uma
# ferramenta que decide deliberadamente nao trazer a prova contrai a obrigacao
# de apontar onde ela esta.
#
# Por que nao serve o campo `recommendation` que ja existia: ele fala com o
# OPERADOR da frota, que age no host (contenha, isole, remova), e e prosa livre.
# O encaminhamento fala com quem trabalha FORA da frota, e precisa ser
# estruturado para que a proxima ferramenta receba um objeto, e nao um paragrafo.
#
# As tres perguntas, e por que sao exatamente estas tres:
#   analysis -> QUE analise conclui o que este achado nao conclui
#   reason   -> POR QUE este achado especifico a motiva (sem isto o
#               encaminhamento vira boilerplate colado em todo achado)
#   object   -> QUAL o objeto, com precisao suficiente para ser buscado depois
#               (pid, regiao de memoria, caminho de arquivo, host)
REFERRAL_CAMPOS = ("analysis", "reason", "object")


def make_referral(analysis, reason, obj):
    """
    Monta um encaminhamento a bancada.

    Os tres campos sao OBRIGATORIOS juntos: um encaminhamento que diz a analise
    e nao diz o objeto nao encaminha nada, so recomenda genericamente. Devolve
    dict vazio se algum faltar, para o laudo poder distinguir "nao encaminhado"
    de "encaminhado pela metade" (D-020).
    """
    if not (analysis and reason and obj):
        return {}
    return {"analysis": str(analysis), "reason": str(reason),
            "object": str(obj)}


def has_referral(referral):
    """Se um achado de fato declara encaminhamento (os tres campos presentes)."""
    return (isinstance(referral, dict)
            and all(referral.get(c) for c in REFERRAL_CAMPOS))


def confidence_label(confidence):
    """Rotulo PT de um nivel de confianca, ou vazio se nao declarado."""
    return CONFIDENCE_LABELS.get(confidence, "")


def custody_level(custody):
    """
    Nivel de custodia de um achado (dict de custodia). Devolve CUSTODY_NONE
    quando nada foi declarado, nunca None: ausencia de custodia e uma resposta.
    """
    if isinstance(custody, dict):
        level = custody.get("level")
        if level in CUSTODY_ORDER:
            return level
    return CUSTODY_NONE


def custody_label(custody):
    """Rotulo PT do nivel de custodia de um achado."""
    return CUSTODY_LABELS.get(custody_level(custody), CUSTODY_LABELS[CUSTODY_NONE])


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
                 references=None, recommendation=None,
                 confidence=None, custody=None, referral=None):
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
        PARAMETER confidence: um dos CONF_* (quao seguro e o achado). None quando
                  o coletor ainda nao declarou; a interface trata como nao dito.
        PARAMETER custody: dict de custodia {"level": CUSTODY_*, "sha256": ...,
                  "copy_path": ...}. Declara o que foi preservado do artefato.
        PARAMETER referral: dict de encaminhamento a bancada (ver make_referral),
                  com analysis/reason/object. Vazio quando o achado se conclui
                  dentro do alcance da frota, e isso tambem e uma resposta.
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
        self.confidence = confidence if confidence in CONFIDENCE_ORDER else None
        self.custody = custody if isinstance(custody, dict) else {}
        self.referral = referral if isinstance(referral, dict) else {}

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
            "confidence": self.confidence,
            "custody": self.custody,
            "referral": self.referral,
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
