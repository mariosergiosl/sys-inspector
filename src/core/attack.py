# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/attack.py
# DESCRIPTION: Local MITRE ATT&CK reference for the techniques this tool
#              reports, so an identifier like "T1053.003" reads as a technique
#              name and a tactic instead of an opaque code.
#
# WHY LOCAL:   The report is a self-contained piece of evidence and must be
#              readable offline, in an air-gapped lab or attached to a case
#              file. The catalogue therefore ships with the tool; the MITRE URL
#              is offered as an extra for whoever has connectivity.
#
# SOURCE:      https://attack.mitre.org/ (MITRE ATT&CK for Enterprise)
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

# id -> (nome, tatica, descricao curta em uma frase)
TECHNIQUES = {
    "T1037": (
        "Boot or Logon Initialization Scripts",
        "Persistence, Privilege Escalation",
        "Scripts executed at boot or at logon run attacker code automatically "
        "every time the system starts or a user signs in."),
    "T1053.003": (
        "Scheduled Task/Job: Cron",
        "Execution, Persistence, Privilege Escalation",
        "A cron entry re-launches the attacker payload on a schedule, "
        "restoring access even after the process is killed."),
    "T1098.004": (
        "Account Manipulation: SSH Authorized Keys",
        "Persistence",
        "Adding a public key to authorized_keys grants silent, password-less "
        "remote access that survives password changes."),
    "T1543.002": (
        "Create or Modify System Process: Systemd Service",
        "Persistence, Privilege Escalation",
        "A systemd unit starts the payload at boot, usually as root, and can "
        "restart it automatically when it dies."),
    "T1547": (
        "Boot or Logon Autostart Execution",
        "Persistence, Privilege Escalation",
        "Generic autostart mechanism that runs attacker code as part of system "
        "or user initialization."),
    "T1547.006": (
        "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
        "Persistence, Privilege Escalation",
        "A malicious kernel module loaded at boot yields the most privileged "
        "form of persistence and can hide other artifacts."),
    "T1556.003": (
        "Modify Authentication Process: Pluggable Authentication Modules",
        "Credential Access, Defense Evasion, Persistence",
        "A tampered PAM stack can capture credentials as users log in or accept "
        "a backdoor password."),
    "T1574.006": (
        "Hijack Execution Flow: Dynamic Linker Hijacking",
        "Persistence, Privilege Escalation, Defense Evasion",
        "Preloading a library through ld.so.preload injects attacker code into "
        "every dynamically linked process, the classic userland rootkit."),
}

MITRE_URL = "https://attack.mitre.org/techniques/"


def describe(technique_id):
    """
    Devolve (nome, tatica, descricao) da tecnica, ou None se desconhecida.
    Nunca levanta excecao: um id novo apenas nao ganha legenda.
    """
    if not technique_id:
        return None
    return TECHNIQUES.get(technique_id)


def technique_url(technique_id):
    """
    Monta a URL da tecnica no site do MITRE. Sub-tecnicas usam barra:
    T1053.003 -> https://attack.mitre.org/techniques/T1053/003/
    """
    if not technique_id:
        return ""
    return MITRE_URL + technique_id.replace(".", "/") + "/"


def used_techniques(findings):
    """
    Extrai as tecnicas presentes numa lista de achados (dicts serializados),
    ordenadas por identificador, para montar a legenda daquela captura.
    """
    ids = set()
    for finding in findings or []:
        tech = finding.get("technique") if isinstance(finding, dict) else None
        if tech:
            ids.add(tech)
    return sorted(ids)
