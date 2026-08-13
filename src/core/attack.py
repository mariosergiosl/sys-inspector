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
#
# NOME e TATICA ficam nos termos oficiais do MITRE (em ingles): sao a taxonomia,
# e traduzi-los quebraria o cruzamento com o catalogo publico e com outras
# ferramentas. A DESCRICAO, que e a explicacao em linguagem simples para quem le
# o laudo, fica em PORTUGUES SEM ACENTO (regra de codigo US-ASCII do projeto).
TECHNIQUES = {
    "T1014": (
        "Rootkit",
        "Defense Evasion",
        "Codigo que esconde processos, arquivos ou conexoes das ferramentas que "
        "um administrador usaria, de modo que o sistema relata errado o proprio "
        "estado."),
    "T1036": (
        "Masquerading",
        "Defense Evasion",
        "O artefato assume o nome ou o local de um software legitimo para "
        "sobreviver a um olhar apressado na lista de processos."),
    "T1053": (
        "Scheduled Task/Job",
        "Execution, Persistence, Privilege Escalation",
        "Um mecanismo de agendamento relanca o payload sozinho, o que transforma "
        "uma execucao pontual em algo que volta."),
    "T1222.002": (
        "File and Directory Permissions Modification: Linux",
        "Defense Evasion",
        "Mudar atributos do arquivo, como o flag imutavel, faz o artefato "
        "resistir a remocao e a inspecao; e tecnica comum de anti-forense e "
        "anti-remocao sobre o proprio arquivo."),
    "T1055": (
        "Process Injection",
        "Defense Evasion, Privilege Escalation",
        "Codigo do atacante roda DENTRO de um processo legitimo, herdando a "
        "identidade e os privilegios dele e sem deixar um processo separado para "
        "notar."),
    "T1071": (
        "Application Layer Protocol",
        "Command and Control",
        "O trafego de comando e controle se esconde dentro de um protocolo comum, "
        "entao a conexao parece uso normal de aplicacao."),
    "T1078": (
        "Valid Accounts",
        "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "Usa credenciais legitimas em vez de malware, e por isso a atividade "
        "passa por toda checagem que pergunta se o usuario tem permissao."),
    "T1037": (
        "Boot or Logon Initialization Scripts",
        "Persistence, Privilege Escalation",
        "Scripts executados no boot ou no logon rodam o codigo do atacante "
        "automaticamente toda vez que o sistema sobe ou um usuario entra."),
    "T1053.003": (
        "Scheduled Task/Job: Cron",
        "Execution, Persistence, Privilege Escalation",
        "Uma entrada de cron relanca o payload do atacante em horario marcado, "
        "restaurando o acesso mesmo depois de o processo ser morto."),
    "T1098.004": (
        "Account Manipulation: SSH Authorized Keys",
        "Persistence",
        "Adicionar uma chave publica ao authorized_keys da acesso remoto "
        "silencioso e sem senha, que sobrevive a troca de senha."),
    "T1543.002": (
        "Create or Modify System Process: Systemd Service",
        "Persistence, Privilege Escalation",
        "Uma unit do systemd sobe o payload no boot, em geral como root, e pode "
        "reinicia-lo sozinho quando ele morre."),
    "T1547": (
        "Boot or Logon Autostart Execution",
        "Persistence, Privilege Escalation",
        "Mecanismo generico de autostart que roda o codigo do atacante como "
        "parte da inicializacao do sistema ou do usuario."),
    "T1547.006": (
        "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
        "Persistence, Privilege Escalation",
        "Um modulo de kernel malicioso carregado no boot da a forma mais "
        "privilegiada de persistencia e pode esconder outros artefatos."),
    "T1556.003": (
        "Modify Authentication Process: Pluggable Authentication Modules",
        "Credential Access, Defense Evasion, Persistence",
        "Uma pilha PAM adulterada pode capturar credenciais no login ou aceitar "
        "uma senha de backdoor."),
    "T1574.006": (
        "Hijack Execution Flow: Dynamic Linker Hijacking",
        "Persistence, Privilege Escalation, Defense Evasion",
        "Precarregar uma biblioteca pelo ld.so.preload injeta codigo do atacante "
        "em todo processo dinamicamente ligado, o classico rootkit de userland."),
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
