# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/collectors/persistence.py
# DESCRIPTION: Enumerates Linux persistence mechanisms, the first thing a
#              forensic examiner checks after a suspected compromise: how would
#              the intruder survive a reboot?
#
#              Covered: systemd units, cron/at, rc.local and shell rc files,
#              ld.so.preload, kernel module autoload, udev rules, PAM modules
#              and per-user authorized_keys.
#
#              Emits normalized Finding objects (src/core/findings.py) with the
#              raw evidence attached, so the analyst can verify the reasoning.
#
# DESIGN:      A healthy system has hundreds of units and cron entries, so a
#              plain listing would be noise. Baseline items are reported as a
#              single Info inventory finding; severity is raised only for the
#              indicators that actually matter (unsafe paths, world-writable
#              files, hidden names, recent modification, ld.so.preload).
#
# NOTES:       Read-only. Compatible with Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import re
import glob
import time
import stat
import logging

from src.core.findings import (Finding, SEV_INFO, SEV_LOW, SEV_MEDIUM,
                               SEV_HIGH, SEV_CRITICAL, SRC_PERSISTENCE)
from src.collectors.integrity import describe_provenance

LOG = logging.getLogger("Persistence")

# Peso das severidades, para comparar sem depender da ordem de importacao.
SEVERITY_RANK = {SEV_INFO: 0, SEV_LOW: 1, SEV_MEDIUM: 2,
                 SEV_HIGH: 3, SEV_CRITICAL: 4}

# Diretorios de onde um binario legitimo de sistema normalmente NAO e executado.
# Persistencia apontando para ca e um indicador forte de comprometimento.
UNSAFE_PREFIXES = ("/tmp", "/dev/shm", "/var/tmp", "/run/shm", "/home")

# Janela para considerar uma alteracao "recente" (24h), sinal de atividade nova.
RECENT_WINDOW_SEC = 24 * 3600

# Limite de leitura de arquivo de configuracao, para nao inflar o payload.
MAX_READ_BYTES = 8192


# ------------------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------------------
def _read_text(path, limit=MAX_READ_BYTES):
    """Le um arquivo de texto de forma segura e truncada; '' em caso de erro."""
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read(limit)
    except Exception:
        return ""


def _stat_info(path):
    """
    Coleta metadados forenses do caminho: MAC times, dono e permissoes.
    Retorna dict vazio se o caminho for inacessivel.

    A permissao e avaliada no ALVO (os.stat), nao no link: em Linux todo
    symlink tem modo 0777, entao usar o lstat marcaria como "gravavel por
    todos" cada unit habilitada em /etc/systemd/system (que sao symlinks para
    /usr/lib), gerando falso-positivo em massa. Os MAC times vem do lstat, que
    descreve o proprio item enumerado.
    """
    try:
        lst = os.lstat(path)
    except Exception:
        return {}

    is_link = stat.S_ISLNK(lst.st_mode)
    perm_st = lst
    if is_link:
        try:
            perm_st = os.stat(path)  # segue o link para avaliar a permissao real
        except Exception:
            perm_st = None  # link pendente: sem alvo para avaliar

    return {
        "path": path,
        "size": lst.st_size,
        "uid": lst.st_uid,
        "gid": lst.st_gid,
        "mode": oct(stat.S_IMODE(perm_st.st_mode)) if perm_st else "dangling",
        "mtime": lst.st_mtime,
        "ctime": lst.st_ctime,
        "atime": lst.st_atime,
        "world_writable": bool(perm_st.st_mode & stat.S_IWOTH) if perm_st else False,
        "is_symlink": is_link,
        "link_target": os.path.realpath(path) if is_link else None,
    }


def _is_recent(meta):
    """Verdadeiro se o arquivo foi modificado dentro da janela recente."""
    mtime = meta.get("mtime")
    if not mtime:
        return False
    return (time.time() - mtime) < RECENT_WINDOW_SEC


def _has_unsafe_path(text):
    """
    Procura referencia a caminhos de execucao suspeitos dentro de um texto de
    configuracao. Retorna o caminho encontrado ou None.

    O lookbehind garante que o prefixo esteja numa fronteira de caminho: sem
    ele, "/tmp" casaria DENTRO de "/var/tmp/backdoor" e o achado reportaria um
    caminho inexistente ("/tmp/backdoor"). A busca comeca no proprio prefixo
    para devolver so o caminho, sem o texto que o antecede (ex.: "ExecStart=").
    """
    if not text:
        return None
    for prefix in UNSAFE_PREFIXES:
        pattern = r"(?<![\w/.-])%s/[^\s\"';|)]*" % re.escape(prefix)
        match = re.search(pattern, text)
        if match:
            return match.group(0)
    return None


def _apply_provenance(finding, path):
    """
    Ajusta o achado conforme a proveniencia do arquivo e anexa a evidencia.

    Um mecanismo de persistencia que PERTENCE a um pacote e software de sistema
    esperado, e nao deve gritar como comprometimento; um que nao pertence a
    pacote nenhum foi colocado ali por alguem, e esse e o sinal que interessa.
    Um arquivo empacotado que nao confere mais com o pacote de origem e o pior
    caso: sistema adulterado.

    Devolve o proprio achado, ja ajustado.
    """
    prov = describe_provenance(path)
    finding.evidence["provenance"] = prov

    if prov.get("packaged"):
        if prov.get("verified") is False:
            # Adulteracao de arquivo de sistema: eleva ao maximo.
            finding.severity = SEV_CRITICAL
            finding.description += (
                " This file belongs to package %s but no longer matches what "
                "the package installed (%s), which indicates tampering."
                % (prov.get("package"), ", ".join(prov.get("issues") or [])))
        else:
            # Pertence a pacote e integro: comportamento esperado do sistema.
            if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK[SEV_LOW]:
                finding.severity = SEV_LOW
            finding.description += (
                " This artifact belongs to the installed package %s and matches "
                "what the package shipped, so it is expected system software."
                % prov.get("package"))
    elif prov.get("package") is None and finding.severity != SEV_INFO:
        finding.description += (
            " This artifact does not belong to any installed package, so it was "
            "placed on the system outside package management.")

    return finding


def _escalate(meta, base=SEV_LOW):
    """
    Ajusta a severidade de um item de persistencia conforme os indicadores
    forenses presentes nos metadados (gravacao por qualquer usuario, nome
    oculto, alteracao recente).
    """
    severity = base
    reasons = []
    if meta.get("world_writable"):
        severity = SEV_HIGH
        reasons.append("world-writable")
    name = os.path.basename(meta.get("path", ""))
    if name.startswith("."):
        severity = SEV_HIGH
        reasons.append("hidden name")
    if _is_recent(meta):
        if severity == SEV_LOW:
            severity = SEV_MEDIUM
        reasons.append("modified in the last 24h")
    return severity, reasons


# ------------------------------------------------------------------------------
# COLLECTORS (um por mecanismo de persistencia)
# ------------------------------------------------------------------------------
def _collect_ld_preload():
    """
    /etc/ld.so.preload force o carregamento de uma biblioteca em TODO processo
    dinamicamente ligado. E raro em sistemas legitimos e e a assinatura classica
    de rootkits de userland, por isso qualquer conteudo aqui e tratado como grave.
    """
    findings = []
    path = "/etc/ld.so.preload"
    if not os.path.exists(path):
        return findings

    meta = _stat_info(path)
    content = _read_text(path).strip()
    findings.append(Finding(
        title="ld.so.preload is present",
        severity=SEV_CRITICAL if content else SEV_HIGH,
        source=SRC_PERSISTENCE,
        category="persistence",
        target=path,
        description=("/etc/ld.so.preload forces a shared library into every "
                     "dynamically linked process. It is uncommon on clean "
                     "systems and is a classic userland rootkit technique."),
        evidence={"content": content, "meta": meta},
        technique="T1574.006",
        recommendation=("Verify each listed library against the owning package; "
                        "an unpackaged library here indicates compromise."),
    ))
    return findings


def _collect_systemd_units():
    """
    Enumera units systemd fora dos diretorios de pacote e destaca as que
    apontam para caminhos inseguros ou foram alteradas recentemente.
    """
    findings = []
    unit_dirs = ["/etc/systemd/system", "/run/systemd/system",
                 "/usr/local/lib/systemd/system"]
    total = 0

    for directory in unit_dirs:
        if not os.path.isdir(directory):
            continue
        for path in glob.glob(os.path.join(directory, "*.service")):
            meta = _stat_info(path)
            target_link = meta.get("link_target") or ""

            # Unit MASCARADA (systemctl mask -> symlink para /dev/null) e um
            # servico DESATIVADO, o oposto de um risco de persistencia. Como
            # /dev/null tem modo 0666, sem este desvio ela seria acusada de
            # "world-writable". Nao entra no inventario nem gera achado.
            if meta.get("is_symlink") and target_link == "/dev/null":
                continue

            total += 1
            content = _read_text(path)
            unsafe = _has_unsafe_path(content)
            severity, reasons = _escalate(meta, base=SEV_INFO)

            # Unit que e symlink para arquivo de pacote (/usr/lib, /lib) apenas
            # indica servico HABILITADO, nao uma definicao local; nao escala por
            # atributos. Um caminho inseguro no conteudo ainda importa.
            if meta.get("is_symlink") and target_link.startswith(("/usr/lib", "/lib")):
                severity, reasons = SEV_INFO, []

            if unsafe:
                finding = Finding(
                    title="systemd unit executes from an unsafe path",
                    severity=SEV_CRITICAL,
                    source=SRC_PERSISTENCE,
                    category="persistence",
                    target=path,
                    description=("A systemd service runs a binary from a "
                                 "world-writable or user-controlled directory, "
                                 "which is how malware commonly survives reboot."),
                    evidence={"reference": unsafe, "content": content, "meta": meta},
                    technique="T1543.002",
                    recommendation="Inspect the referenced binary and the unit origin.",
                )
                findings.append(_apply_provenance(finding, path))
            elif severity in (SEV_MEDIUM, SEV_HIGH):
                findings.append(Finding(
                    title="systemd unit with suspicious attributes",
                    severity=severity,
                    source=SRC_PERSISTENCE,
                    category="persistence",
                    target=path,
                    description="Local systemd unit flagged by: %s." % ", ".join(reasons),
                    evidence={"content": content, "meta": meta},
                    technique="T1543.002",
                ))

    if total:
        findings.append(Finding(
            title="Local systemd units inventoried",
            severity=SEV_INFO,
            source=SRC_PERSISTENCE,
            category="persistence",
            target=", ".join(unit_dirs),
            description="Baseline count of systemd units outside package directories.",
            evidence={"count": total},
        ))
    return findings


def _collect_cron():
    """
    Enumera tarefas agendadas (crontabs de sistema, cron.d, diretorios
    periodicos e crontabs de usuario) procurando execucao de caminhos inseguros.
    """
    findings = []
    targets = ["/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
               "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
               "/var/spool/cron/crontabs", "/etc/at.allow", "/var/spool/atjobs"]
    total = 0

    for target in targets:
        if os.path.isfile(target):
            paths = [target]
        elif os.path.isdir(target):
            paths = [os.path.join(target, n) for n in sorted(os.listdir(target))]
        else:
            continue

        for path in paths:
            if not os.path.isfile(path):
                continue
            total += 1
            meta = _stat_info(path)
            content = _read_text(path)
            unsafe = _has_unsafe_path(content)
            severity, reasons = _escalate(meta, base=SEV_INFO)

            if unsafe:
                finding = Finding(
                    title="Scheduled task runs from an unsafe path",
                    severity=SEV_CRITICAL,
                    source=SRC_PERSISTENCE,
                    category="persistence",
                    target=path,
                    description=("A cron/at entry executes a binary from a "
                                 "user-writable directory, a common way to "
                                 "re-establish access on a schedule."),
                    evidence={"reference": unsafe, "content": content, "meta": meta},
                    technique="T1053.003",
                    recommendation="Verify the scheduled command and who installed it.",
                )
                findings.append(_apply_provenance(finding, path))
            elif severity in (SEV_MEDIUM, SEV_HIGH):
                findings.append(Finding(
                    title="Scheduled task with suspicious attributes",
                    severity=severity,
                    source=SRC_PERSISTENCE,
                    category="persistence",
                    target=path,
                    description="Cron/at entry flagged by: %s." % ", ".join(reasons),
                    evidence={"content": content, "meta": meta},
                    technique="T1053.003",
                ))

    if total:
        findings.append(Finding(
            title="Scheduled tasks inventoried",
            severity=SEV_INFO,
            source=SRC_PERSISTENCE,
            category="persistence",
            target="cron/at",
            description="Baseline count of cron/at entries found on the host.",
            evidence={"count": total},
        ))
    return findings


def _collect_startup_scripts():
    """
    Verifica rc.local e os scripts de inicializacao de shell, que executam a
    cada boot ou a cada login e sao pontos discretos de persistencia.
    """
    findings = []
    candidates = ["/etc/rc.local", "/etc/rc.d/rc.local", "/etc/bash.bashrc",
                  "/etc/profile", "/etc/environment"]
    candidates.extend(sorted(glob.glob("/etc/profile.d/*.sh")))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        meta = _stat_info(path)
        content = _read_text(path)
        unsafe = _has_unsafe_path(content)
        severity, reasons = _escalate(meta, base=SEV_INFO)

        if unsafe:
            findings.append(Finding(
                title="Startup script references an unsafe path",
                severity=SEV_HIGH,
                source=SRC_PERSISTENCE,
                category="persistence",
                target=path,
                description=("A boot or login script executes content from a "
                             "user-writable directory."),
                evidence={"reference": unsafe, "content": content, "meta": meta},
                technique="T1037",
            ))
        elif severity in (SEV_MEDIUM, SEV_HIGH):
            findings.append(Finding(
                title="Startup script recently modified",
                severity=severity,
                source=SRC_PERSISTENCE,
                category="persistence",
                target=path,
                description="Startup script flagged by: %s." % ", ".join(reasons),
                evidence={"meta": meta},
                technique="T1037",
            ))
    return findings


def _collect_kernel_modules():
    """
    Verifica o autoload de modulos de kernel. Um modulo malicioso carregado no
    boot da ao intruso o nivel mais privilegiado de persistencia.
    """
    findings = []
    conf_paths = []
    for directory in ("/etc/modules-load.d", "/etc/modprobe.d"):
        if os.path.isdir(directory):
            conf_paths.extend(sorted(glob.glob(os.path.join(directory, "*"))))
    if os.path.isfile("/etc/modules"):
        conf_paths.append("/etc/modules")

    for path in conf_paths:
        if not os.path.isfile(path):
            continue
        meta = _stat_info(path)
        severity, reasons = _escalate(meta, base=SEV_INFO)
        if severity in (SEV_MEDIUM, SEV_HIGH):
            findings.append(Finding(
                title="Kernel module autoload configuration changed",
                severity=severity,
                source=SRC_PERSISTENCE,
                category="persistence",
                target=path,
                description=("Kernel module autoload config flagged by: %s. A "
                             "malicious module loaded at boot yields kernel-level "
                             "persistence." % ", ".join(reasons)),
                evidence={"content": _read_text(path), "meta": meta},
                technique="T1547.006",
            ))
    return findings


def _collect_udev_rules():
    """
    Regras udev podem executar programas ao conectar dispositivos, servindo de
    gatilho de persistencia pouco monitorado.
    """
    findings = []
    for directory in ("/etc/udev/rules.d", "/run/udev/rules.d"):
        if not os.path.isdir(directory):
            continue
        for path in sorted(glob.glob(os.path.join(directory, "*.rules"))):
            meta = _stat_info(path)
            content = _read_text(path)
            unsafe = _has_unsafe_path(content)
            if unsafe or "RUN" in content:
                severity = SEV_HIGH if unsafe else SEV_LOW
                findings.append(Finding(
                    title="udev rule executes a program",
                    severity=severity,
                    source=SRC_PERSISTENCE,
                    category="persistence",
                    target=path,
                    description=("A udev rule runs a program on device events, "
                                 "which can be abused as a persistence trigger."),
                    evidence={"reference": unsafe or "RUN directive",
                              "content": content, "meta": meta},
                    technique="T1547",
                ))
    return findings


def _collect_pam_modules():
    """
    Modulos PAM interceptam autenticacao; um modulo adulterado captura
    credenciais ou instala backdoor de acesso.
    """
    findings = []
    directory = "/etc/pam.d"
    if not os.path.isdir(directory):
        return findings

    for path in sorted(glob.glob(os.path.join(directory, "*"))):
        if not os.path.isfile(path):
            continue
        meta = _stat_info(path)
        content = _read_text(path)
        unsafe = _has_unsafe_path(content)
        severity, reasons = _escalate(meta, base=SEV_INFO)

        if unsafe:
            findings.append(Finding(
                title="PAM configuration references an unsafe path",
                severity=SEV_CRITICAL,
                source=SRC_PERSISTENCE,
                category="persistence",
                target=path,
                description=("A PAM stack loads a module from a user-writable "
                             "location, which can capture credentials or grant "
                             "unauthorized access."),
                evidence={"reference": unsafe, "content": content, "meta": meta},
                technique="T1556.003",
            ))
        elif severity in (SEV_MEDIUM, SEV_HIGH):
            findings.append(Finding(
                title="PAM configuration recently modified",
                severity=severity,
                source=SRC_PERSISTENCE,
                category="persistence",
                target=path,
                description="PAM config flagged by: %s." % ", ".join(reasons),
                evidence={"meta": meta},
                technique="T1556.003",
            ))
    return findings


def _iter_user_homes():
    """
    Percorre as contas locais de /etc/passwd, devolvendo (usuario, home, shell).
    Evita depender do modulo pwd para manter a leitura auditavel.
    """
    entries = []
    content = _read_text("/etc/passwd", limit=65536)
    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            entries.append((parts[0], parts[5], parts[6]))
    return entries


def _collect_authorized_keys():
    """
    Chaves SSH autorizadas sao a forma mais comum de acesso persistente: basta
    acrescentar uma linha ao authorized_keys da vitima.
    """
    findings = []
    for user, home, _shell in _iter_user_homes():
        if not home or not os.path.isdir(home):
            continue
        for name in ("authorized_keys", "authorized_keys2"):
            path = os.path.join(home, ".ssh", name)
            if not os.path.isfile(path):
                continue

            meta = _stat_info(path)
            content = _read_text(path)
            keys = [ln for ln in content.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")]
            if not keys:
                continue

            severity, reasons = _escalate(meta, base=SEV_INFO)
            # Comentario/identidade de cada chave ajuda a reconhecer o dono.
            comments = []
            for key in keys:
                fields = key.split()
                comments.append(fields[-1] if len(fields) >= 3 else "(no comment)")

            if severity in (SEV_MEDIUM, SEV_HIGH):
                title = "SSH authorized_keys recently modified"
                description = ("Authorized SSH keys for user '%s' flagged by: %s. "
                               "Adding a key is the most common way to keep "
                               "persistent remote access." % (user, ", ".join(reasons)))
            else:
                title = "SSH authorized keys present"
                description = ("User '%s' accepts %d SSH key(s) for remote login. "
                               "Confirm every key belongs to an authorized "
                               "operator." % (user, len(keys)))
                severity = SEV_LOW

            findings.append(Finding(
                title=title,
                severity=severity,
                source=SRC_PERSISTENCE,
                category="persistence",
                target=path,
                description=description,
                evidence={"user": user, "key_count": len(keys),
                          "key_comments": comments, "meta": meta},
                technique="T1098.004",
                recommendation="Match each key against your inventory of authorized operators.",
            ))
    return findings


# ------------------------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------------------------
def collect_persistence():
    """
    Executa todos os coletores de persistencia e devolve a lista de Findings.

    Cada coletor e isolado: uma falha (permissao, caminho ausente) e registrada
    e nao interrompe os demais, para que a captura nunca seja perdida por um
    mecanismo indisponivel no host.
    """
    collectors = (
        ("ld.so.preload", _collect_ld_preload),
        ("systemd", _collect_systemd_units),
        ("cron", _collect_cron),
        ("startup scripts", _collect_startup_scripts),
        ("kernel modules", _collect_kernel_modules),
        ("udev", _collect_udev_rules),
        ("pam", _collect_pam_modules),
        ("authorized_keys", _collect_authorized_keys),
    )

    findings = []
    for name, func in collectors:
        try:
            findings.extend(func())
        except Exception as exc:
            LOG.error("Persistence collector '%s' failed: %s", name, exc)
    return findings
