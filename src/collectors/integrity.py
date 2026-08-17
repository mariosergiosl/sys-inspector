# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/collectors/integrity.py
# DESCRIPTION: Provenance and integrity of files on disk, answering two
#              questions a forensic examiner asks about any suspicious artifact:
#              does it belong to an installed package, and has it been modified
#              since it was installed?
#
# WHY IT MATTERS:
#              A systemd unit or cron entry that belongs to a package is
#              expected system software. One that belongs to no package was put
#              there by someone, which is the real signal. And a packaged file
#              that no longer matches what the package shipped is a tampered
#              system file, one of the strongest indicators of compromise.
#
# NOTES:       Read-only. Degrades silently on systems without a package
#              manager (returns unknown), never breaking a capture.
#              Compatible with Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import shutil
import logging
import subprocess

LOG = logging.getLogger("Integrity")

# Consultar o gerenciador de pacotes custa um processo por arquivo; a captura
# repete os mesmos caminhos, entao o resultado e memorizado.
_owner_cache = {}
_verify_cache = {}

# Teto de tempo por consulta: um banco RPM danificado nao pode travar a captura.
_CMD_TIMEOUT = 10

# Codigos de atributo do rpm -V que indicam adulteracao relevante do conteudo.
# Ver rpm(8): 5=digest(md5), S=size, M=mode, U=user, G=group, T=mtime.
_VERIFY_MEANING = {
    "5": "content digest differs",
    "S": "size differs",
    "M": "permissions differ",
    "U": "owner differs",
    "G": "group differs",
    "L": "symlink target differs",
    "D": "device number differs",
    "T": "modification time differs",
}


def _run(cmd):
    """Executa um comando curto e devolve (rc, stdout). Nunca levanta."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            out, _err = proc.communicate(timeout=_CMD_TIMEOUT)
        except Exception:
            proc.kill()
            return 1, ""
        return proc.returncode, out.decode("utf-8", "replace")
    except Exception as exc:
        LOG.debug("command failed %s: %s", cmd, exc)
        return 1, ""


def has_package_manager():
    """Verdadeiro se ha um gerenciador de pacotes consultavel neste host."""
    return bool(shutil.which("rpm") or shutil.which("dpkg"))


def package_owner(path):
    """
    Devolve o pacote dono do arquivo, ou None se nao pertencer a nenhum.

    O caminho e resolvido antes da consulta: units habilitadas em
    /etc/systemd/system sao symlinks para o arquivo do pacote em
    /usr/lib/systemd/system, e perguntar pelo link responderia, erradamente,
    que ninguem e dono.
    """
    if not path:
        return None

    try:
        real = os.path.realpath(path)
    except Exception:
        real = path

    if real in _owner_cache:
        return _owner_cache[real]

    owner = None
    # Pergunta primeiro ao rpm, depois ao dpkg. Nao basta o binario existir para
    # o sistema ser daquele gerenciador: o runner Ubuntu traz o rpm com um banco
    # vazio, e consultar so ele responderia "sem dono" para um arquivo que na
    # verdade pertence a um pacote dpkg. Tentar os dois e ficar com a primeira
    # resposta positiva mantem a proveniencia correta nas duas bases.
    if shutil.which("rpm"):
        rc, out = _run(["rpm", "-qf", "--queryformat",
                        "%{NAME}-%{VERSION}-%{RELEASE}", real])
        if rc == 0 and out and "not owned" not in out:
            owner = out.strip()
    if owner is None and shutil.which("dpkg"):
        owner = _dpkg_owner(path)

    _owner_cache[real] = owner
    return owner


def _rpm_owns(path):
    """
    Verdadeiro somente se o rpm reconhece o arquivo como pertencente a um
    pacote. So o rpm sabe verificar o conteudo instalado (rpm -V); num host
    dpkg, ou num host onde o binario rpm existe mas nao gerencia o sistema,
    esta verificacao nao se aplica.
    """
    if not shutil.which("rpm"):
        return False
    rc, out = _run(["rpm", "-qf", path])
    return rc == 0 and "not owned" not in out


def _usrmerge_variant(path):
    """
    Alterna um caminho entre /bin e /usr/bin (e afins) para contornar o
    usrmerge. Nesses sistemas /bin e um link para /usr/bin, mas o banco do dpkg
    registra o caminho na forma que o pacote instalou, entao a consulta precisa
    tentar as duas grafias.
    """
    if path.startswith("/usr/"):
        return path[4:]
    if path.startswith(("/bin/", "/sbin/", "/lib/", "/lib64/")):
        return "/usr" + path
    return None


def _parse_dpkg_search(out):
    """Nome do pacote na saida de 'dpkg -S', ignorando linhas de diversion."""
    for line in out.splitlines():
        if not line or "diversion" in line or ":" not in line:
            continue
        return line.split(":", 1)[0].split(",")[0].strip()
    return None


def _dpkg_owner(path):
    """
    Dono via dpkg, resiliente a usrmerge e a symlinks de alternativa.

    O caminho consultado pode diferir do que o dpkg registrou: com usrmerge
    /bin e link para /usr/bin, e /bin/sh e um symlink de alternativa que
    resolve para o dash. Tenta o caminho original, o resolvido e as variantes
    com e sem /usr, ficando com a primeira resposta valida.
    """
    try:
        real = os.path.realpath(path)
    except Exception:
        real = path

    candidates = []
    for base in (path, real):
        if not base:
            continue
        for cand in (base, _usrmerge_variant(base)):
            if cand and cand not in candidates:
                candidates.append(cand)

    for cand in candidates:
        rc, out = _run(["dpkg", "-S", cand])
        if rc == 0:
            pkg = _parse_dpkg_search(out)
            if pkg:
                return pkg
    return None


def verify_file(path):
    """
    Confere o arquivo contra o que o pacote instalou.

    Retorna None quando nao ha como verificar (sem pacote dono ou sem
    gerenciador), lista vazia quando o arquivo esta integro, ou a lista de
    diferencas encontradas (conteudo, tamanho, permissoes, dono).

    Um arquivo de sistema que nao confere mais com o pacote de origem e um
    forte indicador de adulteracao.
    """
    if not path:
        return None

    try:
        real = os.path.realpath(path)
    except Exception:
        real = path

    if real in _verify_cache:
        return _verify_cache[real]

    result = None
    # So verifica quando o proprio rpm e dono do arquivo. Rodar rpm -Vf num
    # arquivo dpkg produz saida vazia, que seria lida como "integro" e mascararia
    # uma adulteracao num host Debian/Ubuntu. Sem dono no rpm, o resultado fica
    # None (desconhecido), que e a resposta honesta.
    if _rpm_owns(real):
        rc, out = _run(["rpm", "-Vf", real])
        if rc == 0 and not out.strip():
            result = []  # integro
        else:
            issues = []
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                attrs, fname = parts[0], parts[1].strip()
                # rpm -Vf verifica o pacote inteiro; interessa a nossa linha.
                if os.path.realpath(fname) != real:
                    continue
                for code, meaning in _VERIFY_MEANING.items():
                    if code in attrs:
                        issues.append(meaning)
            result = issues

    _verify_cache[real] = result
    return result


def describe_provenance(path):
    """
    Resume a proveniencia de um caminho para anexar como evidencia.

    Chaves: package (dono ou None), packaged (bool), verified (True/False/None)
    e issues (lista de diferencas quando adulterado).
    """
    owner = package_owner(path)
    info = {
        "package": owner,
        "packaged": bool(owner),
        "verified": None,
        "issues": [],
    }
    if owner:
        issues = verify_file(path)
        if issues is None:
            info["verified"] = None
        else:
            info["verified"] = not issues
            info["issues"] = issues
    return info


def clear_cache():
    """Limpa a memorizacao (usado em teste e entre capturas longas)."""
    _owner_cache.clear()
    _verify_cache.clear()
