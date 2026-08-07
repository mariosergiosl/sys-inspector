# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/snapshot_diff.py
# DESCRIPTION: Comparacao entre duas capturas do mesmo host.
#
# WHY:         Uma captura isolada responde "como o host esta". A investigacao
#              quase sempre pergunta outra coisa: "o que MUDOU desde ontem?".
#              Num host com centenas de processos, essa diferenca e invisivel a
#              olho nu, e e exatamente onde mora o comprometimento: o processo
#              que apareceu, o achado que surgiu, a persistencia plantada entre
#              uma captura e a seguinte.
#
# IDENTITY:    PID nao identifica processo entre capturas: o kernel reaproveita
#              numeros, e um PID repetido pode ser outro programa. A identidade
#              usada aqui combina PID, comando e horario de inicio, de modo que
#              reaproveitamento apareca como um processo que saiu e outro que
#              entrou, que e a leitura correta.
#
# COST:        Roda no SERVIDOR, sobre dados ja decifrados. O laudo passa de
#              10MB; calcular diferenca no navegador do analista nao e viavel.
#
# NOTES:       Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.92.0
# ==============================================================================

import logging

LOG = logging.getLogger("Diff")

# Campos cuja mudanca em um processo que permaneceu vivo tem valor para a
# investigacao. Nao se compara uso de CPU ou memoria: oscilam por natureza e
# afogariam o que importa.
CAMPOS_VIGIADOS = ("exe_path", "uid", "ppid", "cmdline")


def _identidade(proc):
    """
    Chave estavel de um processo entre duas capturas.

    Inclui o horario de inicio justamente para que o reaproveitamento de PID
    nao passe por continuidade do mesmo processo.
    """
    return (proc.get("pid"),
            proc.get("name") or "",
            proc.get("start_time") or 0)


def _resumo(proc):
    """Versao enxuta de um processo, suficiente para o painel de diferencas."""
    return {"pid": proc.get("pid"),
            "ppid": proc.get("ppid"),
            "name": proc.get("name") or "",
            "cmdline": proc.get("cmdline") or "",
            "uid": proc.get("uid"),
            "exe_path": proc.get("exe_path") or "",
            "alert_score": proc.get("alert_score") or 0}


def _mapear_processos(payload):
    processos = (payload or {}).get("processes") or {}
    mapa = {}
    for proc in processos.values():
        if isinstance(proc, dict):
            mapa[_identidade(proc)] = proc
    return mapa


def _mapear_findings(payload):
    """
    Indexa achados pela impressao digital.

    E o campo pensado para ser estavel entre capturas; usar o texto da descricao
    faria qualquer reformulacao parecer um achado novo.
    """
    mapa = {}
    for f in (payload or {}).get("findings") or []:
        if isinstance(f, dict):
            chave = f.get("fingerprint") or "%s|%s" % (f.get("source"),
                                                       f.get("title"))
            mapa[chave] = f
    return mapa


def diff_snapshots(anterior, atual):
    """
    Compara duas capturas ja decifradas e devolve o que mudou.

    PARAMETER anterior: payload da captura mais antiga.
    PARAMETER atual: payload da captura mais recente.

    Retorna um dicionario com processos que apareceram, sumiram ou foram
    alterados, achados novos e resolvidos, e um resumo contavel.
    """
    antes = _mapear_processos(anterior)
    depois = _mapear_processos(atual)

    surgiram = [_resumo(depois[k]) for k in depois if k not in antes]
    sumiram = [_resumo(antes[k]) for k in antes if k not in depois]

    alterados = []
    for chave in depois:
        if chave not in antes:
            continue
        mudancas = {}
        for campo in CAMPOS_VIGIADOS:
            velho = antes[chave].get(campo)
            novo = depois[chave].get(campo)
            if velho != novo:
                mudancas[campo] = {"antes": velho, "depois": novo}
        if mudancas:
            item = _resumo(depois[chave])
            item["changes"] = mudancas
            alterados.append(item)

    f_antes = _mapear_findings(anterior)
    f_depois = _mapear_findings(atual)

    novos = [f_depois[k] for k in f_depois if k not in f_antes]
    # Um achado que deixou de aparecer nao e necessariamente um problema
    # resolvido: pode ter sido apagado para encobrir rastro. Por isso e
    # reportado como "sumiu", nao como "corrigido".
    sumidos = [f_antes[k] for k in f_antes if k not in f_depois]

    surgiram.sort(key=lambda p: (-(p.get("alert_score") or 0), p.get("pid") or 0))
    sumiram.sort(key=lambda p: (-(p.get("alert_score") or 0), p.get("pid") or 0))

    return {
        "processes": {"appeared": surgiram,
                      "disappeared": sumiram,
                      "changed": alterados},
        "findings": {"new": novos, "gone": sumidos},
        "summary": {"appeared": len(surgiram),
                    "disappeared": len(sumiram),
                    "changed": len(alterados),
                    "findings_new": len(novos),
                    "findings_gone": len(sumidos),
                    "total_before": len(antes),
                    "total_after": len(depois)},
    }


def has_changes(resultado):
    """Diz se houve qualquer diferenca, para o painel nao abrir uma tela vazia."""
    resumo = (resultado or {}).get("summary") or {}
    return any(resumo.get(k) for k in ("appeared", "disappeared", "changed",
                                       "findings_new", "findings_gone"))
