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
# ==============================================================================

import logging

LOG = logging.getLogger("Diff")

# Campos cuja mudanca em um processo que permaneceu vivo tem valor para a
# investigacao. Nao se compara uso de CPU ou memoria: oscilam por natureza e
# afogariam o que importa.
CAMPOS_VIGIADOS = ("exe_path", "uid", "ppid", "cmd")


def _identidade(proc):
    """
    Chave estavel de um processo entre duas capturas.

    Inclui o horario de inicio justamente para que o reaproveitamento de PID
    nao passe por continuidade do mesmo processo.
    """
    return (proc.get("pid"),
            proc.get("cmd") or "",
            proc.get("start_time") or 0)


def _resumo(proc):
    """
    Versao enxuta de um processo, suficiente para o painel de diferencas.

    Os nomes dos campos seguem ProcessNode: a linha de comando e `cmd` e o risco
    e `anomaly_score`. Ler campos que nao existem devolve vazio em silencio, e
    foi exatamente o que aconteceu na primeira versao desta tela: a comparacao
    funcionava, mas mostrava so numeros de PID, sem dizer de que processo se
    tratava.
    """
    return {"pid": proc.get("pid"),
            "ppid": proc.get("ppid"),
            "cmd": proc.get("cmd") or "",
            "user": proc.get("username") or "",
            "uid": proc.get("uid"),
            "exe_path": proc.get("exe_path") or "",
            "duration": proc.get("duration_str") or "",
            "started": proc.get("start_ts_abs") or "",
            "reasons": (proc.get("detection_reasons") or [])[:6],
            "connections": list(proc.get("connections") or [])[:5],
            "alert_score": proc.get("anomaly_score") or 0}


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


# ------------------------------------------------------------------------------
# LEITURA DO QUE MUDOU
# ------------------------------------------------------------------------------
# Uma lista de PIDs nao e analise. O operador precisa saber, sem abrir o laudo,
# se algo do que mudou merece atencao e POR QUE. Os rotulos abaixo respondem a
# perguntas concretas, e cada um so aparece quando ha evidencia que o sustente.
ROTULO_CRITICO = ("critico", "&#128308;",
                  "Risco alto o bastante para ser examinado primeiro")
ROTULO_REDE = ("rede", "&#127760;",
               "Tinha conexao de rede ativa no momento da captura")
ROTULO_CAMINHO = ("caminho suspeito", "&#9888;",
                  "Executa a partir de diretorio gravavel por qualquer um")
ROTULO_ROOT = ("root", "&#128081;",
               "Rodava como root: o alcance de um comprometimento e total")
ROTULO_EFEMERO = ("efemero", "&#9201;",
                  "Viveu menos que o intervalo entre capturas: so foi visto "
                  "porque a captura estava aberta")
ROTULO_ORFAO = ("reparentado", "&#128128;",
                "Pai e o init: perdeu o processo que o criou, o que apaga a "
                "origem")

LIMIAR_CRITICO = 70


def classify(proc):
    """
    Devolve os rotulos que se aplicam a um processo que apareceu ou sumiu.

    Sao afirmacoes verificaveis sobre a evidencia coletada, nao conclusoes: cada
    rotulo diz o que foi observado e deixa o julgamento com o analista.
    """
    rotulos = []

    if (proc.get("alert_score") or 0) >= LIMIAR_CRITICO:
        rotulos.append(ROTULO_CRITICO)

    if proc.get("connections"):
        rotulos.append(ROTULO_REDE)

    motivos = " ".join(proc.get("reasons") or []).lower()
    if "unsafe" in motivos or "/tmp" in motivos or "/dev/shm" in motivos:
        rotulos.append(ROTULO_CAMINHO)

    if proc.get("uid") == 0:
        rotulos.append(ROTULO_ROOT)

    # Um processo cujo pai e o init nasceu de alguem que ja morreu. Numa
    # investigacao isso importa: a cadeia que explicaria a origem se perdeu.
    if proc.get("ppid") == 1 and proc.get("pid") != 1:
        rotulos.append(ROTULO_ORFAO)

    return rotulos


def summarize_risk(itens):
    """Conta quantos dos processos listados merecem atencao imediata."""
    return sum(1 for p in itens
               if (p.get("alert_score") or 0) >= LIMIAR_CRITICO)


def build_timeline(capturas, minimo=2):
    """
    Quantas vezes cada linha de comando apareceu ao longo das capturas.

    Responde a pergunta que uma captura isolada nao alcanca: "isso rodou uma vez
    ou roda sempre?". Um artefato que reaparece a cada poucos minutos tem
    persistencia ativa; um que apareceu uma unica vez pode ter sido acao manual.
    A diferenca muda a resposta ao incidente.

    PARAMETER capturas: lista de payloads decifrados, do mais antigo ao mais novo.
    PARAMETER minimo: ignora o que apareceu menos vezes que isto, para a tela nao
                      virar um inventario do sistema inteiro.
    """
    ocorrencias = {}
    for indice, payload in enumerate(capturas):
        vistos = set()
        for proc in ((payload or {}).get("processes") or {}).values():
            if not isinstance(proc, dict):
                continue
            cmd = (proc.get("cmd") or "").strip()
            if not cmd or cmd in vistos:
                continue
            vistos.add(cmd)
            registro = ocorrencias.setdefault(
                cmd, {"cmd": cmd, "count": 0, "captures": [],
                      "max_score": 0, "pids": []})
            registro["count"] += 1
            registro["captures"].append(indice)
            registro["max_score"] = max(registro["max_score"],
                                        proc.get("anomaly_score") or 0)
            if len(registro["pids"]) < 12:
                registro["pids"].append(proc.get("pid"))

    resultado = [r for r in ocorrencias.values() if r["count"] >= minimo]
    # O que reaparece muito e com risco alto vem primeiro: e a combinacao que
    # descreve persistencia ativa.
    resultado.sort(key=lambda r: (-r["max_score"], -r["count"]))
    return resultado


def has_changes(resultado):
    """Diz se houve qualquer diferenca, para o painel nao abrir uma tela vazia."""
    resumo = (resultado or {}).get("summary") or {}
    return any(resumo.get(k) for k in ("appeared", "disappeared", "changed",
                                       "findings_new", "findings_gone"))
