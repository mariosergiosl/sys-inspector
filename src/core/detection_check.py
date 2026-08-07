# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/detection_check.py
# DESCRIPTION: Afere o termometro: compara o que o cenario GEROU com o que a
#              captura ENXERGOU.
#
# WHY:         O chaos_maker e o instrumento com que se mede se a deteccao
#              funciona. Um instrumento que nunca e aferido nao mede nada: se um
#              artefato deixa de ser detectado, o resultado continua parecendo
#              normal, e a conclusao errada e indistinguivel da certa.
#
#              A conferencia precisa comparar contra a REALIDADE do host, e nao
#              contra o que o script diz ter feito. Um modulo do cenario pode
#              pular por falta de ferramenta (gcc, podman) e isso e legitimo; o
#              que nao pode e um artefato existir no host e a captura nao ve-lo.
#              Sao situacoes diferentes e o relatorio as separa, porque tratar
#              as duas como falha esconderia a unica que importa.
#
# NOTES:       Compativel com Python 3.6. So leitura.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.92.0
# ==============================================================================

import logging

LOG = logging.getLogger("DetectionCheck")

# Artefatos que o cenario cria, com o rotulo que a captura deveria atribuir a
# cada um. O rotulo vazio significa que basta o processo ser visto: nem todo
# artefato existe para disparar um sinal especifico, alguns existem para gerar
# carga ou ruido.
ARTEFATOS = (
    ("artifact_net.py", "", "trafego TCP/UDP/DNS"),
    ("artifact_fw.py", "", "conexoes bloqueadas por firewall"),
    ("artifact_io.py", "", "carga de disco"),
    ("artifact_unsafe.py", "UNSAFE", "biblioteca carregada de caminho gravavel"),
    ("artifact_zombie.py", "ZOMBIE", "processo zumbi"),
    ("artifact_fano.py", "", "simulacao de fanotify"),
    ("nice_test_low", "UNSAFE", "binario executado de caminho gravavel"),
    ("deleted_sleep", "DELETED", "binario apagado com o processo vivo"),
    ("kryptominer", "MINER", "assinatura de mineracao"),
    ("fake_edr", "EDR/AV", "processo que se apresenta como seguranca"),
    ("victim_loader", "", "processo congelado pelo falso EDR"),
)

# Modulos que dependem de ferramenta externa. Ausente a ferramenta, o cenario
# pula o modulo e a ausencia do artefato NAO e falha de deteccao.
DEPENDENCIAS = {
    "artifact_unsafe.py": "gcc",
    "fake_edr": "gcc",
    "victim_loader": "gcc",
}

# Estados possiveis de cada artefato na conferencia.
OK = "ok"                    # existe no host e a captura viu
NAO_GERADO = "nao_gerado"    # nem o host tem: modulo pulado, nao e falha
NAO_VISTO = "nao_visto"      # existe no host e a captura NAO viu: FALHA
SEM_ROTULO = "sem_rotulo"    # a captura viu, mas nao atribuiu o sinal esperado


def available_tools(candidatas=None):
    """
    Quais ferramentas exigidas pelo cenario existem neste host.

    E o que permite dizer se um artefato faltou porque o modulo nao pode rodar
    ou porque simplesmente nao estava em execucao. Sem isso o relatorio atribui
    a ausencia a uma causa que pode nao ser a verdadeira.
    """
    import subprocess
    presentes = set()
    for ferramenta in (candidatas or set(DEPENDENCIAS.values())):
        try:
            subprocess.check_output(["sh", "-c", "command -v %s" % ferramenta],
                                    stderr=subprocess.DEVNULL)
            presentes.add(ferramenta)
        except Exception:
            continue
    return presentes


def check_detection(processos_do_host, arvore_capturada, ferramentas=None):
    """
    Compara a realidade do host com o que a captura registrou.

    PARAMETER processos_do_host: texto com a listagem de processos do sistema
                                 (a saida de `ps -eo pid,args`), usada como
                                 verdade de referencia.
    PARAMETER arvore_capturada: dict pid -> dados do processo, como a captura
                                produziu.
    PARAMETER ferramentas: conjunto de ferramentas presentes no host. Sem ele, a
                           ausencia de um artefato compilado e atribuida a falta
                           da ferramenta mesmo quando ela existe, o que aponta a
                           causa errada.

    Retorna a lista de resultados por artefato e um resumo. Falha e apenas
    NAO_VISTO e SEM_ROTULO: sao os casos em que o host tem o artefato e a
    ferramenta nao o representa corretamente.
    """
    resultados = []

    for nome, rotulo_esperado, descricao in ARTEFATOS:
        no_host = nome in (processos_do_host or "")

        visto = None
        for dados in (arvore_capturada or {}).values():
            if isinstance(dados, dict) and nome in (dados.get("cmd") or ""):
                visto = dados
                break

        if not no_host:
            estado = NAO_GERADO
        elif visto is None:
            estado = NAO_VISTO
        elif rotulo_esperado and rotulo_esperado not in (
                visto.get("context_tags") or []):
            estado = SEM_ROTULO
        else:
            estado = OK

        resultados.append({
            "artifact": nome,
            "description": descricao,
            "expected_label": rotulo_esperado,
            "requires": DEPENDENCIAS.get(nome, ""),
            "tool_missing": bool(DEPENDENCIAS.get(nome)
                                 and ferramentas is not None
                                 and DEPENDENCIAS[nome] not in ferramentas),
            "state": estado,
            "score": (visto or {}).get("anomaly_score", 0),
            "labels": list((visto or {}).get("context_tags") or []),
        })

    falhas = [r for r in resultados if r["state"] in (NAO_VISTO, SEM_ROTULO)]
    return {
        "results": resultados,
        "failures": falhas,
        "summary": {
            "ok": sum(1 for r in resultados if r["state"] == OK),
            "skipped": sum(1 for r in resultados if r["state"] == NAO_GERADO),
            "missed": sum(1 for r in resultados if r["state"] == NAO_VISTO),
            "unlabelled": sum(1 for r in resultados if r["state"] == SEM_ROTULO),
            "total": len(resultados),
        },
    }


def format_report(conferencia):
    """Relatorio em texto, para rodar por ssh sem depender de interface."""
    linhas = ["%-22s %-12s %-10s %s" % ("ARTEFATO", "ESTADO", "SINAL", "OBSERVACAO")]
    simbolos = {OK: "ok", NAO_GERADO: "nao gerado", NAO_VISTO: "NAO VISTO",
                SEM_ROTULO: "SEM SINAL"}

    for r in conferencia["results"]:
        observacao = r["description"]
        if r["state"] == NAO_GERADO and r["tool_missing"]:
            observacao = "modulo pulado: este host nao tem %s" % r["requires"]
        elif r["state"] == NAO_GERADO and r["requires"]:
            observacao = ("nao estava em execucao na janela da captura "
                          "(%s existe neste host)" % r["requires"])
        elif r["state"] == NAO_GERADO:
            observacao = "nao estava em execucao na janela da captura"
        elif r["state"] == SEM_ROTULO:
            observacao = ("esperava %s, veio %s"
                          % (r["expected_label"], r["labels"] or "nada"))
        linhas.append("%-22s %-12s %-10s %s"
                      % (r["artifact"], simbolos[r["state"]],
                         r["expected_label"] or "-", observacao))

    s = conferencia["summary"]
    linhas.append("")
    linhas.append("%d detectados, %d pulados por falta de ferramenta, "
                  "%d NAO VISTOS, %d sem o sinal esperado (de %d)"
                  % (s["ok"], s["skipped"], s["missed"], s["unlabelled"],
                     s["total"]))
    if not conferencia["failures"]:
        linhas.append("Termometro aferido: nada que o host tem passou batido.")
    return "\n".join(linhas)
