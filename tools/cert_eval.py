# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tools/cert_eval.py
# DESCRIPTION: Cruza os sinais DETECTADOS (saida do certify_chaos.py) com o que o
#              host tinha COMO exercitar, e imprime um checklist de certificacao.
#
# WHY:         A pergunta e "toda capacidade que RODOU no host foi detectada?".
#              A resposta so vale se levar em conta o que o host consegue gerar:
#              cobrar container de um host sem podman, ou ld.so.preload de um sem
#              gcc, seria acusar falha onde nao ha o que detectar. Este script
#              aplica esse criterio de forma explicita e auditavel.
#
# USAGE:       echo '{"detected":{...},"gcc":true,"podman":true}' \
#                  | python3 cert_eval.py <rotulo_do_host>
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import sys
import json


def _tem_tag(det, *nomes):
    tags = set(det.get("tags") or [])
    return any(n in tags for n in nomes)


def _tem_tecnica(det, tid):
    return tid in (det.get("techniques") or [])


def avaliar(host, det, gcc, podman):
    """
    Monta o checklist. Cada item: (nome, esperado?, detectado?, observacao).

    'esperado?' embute a capacidade do host: um item que o host nao pode gerar
    entra como N/A, e N/A nunca reprova.
    """
    ms = det.get("max_score") or 0
    itens = []

    # --- Persistencia estatica (todos os hosts plantam) ---
    itens.append(("systemd unit (T1543.002)", True,
                  _tem_tecnica(det, "T1543.002"), ""))
    itens.append(("cron (T1053.003)", True,
                  _tem_tecnica(det, "T1053.003"), ""))
    itens.append(("ld.so.preload (T1574.006)", gcc,
                  _tem_tecnica(det, "T1574.006"),
                  "" if gcc else "N/A: host sem gcc nao planta a lib"))

    # --- Runtime do agent_chaos ---
    itens.append(("binario em local gravavel (miner)", True,
                  (det.get("unsafe_cmdlines") or 0) > 0 or _tem_tag(det, "UNSAFE"),
                  ""))

    # --- Modulos do chaos_maker ---
    itens.append(("GPU/mineracao", True, _tem_tag(det, "GPU", "MINER"), ""))
    itens.append(("falha de rede (NET ERR)", True, _tem_tag(det, "NET ERR"), ""))
    itens.append(("processo zumbi", True, _tem_tag(det, "ZOMBIE"), ""))
    itens.append(("binario apagado (DELETED)", True, _tem_tag(det, "DELETED"), ""))
    itens.append(("EDR/AV (fanotify)", True, _tem_tag(det, "EDR/AV"), ""))
    itens.append(("container", podman, _tem_tag(det, "CONTAINER"),
                  "" if podman else "N/A: host sem podman"))
    # Imutavel: o sinal confiavel e o Finding (T1222.002), que roda
    # deterministico no coletor; o bit 256 no score e um bonus quando o motor o
    # aplica. Aceitar qualquer um dos dois.
    itens.append(("arquivo imutavel (T1222.002)", True,
                  _tem_tecnica(det, "T1222.002") or bool(ms & 256),
                  "detectado como Finding de persistencia"))

    return itens


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "?"
    payload = json.load(sys.stdin)
    det = payload.get("detected") or {}
    gcc = bool(payload.get("gcc"))
    podman = bool(payload.get("podman"))

    if not det.get("found"):
        print("  [%s] SEM DADOS: %s" % (host, det.get("reason") or det))
        print("RESULT %s FAIL" % host)
        return

    itens = avaliar(host, det, gcc, podman)
    faltando = []
    for nome, esperado, detectado, obs in itens:
        if not esperado:
            estado = "N/A "
        elif detectado:
            estado = " OK "
        else:
            estado = "FALTA"
            faltando.append(nome)
        linha = "  [%s] %s" % (estado, nome)
        if obs:
            linha += "  (%s)" % obs
        print(linha)

    veredito = "PASS" if not faltando else "FAIL"
    print("  janela: %d capturas | max_score=%d | tags=%s"
          % (det.get("snapshots_in_window") or 0, det.get("max_score") or 0,
             ",".join(det.get("tags") or [])))
    print("RESULT %s %s%s" % (host, veredito,
                              ("" if not faltando else " faltando=" + ";".join(faltando))))


if __name__ == "__main__":
    main()
