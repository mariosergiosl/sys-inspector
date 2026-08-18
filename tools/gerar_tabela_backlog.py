#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tools/gerar_tabela_backlog.py
# USAGE: gerar_tabela_backlog.py [--stamp] [--backlog CAMINHO] [--saida CAMINHO]
# DESCRIPTION: Gera a tabela linear de acompanhamento a partir do backlog.
#
# WHY:         O backlog detalhado e a FONTE; a tabela e uma VISTA. Manter as duas
#              a mao recriaria a divergencia silenciosa que este projeto ja pagou
#              caro (o mesmo fato em dois lugares, afastando-se sem avisar). Aqui
#              a tabela e verdadeira por construcao: pode ser apagada do disco e
#              volta identica a partir do backlog.
#
#              O --stamp escreve os IDs DE VOLTA no backlog, uma unica vez. Sem
#              isso o identificador dependeria da posicao da linha e mudaria a
#              cada insercao, e um ID que muda nao serve para virar tarefa.
#
# OPTIONS:      ver a funcao usage
# REQUIREMENTS: Python 3.6+
# BUGS:         ---
# NOTES:        ---
# AUTHOR:       Mario Luz
# VERSION:      1.0
# CREATED:      2026-08-18
# REVISION:     ---
# ==============================================================================

import io
import os
import re
import sys
import datetime

BACKLOG = "docs/internal/backlog-completo.md"
SAIDA = "docs/internal/TABELA-acompanhamento.md"

# Estados reconhecidos, do concluido ao nao iniciado. Esta ordem e tambem a ordem
# de exibicao dentro de cada tema.
ESTADOS = ["OK", "PARC", "DIREC", "ADIADO", "FORA", "--", "REGRA"]

ROTULO = {
    "OK": "concluido",
    "PARC": "parcial",
    "DIREC": "so direcionar",
    "ADIADO": "adiado",
    "FORA": "fora de escopo",
    "--": "aberto",
    "REGRA": "regra permanente",
}

# Gaveta por secao (D-023). O que nao casar cai em F.
GAVETA_POR_SECAO = {
    "1.": "C", "2.": "C", "3.": "C", "4.": "C", "5.": "C",
    "7.": "C", "9.": "C", "13.": "C", "14.": "C", "15.": "C",
    "6.": "F", "8.": "F", "10.": "F", "11.": "F", "12.": "F",
}

ITEM = re.compile(r"^(\s*)-\s+\*\*\[(OK|PARC|DIREC|ADIADO|FORA|REGRA|--)\]\*\*\s+(.*)$")
ID_JA = re.compile(r"^`([A-Z]{1,2}-\d{3})`\s+")
SECAO = re.compile(r"^##\s+(.*)$")
SUBSECAO = re.compile(r"^###\s+(.*)$")


def gaveta(secao):
    """Descobre a gaveta (F ou C) pelo numero da secao."""
    for prefixo, g in GAVETA_POR_SECAO.items():
        if secao.strip().startswith(prefixo):
            return g
    return "F"


def limpa(texto):
    """Texto legivel numa celula: sem marcacao e sem quebrar a coluna."""
    t = re.sub(r"\*\*|~~", "", texto)
    t = t.replace("`", "").replace("|", "/").replace("\n", " ")
    return re.sub(r"\s+", " ", t).strip()


def ler_itens(caminho):
    """Percorre o backlog e devolve um registro por linha marcada."""
    itens = []
    secao = ""
    subsecao = ""
    with io.open(caminho, encoding="utf-8") as fh:
        linhas = fh.readlines()

    for n, linha in enumerate(linhas):
        m = SECAO.match(linha)
        if m:
            secao = m.group(1).strip()
            subsecao = ""
            continue
        m = SUBSECAO.match(linha)
        if m:
            subsecao = m.group(1).strip()
            continue
        m = ITEM.match(linha.rstrip("\n"))
        if not m:
            continue
        corpo = m.group(3)
        existente = ID_JA.match(corpo)
        itens.append({
            "linha": n,
            "indent": m.group(1),
            "estado": m.group(2),
            "id": existente.group(1) if existente else None,
            "texto": corpo[existente.end():] if existente else corpo,
            "secao": secao,
            "subsecao": subsecao,
        })
    return itens, linhas


def carimbar(itens, linhas, caminho):
    """Escreve os IDs de volta no backlog, preservando os que ja existem."""
    contador = {}
    for item in itens:
        if item["id"]:
            g, num = item["id"].split("-")
            contador[g] = max(contador.get(g, 0), int(num))

    novos = 0
    for item in itens:
        if item["id"]:
            continue
        g = gaveta(item["secao"])
        contador[g] = contador.get(g, 0) + 1
        item["id"] = "%s-%03d" % (g, contador[g])
        linhas[item["linha"]] = "%s- **[%s]** `%s` %s\n" % (
            item["indent"], item["estado"], item["id"], item["texto"].rstrip())
        novos += 1

    if novos:
        with io.open(caminho, "w", encoding="utf-8") as fh:
            fh.writelines(linhas)
    return novos


def gerar(itens, saida, origem):
    """Escreve a tabela de acompanhamento."""
    hoje = datetime.date.today().isoformat()
    por_secao = {}
    ordem_secao = []
    for i in itens:
        if i["secao"] not in por_secao:
            por_secao[i["secao"]] = []
            ordem_secao.append(i["secao"])
        por_secao[i["secao"]].append(i)

    total = dict((e, 0) for e in ESTADOS)
    for i in itens:
        total[i["estado"]] += 1
    aberto = total["--"] + total["PARC"]

    out = []
    out.append("# Tabela de acompanhamento\n\n")
    out.append("> **GERADO AUTOMATICAMENTE em %s. Nao editar a mao.**\n" % hoje)
    out.append("> Fonte: `%s`\n" % origem)
    out.append("> Regenerar: `python3 tools/gerar_tabela_backlog.py`\n>\n")
    out.append("> O backlog detalhado e a FONTE; esta tabela e apenas uma vista\n")
    out.append("> dele. Editar aqui cria duas versoes do mesmo fato, que e a\n")
    out.append("> divergencia silenciosa que este projeto ja pagou caro.\n\n")

    out.append("## Panorama\n\n")
    out.append("| Estado | Quantos |\n|---|---:|\n")
    for e in ESTADOS:
        if total[e]:
            out.append("| %s | %d |\n" % (ROTULO[e], total[e]))
    out.append("| **total** | **%d** |\n\n" % len(itens))
    out.append("**Em aberto (aberto + parcial): %d**\n\n" % aberto)

    out.append("## Progresso por tema\n\n")
    out.append("| Tema | Feito | Aberto | Progresso |\n|---|---:|---:|---|\n")
    for secao in ordem_secao:
        lst = por_secao[secao]
        ok = len([i for i in lst if i["estado"] == "OK"])
        ab = len([i for i in lst if i["estado"] in ("--", "PARC")])
        rel = len([i for i in lst if i["estado"] != "FORA"])
        pct = int(100.0 * ok / rel) if rel else 100
        barra = "#" * (pct // 10) + "." * (10 - pct // 10)
        out.append("| %s | %d | %d | `%s` %d%% |\n"
                   % (limpa(secao)[:58], ok, ab, barra, pct))
    out.append("\n---\n\n")

    for secao in ordem_secao:
        out.append("## %s\n\n" % limpa(secao))
        out.append("| ID | Estado | Item | Onde |\n|---|---|---|---|\n")
        ordenado = sorted(por_secao[secao],
                          key=lambda i: (ESTADOS.index(i["estado"]), i["linha"]))
        for i in ordenado:
            out.append("| `%s` | %s | %s | %s |\n"
                       % (i["id"] or "-", ROTULO[i["estado"]],
                          limpa(i["texto"])[:150],
                          limpa(i["subsecao"])[:38] or "-"))
        out.append("\n")

    with io.open(saida, "w", encoding="utf-8") as fh:
        fh.write("".join(out))
    return len(itens)


def usage():
    """Mostra a ajuda de uso."""
    print("Uso: gerar_tabela_backlog.py [--stamp] [--backlog X] [--saida Y]")
    print("  --stamp    escreve os IDs de volta no backlog (uma vez)")
    print("  --backlog  caminho do backlog (padrao: %s)" % BACKLOG)
    print("  --saida    caminho da tabela (padrao: %s)" % SAIDA)
    print("  --version  mostra a versao")
    sys.exit(0)


def main():
    """Fluxo principal."""
    backlog = BACKLOG
    saida = SAIDA
    stamp = False

    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--stamp":
            stamp = True
        elif a == "--backlog":
            backlog = args.pop(0)
        elif a == "--saida":
            saida = args.pop(0)
        elif a in ("--help", "-h"):
            usage()
        elif a in ("--version", "-v"):
            print("gerar_tabela_backlog.py versao 1.0")
            sys.exit(0)
        else:
            print("Opcao desconhecida: %s" % a)
            sys.exit(2)

    if not os.path.exists(backlog):
        print("Backlog nao encontrado: %s" % backlog)
        sys.exit(1)

    itens, linhas = ler_itens(backlog)
    if stamp:
        novos = carimbar(itens, linhas, backlog)
        print("IDs novos carimbados no backlog: %d" % novos)
        itens, linhas = ler_itens(backlog)

    n = gerar(itens, saida, backlog)
    print("Tabela gerada: %s (%d itens)" % (saida, n))


if __name__ == "__main__":
    main()
