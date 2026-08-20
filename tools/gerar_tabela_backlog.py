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

# --------------------------------------------------------------------------
# TEMA: a vista reagrupa, porque o backlog guarda por PROCEDENCIA
# --------------------------------------------------------------------------
# O backlog e um registro historico e agrupa por ONDE o item foi descoberto:
# a secao 0 e "pendencias acumuladas ate o release", a 15 e "itens que estavam
# fora do inventario". Isso tem valor e nao se mexe. Mas quem procura um ajuste
# de interface vai na secao "Interface", e ali so encontra o que ja foi feito:
# medido em 2026-08-20, 14 itens de interface estavam na secao 8 e 33 espalhados
# pelas outras. A tabela e uma VISTA, entao ela pode reagrupar por assunto sem
# tocar na fonte. A coluna "Origem" preserva de onde o item veio, para que a
# reclassificacao nunca esconda a procedencia.
# [2026-08-20, Mario] QUATRO temas, e nao dezesseis. A taxonomia anterior
# separava "Sustentacao operacional" de "Modo ocioso" de "Frota e distribuido",
# e o proprio dono do projeto nao reconhecia essas caixas: "eu vejo interface,
# coletores, agente e servidor". Classificacao que o leitor nao reconhece nao
# organiza, espalha: o mesmo assunto cai em duas caixas conforme a palavra usada,
# e ai some ou duplica. O que a tabela precisa responder e o que ha para fazer e
# o que depende do que.
TEMA_POR_SECAO = {
    "1.": "Coletores",
    "2.": "Coletores",
    "2-B": "Interface",
    "3.": "Coletores",
    "4.": "Coletores",
    "5.": "Servidor",
    "6.": "Servidor",
    "7.": "Agente",
    "8.": "Interface",
    "9.": "Servidor",
    "10.": "Projeto",
    "11.": "Projeto",
    "12.": "Projeto",
    "13.": "Agente",
    "14.": "Coletores",
}

# Secoes que sao GAVETA DE PROCEDENCIA, nao tema: os itens delas sao
# redistribuidos por palavra-chave. Qualquer outra secao mantem o tema dela.
SECOES_PROCEDENCIA = ("0.", "15.")

# Ordem de exibicao dos temas. Primeiro o que se olha mais.
ORDEM_TEMA = [
    "Interface",
    "Coletores",
    "Agente",
    "Servidor",
    "Projeto",
    "Sem tema definido",
]

# Classificacao por palavra-chave, aplicada SO aos itens das gavetas de
# procedencia. A ordem importa: o primeiro que casar vence, entao o mais
# especifico vem antes. Erro de classificacao aqui e visivel (o item aparece no
# tema errado) e nao silencioso (o item some), que e a troca certa.
TEMA_PALAVRAS = [
    ("Projeto",
     r"\brpm\b|pypi|\bobs\b|pacote|empacota|\.spec|release|versionamento|"
     r"changelog|\bteste|pytest|flake8|pylint|\blint\b|\bci\b|cobertura|"
     r"regress|document|readme|roadmap|manual|diagrama|\buml\b|"
     r"captura de tela|\.md\b|backlog|tabela de acompanhamento"),
    ("Interface",
     r"\btela|coluna|bot[ao]|\baba\b|arvore|[aá]rvore|badge|filtro|laudo|manager|"
     r"\bux\b|interface|icone|[íi]cone|legenda|tooltip|layout|dashboard|render|"
     r"emoji|navega|calend|exibi|clic|grafic|gr[áa]fic"),
    ("Coletores",
     r"sonda|probe|ebpf|kprobe|tracepoint|co-re|libbpf|\bbcc\b|coleta|captur|"
     r"kernel|rootkit|syscall|finding|achado|deteccao|detec[cç]|correlac|"
     r"correla[cç]|timeline|linha do tempo"),
    ("Servidor",
     r"servidor|ingest|dashboard|autentica|\bauth\b|\btls\b|https|certificad|"
     r"\btoken\b|allowlist|senha|\bca\b|frota"),
    ("Agente",
     r"agente|daemon|outbox|heartbeat|check.?in|reten[cç]|limpeza|\blog\b|"
     r"alerta|telegram|chaos|caos|fila|comando|ocioso"),
]

# Bloco em negrito sem ID: o gerador era CEGO a isto ate 2026-08-20, e por isso
# a "NAVEGACAO DE CAPTURAS", decidida pelo Mario em 2026-08-14, nunca apareceu na
# tabela. Agora aparece numa secao propria, marcada, em vez de sumir.
BLOCO_SOLTO = re.compile(r"^\*\*([^*].{12,})\*\*\s*:?\s*$")
# Rotulos internos de um item (nao sao itens): "**Why:**", "**Peso**", etc.
ROTULO_INTERNO = re.compile(
    r"^(why|how to apply|motivo|nota|aten[cç][aã]o|peso|regra|decis[aã]o|"
    r"argumento|proposta|ressalva|dire[cç][aã]o|a[cç][aã]o aqui|consequ|"
    r"padr[aã]o definido|antes de implementar|verificado|status)", re.I)

ITEM = re.compile(r"^(\s*)-\s+\*\*\[(OK|PARC|DIREC|ADIADO|FORA|REGRA|--)\]\*\*\s+(.*)$")
ID_JA = re.compile(r"^`([A-Z]{1,2}-\d{3})`\s+")
SECAO = re.compile(r"^##\s+(.*)$")
SUBSECAO = re.compile(r"^###\s+(.*)$")
# Dependencia declarada no proprio item: "(dep: C-001, F-014)". Fica no backlog,
# junto do item, porque dependencia e propriedade DELE: mantida numa lista a
# parte, ela envelheceria sem ninguem perceber.
DEP = re.compile(r"\(dep:\s*([A-Z]{1,2}-\d{3}(?:\s*,\s*[A-Z]{1,2}-\d{3})*)\)")


LEGENDA = """## Legenda

**Letra do ID: a ORIGEM da demanda** (D-023). A separacao existe porque as tres
nascentes tem cadencias incompativeis, e a infinita sufocaria as finitas se
vivessem na mesma lista.

| Letra | Gaveta | Nasce de | Comportamento |
|---|---|---|---|
| `F` | **Ferramenta** | uso, bug, divida tecnica, UX, documentacao | finito, diminui quando se trabalha |
| `C` | **Capacidade** | visao de produto, arquitetura, coleta nova | finito, muda a fundacao |
| `AM` | **Ameaca** | analise de ameaca externa (acervo proprio) | INFINITO, cresce sozinho |

**Estado do item:**

| Estado | Significa |
|---|---|
| concluido | Feito e verificado |
| parcial | Comecado, falta parte declarada no item |
| aberto | Nao comecou |
| so direcionar | A ferramenta APONTA o caminho, nao executa (D-028, D-031) |
| adiado | Correto, mas atras de outro item |
| fora de escopo | Decidido NAO fazer, com a decisao que tirou |
| regra permanente | Nao e tarefa: e regra que vale sempre |

**Colunas de dependencia:**

- **Depende de**: precisa daqueles itens prontos antes. Se algum estiver aberto,
  este nao esta pronto para comecar.
- **Destrava**: o que passa a ser possivel quando este fechar. Numero alto aqui
  significa gargalo, e gargalo merece prioridade mesmo sendo pequeno.

---

"""


def gaveta(secao):
    """Descobre a gaveta (F ou C) pelo numero da secao."""
    for prefixo, g in GAVETA_POR_SECAO.items():
        if secao.strip().startswith(prefixo):
            return g
    return "F"


def tema(item):
    """
    Assunto do item, para a VISTA. Nao altera nada no backlog.

    Secao tematica manda: e a classificacao que o autor deu. Secao de
    procedencia (0 e 15) nao diz assunto nenhum, entao o item e classificado
    pelo texto. Sem casar nenhuma palavra, cai em "Sem tema definido", que e
    visivel de proposito: nao classificado tem que incomodar.
    """
    s = item["secao"].strip()
    for prefixo in SECOES_PROCEDENCIA:
        if s.startswith(prefixo):
            # O nome da secao de procedencia NAO entra: "PENDENCIAS ACUMULADAS
            # ATE O RELEASE 1.0.0" contem "release", e isso mandava a secao 0
            # inteira para Empacotamento. Classificar pelo nome da gaveta e
            # classificar pelo acaso do titulo dela.
            #
            # Duas passadas, e a ordem importa. A PRIMEIRA LINHA e o item se
            # declarando, e vale mais: "Espacos vazios desperdicando altura de
            # tela no laudo" e interface, sem duvida. O corpo e explicacao, e
            # explicacao cita tudo: esse mesmo item menciona "durante o teste" e
            # ia parar em Qualidade. Por isso o corpo so decide quando a
            # primeira linha nao disse nada.
            for fonte in ("%s %s" % (item["texto"], item["subsecao"]),
                          item.get("corpo_todo") or ""):
                for nome, padrao in TEMA_PALAVRAS:
                    if re.search(padrao, fonte, re.I):
                        return nome
            return "Sem tema definido"
    for prefixo, nome in TEMA_POR_SECAO.items():
        if s.startswith(prefixo):
            return nome
    return "Sem tema definido"


def rotulo_secao(secao):
    """Nome curto da secao de origem, para a coluna Origem."""
    s = re.sub(r"\s*\[.*?\]\s*", "", secao).strip()
    return re.sub(r"\s+", " ", s)[:34]


def limpa(texto):
    """Texto legivel numa celula: sem marcacao e sem quebrar a coluna."""
    # A dependencia tem coluna propria; repeti-la no texto so rouba espaco.
    t = DEP.sub("", texto)
    t = re.sub(r"\*\*|~~", "", t)
    t = t.replace("`", "").replace("|", "/").replace("\n", " ")
    return re.sub(r"\s+", " ", t).strip()


def ler_itens(caminho):
    """
    Percorre o backlog e devolve um registro por linha marcada.

    Devolve TAMBEM os blocos em negrito sem ID. Ate 2026-08-20 eles eram
    simplesmente ignorados, e conteudo decidido pelo Mario ficava fora da vista
    que ele usa para dirigir o projeto. Agora saem numa secao propria: melhor
    aparecer marcado como nao classificado do que nao aparecer.
    """
    itens = []
    soltos = []
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
            # Bloco solto: so nas secoes numeradas. Os apendices (A a I) sao
            # registro de decisao e nota de projeto, nao fila de trabalho.
            b = BLOCO_SOLTO.match(linha.rstrip("\n"))
            if b and secao and secao[0].isdigit():
                titulo = b.group(1).strip()
                if not ROTULO_INTERNO.match(titulo):
                    soltos.append({"linha": n + 1, "texto": titulo,
                                   "secao": secao, "subsecao": subsecao})
            continue
        corpo = m.group(3)
        existente = ID_JA.match(corpo)
        deps = DEP.search(corpo)
        # Continuacao do item, para a CLASSIFICACAO por tema apenas. Um item de
        # varias linhas costuma dizer o assunto so a partir da segunda ("Deve ser
        # possivel dizer quais arquivos..."), e classificar pela primeira linha
        # jogava esses itens em "Sem tema definido" sem motivo real.
        corpo_todo = [corpo]
        for adiante in linhas[n + 1:]:
            texto_adiante = adiante.rstrip("\n")
            if (ITEM.match(texto_adiante) or SECAO.match(adiante)
                    or SUBSECAO.match(adiante) or BLOCO_SOLTO.match(texto_adiante)):
                break
            corpo_todo.append(texto_adiante)
        itens.append({
            "corpo_todo": " ".join(corpo_todo),
            "linha": n,
            "indent": m.group(1),
            "estado": m.group(2),
            "id": existente.group(1) if existente else None,
            "texto": corpo[existente.end():] if existente else corpo,
            "secao": secao,
            "subsecao": subsecao,
            "dep": [d.strip() for d in deps.group(1).split(",")] if deps else [],
        })
    return itens, soltos, linhas


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


def gerar(itens, soltos, saida, origem):
    """
    Escreve a tabela de acompanhamento: UMA fila, na ordem de execucao.

    [2026-08-20, Mario] A versao anterior tinha legenda longa, panorama, barras
    de progresso por tema, uma lista "ordem logica" quebrada por tema, outra de
    travados, e depois uma tabela por tema. O mesmo item aparecia em tres
    lugares, e achar um exigia saber em qual secao ele tinha caido. O pedido foi
    direto: uma tabela grande, na ordem do proximo a executar, dizendo do que
    depende e o que libera. E so isso que uma fila precisa responder.
    """
    hoje = datetime.date.today().isoformat()
    for i in itens:
        i["tema"] = tema(i)

    total = dict((e, 0) for e in ESTADOS)
    for i in itens:
        total[i["estado"]] += 1

    # Quem cada item destrava. Um item com muitos dependentes e gargalo, e
    # gargalo pequeno merece prioridade sobre item grande e isolado.
    destrava = {}
    por_id = dict((i["id"], i) for i in itens if i["id"])
    for i in itens:
        for d in i["dep"]:
            destrava.setdefault(d, []).append(i["id"])

    abertos = [i for i in itens if i["estado"] in ("--", "PARC")]
    prontos, travados = [], []
    for i in abertos:
        pendentes = [d for d in i["dep"]
                     if d in por_id and por_id[d]["estado"] in ("--", "PARC")]
        i["espera"] = pendentes
        (travados if pendentes else prontos).append(i)

    # Ordem da fila: primeiro o que ja da para comecar, e dentro disso o que
    # mais destrava. Depois o que espera alguem, que so entra na fila quando a
    # dependencia sair.
    prontos.sort(key=lambda i: (-len(destrava.get(i["id"], [])),
                                ORDEM_TEMA.index(i["tema"])
                                if i["tema"] in ORDEM_TEMA else 99,
                                i["linha"]))
    travados.sort(key=lambda i: (len(i["espera"]), i["linha"]))

    out = []
    out.append("# Tabela de acompanhamento\n\n")
    out.append("> **GERADO AUTOMATICAMENTE em %s. Nao editar a mao.**\n" % hoje)
    out.append("> Fonte: `%s`\n" % origem)
    out.append("> Regenerar: `python3 tools/gerar_tabela_backlog.py`\n>\n")
    out.append("> O backlog detalhado e a FONTE; esta tabela e uma vista dele.\n")
    out.append("> Editar aqui cria duas versoes do mesmo fato.\n\n")

    out.append("**Aberto: %d** (%d prontos para comecar, %d esperando outro "
               "item)  |  **Concluido: %d**  |  **Total: %d**\n\n"
               % (len(abertos), len(prontos), len(travados),
                  total["OK"], len(itens)))

    out.append("Letra do ID: `F` ferramenta, `C` capacidade, `AM` ameaca "
               "(D-023). Tema: onde o trabalho acontece.\n\n")

    # ------------------------------------------------------------------
    # A FILA
    # ------------------------------------------------------------------
    out.append("## A fila: proximo a executar primeiro\n\n")
    out.append("Ordenado por quanto cada item DESTRAVA. Os que esperam outro\n")
    out.append("item vem no fim, e so entram na fila quando a espera sair.\n\n")
    out.append("> **Cuidado ao ler:** \"depende de\" vazio significa dependencia\n")
    out.append("> **nao declarada**, e nao dependencia inexistente. So o que foi\n")
    out.append("> escrito como `(dep: ...)` no backlog e conhecido.\n\n")
    out.append("| # | ID | Tema | Item | Depende de | Libera |\n"
               "|---:|---|---|---|---|---|\n")
    pos = 0
    for i in prontos:
        pos += 1
        alvo = destrava.get(i["id"], [])
        out.append("| %d | `%s` | %s | %s | - | %s |\n"
                   % (pos, i["id"] or "-", i["tema"], limpa(i["texto"])[:110],
                      ", ".join("`%s`" % a for a in alvo) or "-"))
    for i in travados:
        pos += 1
        alvo = destrava.get(i["id"], [])
        out.append("| %d | `%s` | %s | %s | %s | %s |\n"
                   % (pos, i["id"] or "-", i["tema"], limpa(i["texto"])[:110],
                      ", ".join("`%s`" % d for d in i["espera"]),
                      ", ".join("`%s`" % a for a in alvo) or "-"))
    out.append("\n")

    # ------------------------------------------------------------------
    # NAO CLASSIFICADO: o que o gerador via mas nao sabia contar
    # ------------------------------------------------------------------
    if soltos:
        out.append("## Fora da fila: blocos sem ID\n\n")
        out.append("Escrito no backlog em bloco de negrito, **sem o formato de\n")
        out.append("item**, e por isso fora da fila acima. Ate 2026-08-20 estes\n")
        out.append("blocos eram ignorados, e decisao registrada podia nunca\n")
        out.append("aparecer aqui.\n\n")
        out.append("> **Para trazer um para a fila:** reescrever no backlog como\n")
        out.append("> `- **[--]** texto` e rodar `--stamp`, que atribui o ID.\n\n")
        out.append("**Total: %d blocos.**\n\n" % len(soltos))
        out.append("| Linha | Bloco | Secao de origem |\n|---:|---|---|\n")
        for b in sorted(soltos, key=lambda x: x["linha"]):
            out.append("| %d | %s | %s |\n"
                       % (b["linha"], limpa(b["texto"])[:96],
                          rotulo_secao(b["secao"])))
        out.append("\n")

    # ------------------------------------------------------------------
    # CONCLUIDOS: fora do caminho, mas nao apagados
    # ------------------------------------------------------------------
    feitos = [i for i in itens if i["estado"] not in ("--", "PARC")]
    if feitos:
        out.append("## Fechados\n\n")
        out.append("Fora da fila de propriedade: quem dirige o projeto olha o\n")
        out.append("que falta. Ficam aqui porque apagar o registro do que foi\n")
        out.append("feito e como perder o historico.\n\n")
        out.append("| ID | Tema | Estado | Item |\n|---|---|---|---|\n")
        for i in sorted(feitos, key=lambda i: (ESTADOS.index(i["estado"]),
                                               i["linha"])):
            out.append("| `%s` | %s | %s | %s |\n"
                       % (i["id"] or "-", i["tema"], ROTULO[i["estado"]],
                          limpa(i["texto"])[:110]))
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

    itens, soltos, linhas = ler_itens(backlog)
    if stamp:
        novos = carimbar(itens, linhas, backlog)
        print("IDs novos carimbados no backlog: %d" % novos)
        itens, soltos, linhas = ler_itens(backlog)

    n = gerar(itens, soltos, saida, backlog)
    print("Tabela gerada: %s (%d itens)" % (saida, n))


if __name__ == "__main__":
    main()
