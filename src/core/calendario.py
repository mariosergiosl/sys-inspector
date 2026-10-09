# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/calendario.py
# DESCRIPTION: Calendario de capturas e coletas (F-259): agrupa as capturas por
#              dia, marca o que mudou, o que foge do padrao do host e as
#              lacunas, e desenha o mes, na visao geral (todos os hosts) e na
#              individual (um host).
#
# WHY:         Pedido do Mario em 2026-10-09. Com uma captura a cada ~40 s, a
#              navegacao sequencial entre capturas nao leva ao incidente: sao
#              ~90 por hora por host, todas parecidas. O calendario responde
#              "em que dia aconteceu algo diferente" sem abrir nenhuma.
#
#              Decisoes dele que este modulo segue:
#              - captura e do agente, coleta e do servidor; as duas datas
#                aparecem, e a diferenca e o atraso de entrega;
#              - Info e inventario e fica fora da faixa de severidade;
#              - a contagem vale pelo DESVIO: dez capturas com 1 e uma com 15
#                e o que se olha;
#              - "o que mudou" e um MARCADOR, nao a contagem;
#              - nem so nivel nem so quantidade: a celula mostra a composicao
#                por severidade (20 medios nao sao 1 critico nem 20 criticos).
#
#              Usa so colunas em claro (custodia, tipo, resumo de achados):
#              nao decifra captura nenhuma, e por isso abre rapido mesmo com
#              milhares de capturas.
#
#              Sem dependencia de Linux (pwd, eBPF): os testes rodam em
#              qualquer plataforma.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import calendar
import datetime
import html
import statistics
from collections import Counter, defaultdict

from src.core.findings import (SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL)
from src.core.risk import CORES

# Ordem de exibicao da faixa, do mais grave ao menos. Info fica fora de
# proposito: e inventario, aparece em toda captura e nao separa nada.
SEVERIDADES = (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW)
SIGLA = {SEV_CRITICAL: "C", SEV_HIGH: "A", SEV_MEDIUM: "M", SEV_LOW: "B"}

# Lacuna: intervalo entre duas capturas do mesmo host maior que este multiplo
# do intervalo tipico daquele host, com um piso para nao acusar variacao normal
# de poucos segundos.
MULTIPLO_LACUNA = 3
PISO_LACUNA_S = 120

NOMES_MES = ("janeiro", "fevereiro", "marco", "abril", "maio", "junho",
             "julho", "agosto", "setembro", "outubro", "novembro", "dezembro")
DIAS_SEMANA = ("seg", "ter", "qua", "qui", "sex", "sab", "dom")


def _num(valor):
    """Inteiro tolerante: resumo vindo de outra versao nao derruba a tela."""
    try:
        return int(valor or 0)
    except (TypeError, ValueError):
        return 0


def preparar(linhas, nomes=None):
    """
    Enriquece cada captura com o que o calendario precisa.

    PARAMETER linhas: dicts com id, agent_uuid, collected_at, captured_at,
              capture_type e findings_summary (como devolve
              DatabaseManager.get_calendar_rows).
    PARAMETER nomes: {agent_uuid: hostname}, para exibir.
    Devolve a lista ordenada por instante de captura, cada item com: sev
    (contagens por severidade, sem Info), total, atraso, mudou, fora_do_padrao,
    lacuna_antes e captura_estimada (True quando a data de captura nao veio da
    custodia e foi usada a de coleta).
    """
    nomes = nomes or {}
    itens = []
    for ln in linhas or []:
        resumo = ln.get("findings_summary") or {}
        sev = {s: _num(resumo.get(s)) for s in SEVERIDADES}
        coletado = ln.get("collected_at")
        capturado = ln.get("captured_at")
        estimada = capturado is None
        if estimada:
            capturado = coletado
        itens.append({
            "id": ln.get("id"),
            "agent_uuid": ln.get("agent_uuid"),
            "host": nomes.get(ln.get("agent_uuid")) or ln.get("agent_uuid"),
            "captured_at": float(capturado or 0),
            "collected_at": float(coletado or 0),
            "captura_estimada": estimada,
            "atraso": (float(coletado) - float(capturado)
                       if coletado is not None and not estimada else None),
            "capture_type": ln.get("capture_type"),
            "sev": sev,
            "total": sum(sev.values()),
            "mudou": False,
            "fora_do_padrao": False,
            "lacuna_antes": False,
        })
    itens.sort(key=lambda i: i["captured_at"])

    por_host = defaultdict(list)
    for item in itens:
        por_host[item["agent_uuid"]].append(item)
    for capturas in por_host.values():
        # Padrao do host: o total mais comum na janela. Empate fica com o
        # menor, que e a leitura conservadora ("o normal e ter menos").
        contagem = Counter(c["total"] for c in capturas)
        maior = max(contagem.values())
        padrao = min(t for t, n in contagem.items() if n == maior)
        intervalos = [b["captured_at"] - a["captured_at"]
                      for a, b in zip(capturas, capturas[1:])]
        tipico = statistics.median(intervalos) if intervalos else 0
        limite = max(PISO_LACUNA_S, MULTIPLO_LACUNA * tipico)
        anterior = None
        for c in capturas:
            c["fora_do_padrao"] = len(capturas) > 1 and c["total"] != padrao
            if anterior is not None:
                c["mudou"] = c["sev"] != anterior["sev"]
                c["lacuna_antes"] = (c["captured_at"] - anterior["captured_at"]
                                     > limite)
            anterior = c
    return itens


def _dia(ts):
    return datetime.datetime.fromtimestamp(ts).date()


def resumir_dias(itens):
    """
    Agrega as capturas por dia (data local da CAPTURA).

    Por dia: capturas, hosts, pior composicao (o maximo de cada severidade
    entre as capturas do dia), tipos, quantas mudaram, quantas fogem do padrao,
    lacunas, hosts com algo a olhar (mudou ou fora do padrao) e o maior atraso.
    """
    dias = {}
    for it in itens:
        d = _dia(it["captured_at"])
        r = dias.setdefault(d, {
            "capturas": 0, "hosts": set(), "pior": {s: 0 for s in SEVERIDADES},
            "tipos": Counter(), "mudou": 0, "fora": 0, "lacunas": 0,
            "hosts_atencao": set(), "atraso_max": None})
        r["capturas"] += 1
        r["hosts"].add(it["agent_uuid"])
        for s in SEVERIDADES:
            r["pior"][s] = max(r["pior"][s], it["sev"][s])
        r["tipos"][it["capture_type"] or "?"] += 1
        r["mudou"] += 1 if it["mudou"] else 0
        r["fora"] += 1 if it["fora_do_padrao"] else 0
        r["lacunas"] += 1 if it["lacuna_antes"] else 0
        if it["mudou"] or it["fora_do_padrao"]:
            r["hosts_atencao"].add(it["agent_uuid"])
        if it["atraso"] is not None:
            r["atraso_max"] = max(r["atraso_max"] or 0, it["atraso"])
    return dias


def severidade_mais_alta(composicao):
    """Primeira severidade com contagem, na ordem do mais grave; ou None."""
    for s in SEVERIDADES:
        if composicao.get(s):
            return s
    return None


def _faixa(composicao, largura=100):
    """Faixa empilhada por severidade, com as contagens escritas."""
    total = sum(composicao.values())
    if not total:
        return ("<div class='cal-faixa vazia' title='Nenhum achado Baixo ou "
                "acima'>&mdash;</div>")
    partes = []
    for s in SEVERIDADES:
        n = composicao.get(s, 0)
        if n:
            partes.append("<span style='flex:%d;background:%s' title='%s: %d'>"
                          "%s%d</span>" % (n, CORES[s], s, n, SIGLA[s], n))
    return ("<div class='cal-faixa' style='width:%d%%'>%s</div>"
            % (largura, "".join(partes)))


def _fmt_hora(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def fmt_atraso(seg):
    if seg is None:
        return "&mdash;"
    if seg < 120:
        return "%ds" % round(seg)
    if seg < 7200:
        return "%dmin" % round(seg / 60)
    return "%.1fh" % (seg / 3600.0)


CSS = (
    ".cal-nav{display:flex;align-items:center;gap:14px;margin:4px 0 14px}"
    ".cal-nav a{color:var(--cyn);text-decoration:none}"
    ".cal-grade{display:grid;grid-template-columns:repeat(7,1fr);gap:6px}"
    ".cal-sem{color:#777;font-size:10px;text-transform:uppercase;"
    "text-align:center}"
    ".cal-dia{background:var(--drk);border:1px solid #333;border-left-width:4px;"
    "border-radius:4px;padding:6px;min-height:78px;font-size:11px;color:#bbb;"
    "text-decoration:none;display:block}"
    ".cal-dia:hover{border-color:var(--cyn)}"
    ".cal-dia.fora{opacity:.25}"
    ".cal-dia.sel{outline:2px solid var(--cyn)}"
    ".cal-num{font-size:13px;color:#ddd}"
    ".cal-faixa{display:flex;height:14px;margin:4px 0;border-radius:2px;"
    "overflow:hidden;font-size:9px;color:#111;font-weight:bold}"
    ".cal-faixa span{display:flex;align-items:center;justify-content:center;"
    "min-width:18px}"
    ".cal-faixa.vazia{color:#555;font-weight:normal}"
    ".cal-marca{display:inline-block;margin-right:6px}"
    ".cal-delta{color:#4ec9b0}.cal-desvio{color:#ffd166}"
    ".cal-lacuna{color:#ff6b6b}"
    ".cal-legenda{font-size:11px;color:#888;margin:10px 0 18px;line-height:1.7}"
)


def _marcas(r):
    """Contadores do dia: mudou, fora do padrao, lacunas."""
    saida = ""
    if r["mudou"]:
        saida += ("<span class='cal-marca cal-delta' title='Capturas cuja "
                  "composicao de achados mudou em relacao a anterior do mesmo "
                  "host'>&Delta;%d</span>" % r["mudou"])
    if r["fora"]:
        saida += ("<span class='cal-marca cal-desvio' title='Capturas com total "
                  "de achados diferente do padrao do proprio host'>&ne;%d"
                  "</span>" % r["fora"])
    if r["lacunas"]:
        saida += ("<span class='cal-marca cal-lacuna' title='Intervalos sem "
                  "captura muito maiores que o tipico do host'>&#9888;%d</span>"
                  % r["lacunas"])
    return saida


def render_mes(ano, mes, dias, link_dia, link_mes, geral, dia_sel=None):
    """
    Grade do mes.

    PARAMETER dias: resultado de resumir_dias.
    PARAMETER link_dia: funcao(date) -> URL do dia.
    PARAMETER link_mes: funcao(ano, mes) -> URL do mes.
    PARAMETER geral: True na visao de todos os hosts (a celula diz quantos
              hosts tiveram algo a olhar).
    """
    anterior = (ano - 1, 12) if mes == 1 else (ano, mes - 1)
    proximo = (ano + 1, 1) if mes == 12 else (ano, mes + 1)
    saida = ("<div class='cal-nav'><a href='%s'>&#9664;</a>"
             "<b style='font-size:15px'>%s de %d</b>"
             "<a href='%s'>&#9654;</a></div>"
             % (link_mes(*anterior), NOMES_MES[mes - 1], ano,
                link_mes(*proximo)))
    saida += "<div class='cal-grade'>"
    saida += "".join("<div class='cal-sem'>%s</div>" % d for d in DIAS_SEMANA)
    for semana in calendar.Calendar(firstweekday=0).monthdatescalendar(ano, mes):
        for d in semana:
            r = dias.get(d)
            classes = "cal-dia" + ("" if d.month == mes else " fora")
            classes += " sel" if d == dia_sel else ""
            if not r:
                saida += ("<div class='%s' style='border-left-color:#333'>"
                          "<div class='cal-num'>%d</div>"
                          "<div style='color:#555'>sem captura</div></div>"
                          % (classes, d.day))
                continue
            alta = severidade_mais_alta(r["pior"])
            cor = CORES.get(alta, "#444") if alta else "#444"
            hosts = (" &middot; %d hosts" % len(r["hosts"])) if geral else ""
            atencao = ""
            if geral and r["hosts_atencao"]:
                atencao = ("<div style='color:#ffd166'>%d host(s) a olhar</div>"
                           % len(r["hosts_atencao"]))
            saida += ("<a class='%s' href='%s' style='border-left-color:%s' "
                      "title='Composicao da pior captura do dia; clique para "
                      "listar as capturas'>"
                      "<div class='cal-num'>%d</div>"
                      "<div>%d capturas%s</div>%s<div>%s</div>%s</a>"
                      % (classes, link_dia(d), cor, d.day, r["capturas"], hosts,
                         _faixa(r["pior"]), _marcas(r), atencao))
    saida += "</div>"
    saida += ("<div class='cal-legenda'>Borda: severidade mais alta do dia. "
              "Faixa: composicao da pior captura do dia (C critico, A alto, "
              "M medio, B baixo; Info fica fora). "
              "<span class='cal-delta'>&Delta;</span> capturas que mudaram em "
              "relacao a anterior do mesmo host. "
              "<span class='cal-desvio'>&ne;</span> capturas fora do padrao do "
              "host. <span class='cal-lacuna'>&#9888;</span> lacunas sem "
              "captura. Capturado = agente; coletado = servidor.</div>")
    return saida


def render_lista_do_dia(dia, itens, selo, link_captura):
    """
    Capturas de um dia, agrupadas por host.

    PARAMETER selo: funcao(capture_type) -> HTML do selo de tipo.
    PARAMETER link_captura: funcao(agent_uuid, id) -> URL do relatorio.
    """
    do_dia = [i for i in itens if _dia(i["captured_at"]) == dia]
    if not do_dia:
        return "<p style='color:#888'>Nenhuma captura em %s.</p>" % dia
    por_host = defaultdict(list)
    for it in do_dia:
        por_host[it["host"]].append(it)
    saida = "<h3 style='font-weight:300'>Capturas de %s</h3>" % dia.strftime(
        "%d/%m/%Y")
    for host in sorted(por_host, key=lambda h: str(h)):
        caps = por_host[host]
        saida += ("<h4 style='margin:14px 0 4px;color:#4ec9b0'>%s "
                  "<span style='color:#777;font-weight:normal'>(%d)</span></h4>"
                  % (html.escape(str(host)), len(caps)))
        saida += ("<table><tr><th>Capturado</th><th>Coletado</th><th>Atraso</th>"
                  "<th>Tipo</th><th>Achados</th><th>Marcas</th><th></th></tr>")
        for c in caps:
            marcas = ""
            if c["mudou"]:
                marcas += "<span class='cal-marca cal-delta'>&Delta; mudou</span>"
            if c["fora_do_padrao"]:
                marcas += ("<span class='cal-marca cal-desvio'>&ne; fora do "
                           "padrao</span>")
            if c["lacuna_antes"]:
                marcas += ("<span class='cal-marca cal-lacuna'>&#9888; lacuna "
                           "antes</span>")
            capt = _fmt_hora(c["captured_at"])
            if c["captura_estimada"]:
                capt = ("<span title='Captura sem data na custodia: usada a "
                        "data de coleta'>%s*</span>" % capt)
            saida += ("<tr class='item'><td>%s</td><td>%s</td><td>%s</td>"
                      "<td>%s</td><td style='width:220px'>%s</td><td>%s</td>"
                      "<td><a href='%s'>relatorio</a></td></tr>"
                      % (capt, _fmt_hora(c["collected_at"]),
                         fmt_atraso(c["atraso"]), selo(c["capture_type"]),
                         _faixa(c["sev"]), marcas or "&mdash;",
                         link_captura(c["agent_uuid"], c["id"])))
        saida += "</table>"
    return saida
