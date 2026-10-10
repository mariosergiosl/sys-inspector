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
from collections import Counter, defaultdict, deque

from src.core.findings import (SEV_LOW, SEV_MEDIUM, SEV_HIGH, SEV_CRITICAL)
from src.core.risk import CORES

# Ordem de exibicao da faixa, do mais grave ao menos. Info fica fora de
# proposito: e inventario, aparece em toda captura e nao separa nada.
SEVERIDADES = (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW)
SIGLA = {SEV_CRITICAL: "C", SEV_HIGH: "A", SEV_MEDIUM: "M", SEV_LOW: "B"}
NOME = {SEV_CRITICAL: "Critico", SEV_HIGH: "Alto", SEV_MEDIUM: "Medio",
        SEV_LOW: "Baixo"}

# Severidades que contam para "mudou", "fora do padrao" e para separar grupos.
# Baixo fica de fora pela mesma razao da regra de alerta (F-261): e atividade
# rotineira e varia o tempo todo. Medido em 2026-10-10 no dia 09/10 da .161:
# com o Baixo indo de 4 a 23 entre capturas seguidas, 99 de ~150 capturas
# sairam "fora do padrao" e 22 "mudaram", e o marcador deixou de separar.
# O Baixo continua na faixa; so nao dispara marcador.
RELEVANTES = (SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM)

# Lacuna: intervalo entre duas capturas do mesmo host maior que este multiplo
# do intervalo tipico daquele host, com um piso para nao acusar variacao normal
# de poucos segundos.
MULTIPLO_LACUNA = 3
PISO_LACUNA_S = 120

# [F-265] Padrao do host: o total de achados Medio ou acima mais comum nas
# capturas das ULTIMAS 24 HORAS antes de cada captura. Ate 2026-10-10 era o
# mais comum do mes inteiro, e as primeiras capturas LIMPAS da .161, logo
# depois de remover artefatos plantados, sairam "fora do padrao" porque o mes
# ainda era dominado pelo estado de antes. Um padrao recente acompanha a
# mudanca de estado do host. Com menos de PADRAO_MINIMO capturas na janela nao
# ha padrao para comparar, e a marca nao acende.
JANELA_PADRAO_S = 24 * 3600
PADRAO_MINIMO = 3

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
            "relevante": tuple(sev[s] for s in RELEVANTES),
            "total_relevante": sum(sev[s] for s in RELEVANTES),
            "mudou": False,
            "fora_do_padrao": False,
            "lacuna_antes": False,
            "anterior_sev": None,
            "padrao": None,
            "lacuna_s": None,
        })
    itens.sort(key=lambda i: i["captured_at"])

    por_host = defaultdict(list)
    for item in itens:
        por_host[item["agent_uuid"]].append(item)
    for capturas in por_host.values():
        intervalos = [b["captured_at"] - a["captured_at"]
                      for a, b in zip(capturas, capturas[1:])]
        tipico = statistics.median(intervalos) if intervalos else 0
        limite = max(PISO_LACUNA_S, MULTIPLO_LACUNA * tipico)
        anterior = None
        janela = deque()
        contagem = Counter()
        for c in capturas:
            # Janela deslizante das 24 h anteriores a ESTA captura, com o
            # contador mantido incrementalmente (meses de capturas a cada ~40 s
            # nao podem custar uma varredura por captura).
            while janela and (c["captured_at"] - janela[0]["captured_at"]
                              > JANELA_PADRAO_S):
                velha = janela.popleft()
                contagem[velha["total_relevante"]] -= 1
                if not contagem[velha["total_relevante"]]:
                    del contagem[velha["total_relevante"]]
            if len(janela) >= PADRAO_MINIMO:
                # Empate fica com o menor, que e a leitura conservadora ("o
                # normal e ter menos").
                maior = max(contagem.values())
                c["padrao"] = min(t for t, n in contagem.items() if n == maior)
                c["fora_do_padrao"] = c["total_relevante"] != c["padrao"]
            janela.append(c)
            contagem[c["total_relevante"]] += 1
            if anterior is not None:
                c["anterior_sev"] = anterior["sev"]
                c["mudou"] = c["relevante"] != anterior["relevante"]
                intervalo = c["captured_at"] - anterior["captured_at"]
                c["lacuna_antes"] = intervalo > limite
                c["lacuna_s"] = intervalo if c["lacuna_antes"] else None
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


def _faixa(composicao, largura=100, contexto=""):
    """
    Faixa empilhada por severidade, com as contagens escritas.

    Cada pedaco diz por extenso o que conta ao passar o mouse ("Critico: 3
    achados"): a letra sozinha era um codigo que so quem escreveu entendia.

    PARAMETER contexto: complemento da dica, por exemplo "na pior captura do
              dia".
    """
    total = sum(composicao.values())
    if not total:
        return ("<div class='cal-faixa vazia' title='Nenhum achado Baixo ou "
                "acima'>nada encontrado</div>")
    partes = []
    for s in SEVERIDADES:
        n = composicao.get(s, 0)
        if n:
            partes.append("<span style='flex:%d;background:%s' title='%s: %d "
                          "achado(s)%s'>%s%d</span>"
                          % (n, CORES[s], NOME[s], n,
                             (" " + contexto) if contexto else "",
                             SIGLA[s], n))
    return ("<div class='cal-faixa' style='width:%d%%'>%s</div>"
            % (largura, "".join(partes)))


def _fmt_hora(ts):
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def fmt_atraso(seg):
    if seg is None:
        return "nao medido"
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
    "min-width:24px;padding:0 2px}"
    ".cal-faixa.vazia{color:#555;font-weight:normal}"
    ".cal-marca{display:inline-block;margin-right:6px}"
    ".cal-delta{color:#4ec9b0}.cal-desvio{color:#ffd166}"
    ".cal-lacuna{color:#ff6b6b}"
    ".cal-legenda{font-size:11px;color:#888;margin:10px 0 18px;line-height:1.7}"
    ".cal-horas{display:grid;grid-template-columns:repeat(24,1fr);gap:3px;"
    "margin:10px 0}"
    ".cal-hora{background:var(--drk);border:1px solid #333;border-top-width:4px;"
    "border-radius:3px;padding:3px;font-size:10px;color:#bbb;"
    "text-decoration:none;text-align:center;display:block}"
    ".cal-hora .cal-faixa span{min-width:0}"
    ".cal-hora.sel{outline:2px solid var(--cyn)}"
    # Botoes no desenho dos da tela Manager, e nao links sublinhados.
    ".cal-btn{color:var(--cyn);text-decoration:none;border:1px solid #2f4f4a;"
    "border-radius:4px;padding:2px 9px;font-size:11px;white-space:nowrap;"
    "margin-right:4px;display:inline-block}"
    ".cal-btn:hover{background:#222;color:#fff;border-color:var(--cyn)}"
    ".cal-detalhe{color:#999;font-size:11px;margin-top:2px}"
    ".cal-titulo{display:flex;align-items:center;gap:8px}"
)


def bolha(titulo, conteudo):
    """
    O "?" de ajuda, no mesmo desenho das outras telas (classe .ajuda, cujo
    estilo vem em toda pagina do servidor). Fica aqui para o calendario nao
    depender do controlador.
    """
    return ("<span class='ajuda'><span class='icone'>?</span>"
            "<span class='balao'><b style='color:#4ec9b0;font-size:11px'>%s"
            "</b><div style='font-size:11px;color:#bbb;line-height:1.6;"
            "margin-top:6px'>%s</div></span></span>"
            % (html.escape(titulo), conteudo))


AJUDA_FAIXA = (
    "Cada cor e uma severidade, com a letra e a quantidade: "
    "<b style='color:%s'>C</b> critico, <b style='color:%s'>A</b> alto, "
    "<b style='color:%s'>M</b> medio, <b style='color:%s'>B</b> baixo. Info "
    "fica de fora: e inventario e aparece em toda captura. A borda do dia (ou "
    "da hora) tem a cor da severidade mais alta presente."
    % (CORES[SEV_CRITICAL], CORES[SEV_HIGH], CORES[SEV_MEDIUM], CORES[SEV_LOW]))

AJUDA_MARCAS = (
    "<b class='cal-delta'>mudou</b>: a captura tem achados Medio ou acima "
    "diferentes da captura anterior do mesmo host. "
    "<b class='cal-desvio'>fora do padrao</b>: o total de achados Medio ou "
    "acima difere do valor mais comum daquele host nas 24 horas anteriores "
    "(com pelo menos tres capturas para comparar). "
    "<b class='cal-lacuna'>lacuna</b>: o intervalo desde a captura anterior foi "
    "bem maior que o tipico do host (agente parado, host desligado ou "
    "entrega interrompida). Achados Baixos variam com a atividade normal e "
    "nao disparam nenhuma destas marcas.")


def _marcas(r):
    """Contadores do dia em palavras: mudaram, fora do padrao, lacunas."""
    saida = ""
    if r["mudou"]:
        saida += ("<div class='cal-delta' title='Capturas com achados Medio ou "
                  "acima diferentes da anterior do mesmo host'>%d mudaram</div>"
                  % r["mudou"])
    if r["fora"]:
        saida += ("<div class='cal-desvio' title='Capturas cujo total de achados "
                  "Medio ou acima difere do mais comum do host'>%d fora do "
                  "padrao</div>" % r["fora"])
    if r["lacunas"]:
        saida += ("<div class='cal-lacuna' title='Intervalos sem captura bem "
                  "maiores que o tipico do host'>%d lacuna(s)</div>"
                  % r["lacunas"])
    return saida


def _grade(ano, mes, dias, link_mes, celula, legenda, dia_sel=None):
    """
    Grade do mes, comum aos dois calendarios (capturas e achados): as mesmas
    cores e a mesma leitura nos dois, como o Mario pediu.

    PARAMETER celula: funcao(date, resumo_do_dia) -> (cor_da_borda, url,
              html_interno, dica). Chamada so para dias com dado.
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
            cor, url, interno, dica = celula(d, r)
            saida += ("<a class='%s' href='%s' style='border-left-color:%s' "
                      "title='%s'><div class='cal-num'>%d</div>%s</a>"
                      % (classes, url, cor, dica, d.day, interno))
    ajuda = bolha("Como ler o calendario",
                  AJUDA_FAIXA + "<br><br>" + AJUDA_MARCAS)
    saida += ("</div><div class='cal-legenda cal-titulo'>%s %s</div>"
              % (ajuda, legenda))
    return saida


def _cor_borda(composicao):
    """Cor da severidade mais alta presente; cinza quando nao ha nenhuma."""
    alta = severidade_mais_alta(composicao)
    return CORES.get(alta, "#444") if alta else "#444"


LEGENDA_CORES = ("Borda: severidade mais alta do dia. Faixa: composicao por "
                 "severidade (C critico, A alto, M medio, B baixo; Info fica "
                 "fora). ")


def render_mes(ano, mes, dias, link_dia, link_mes, geral, dia_sel=None):
    """
    Calendario de CAPTURAS E COLETAS.

    PARAMETER dias: resultado de resumir_dias.
    PARAMETER link_dia: funcao(date) -> URL do dia.
    PARAMETER link_mes: funcao(ano, mes) -> URL do mes.
    PARAMETER geral: True na visao de todos os hosts (a celula diz quantos
              hosts tiveram algo a olhar).
    """
    def celula(d, r):
        hosts = (" &middot; %d hosts" % len(r["hosts"])) if geral else ""
        atencao = ""
        if geral and r["hosts_atencao"]:
            atencao = ("<div style='color:#ffd166'>%d host(s) a olhar</div>"
                       % len(r["hosts_atencao"]))
        interno = ("<div>%d capturas%s</div>%s%s%s"
                   % (r["capturas"], hosts,
                      _faixa(r["pior"], contexto="na pior captura do dia"),
                      _marcas(r), atencao))
        return (_cor_borda(r["pior"]), link_dia(d), interno,
                "Composicao da pior captura do dia; clique para listar as "
                "capturas")
    legenda = (LEGENDA_CORES + "Aqui a faixa e a da pior captura do dia. "
               "<span class='cal-delta'>&Delta;</span> capturas que mudaram em "
               "relacao a anterior do mesmo host. "
               "<span class='cal-desvio'>&ne;</span> capturas fora do padrao do "
               "host. <span class='cal-lacuna'>&#9888;</span> lacunas sem "
               "captura. Capturado = agente; coletado = servidor.")
    return _grade(ano, mes, dias, link_mes, celula, legenda, dia_sel)


# Tipo de evento dos achados e da captura, como gravados pela EventStore.
EV_ACHADO = "finding.raised"
EV_CAPTURA = "capture.taken"


def _resumir_achados(eventos, chave_tempo):
    """
    Agrega eventos por uma chave de tempo (dia ou hora) para o calendario de
    achados: achados distintos por severidade, novos, demais eventos,
    capturas e hosts. "Novo" e a primeira vez, na sequencia recebida, que
    aquele host mostra aquele achado.
    """
    ordem = {sv: i for i, sv in enumerate(reversed(SEVERIDADES))}
    ja_visto = set()
    saida = {}
    for ev in eventos or []:
        k = chave_tempo(float(ev.get("corrected_ts") or 0))
        r = saida.setdefault(k, {"achados": {}, "novos": 0, "descobertas": 0,
                                 "capturas": 0, "eventos": 0, "hosts": set(),
                                 "hosts_atencao": set()})
        r["eventos"] += 1
        r["hosts"].add(ev.get("agent_uuid"))
        tipo = ev.get("type")
        if tipo == EV_CAPTURA:
            r["capturas"] += 1
            continue
        if tipo != EV_ACHADO:
            r["descobertas"] += 1
            continue
        sev = ev.get("severity")
        if sev not in SEVERIDADES:
            continue
        chave = (ev.get("agent_uuid"), ev.get("subject"))
        atual = r["achados"].get(chave)
        if atual is None or ordem[sev] > ordem[atual]:
            r["achados"][chave] = sev
        if chave not in ja_visto:
            ja_visto.add(chave)
            r["novos"] += 1
            r["hosts_atencao"].add(ev.get("agent_uuid"))
    for r in saida.values():
        r["composicao"] = {sv: 0 for sv in SEVERIDADES}
        for sev in r["achados"].values():
            r["composicao"][sev] += 1
    return saida


def render_horas_achados(eventos_do_dia, link_hora, hora_sel=None):
    """
    [F-258] Faixa das 24 horas na lista de eventos de um dia, no mesmo desenho
    da faixa do calendario de capturas. Pedido do Mario em 2026-10-10: "pode
    colocar nessa tela aquela mesma barra de filtro de hora?". Reduz o corte
    em 1500 eventos, mas nao o elimina: medido no mesmo dia, a hora das 18h da
    .161 tinha 3140 eventos, 1367 deles o mesmo achado reemitido a cada
    captura. Agrupar o evento repetido na lista e o que resolve (F-266).

    PARAMETER eventos_do_dia: dicts de EventStore.daily_rows do dia.
    PARAMETER link_hora: funcao(hora ou None) -> URL; None volta ao dia todo.
    """
    horas = _resumir_achados(
        eventos_do_dia, lambda ts: datetime.datetime.fromtimestamp(ts).hour)
    saida = ("<div class='cal-titulo' style='margin-top:6px'><b>Horas do "
             "dia</b> %s</div><div class='cal-horas'>"
             % bolha("Horas do dia", "Cada coluna e uma hora: quantos eventos "
                     "houve, a faixa dos achados distintos daquela hora (o "
                     "mesmo achado do mesmo host conta uma vez) e quantos "
                     "achados apareceram pela primeira vez no dia. Clique numa "
                     "hora para ver so ela.<br><br>"
                     + AJUDA_FAIXA))
    for h in range(24):
        r = horas.get(h)
        sel = " sel" if h == hora_sel else ""
        if not r:
            saida += ("<div class='cal-hora%s' style='border-top-color:#333'>"
                      "<b>%02dh</b><div style='color:#555'>sem evento</div></div>"
                      % (sel, h))
            continue
        novos = ("<span class='cal-delta' title='%d achado(s) vistos pela "
                 "primeira vez no dia'>novos %d</span>"
                 % (r["novos"], r["novos"])) if r["novos"] else ""
        saida += ("<a class='cal-hora%s' href='%s' style='border-top-color:%s' "
                  "title='Clique para listar so esta hora'><b>%02dh</b>"
                  "<div title='%d evento(s) nesta hora'>%d</div>%s"
                  "<div style='font-size:9px'>%s</div></a>"
                  % (sel, link_hora(h), _cor_borda(r["composicao"]), h,
                     r["eventos"], r["eventos"],
                     _faixa(r["composicao"],
                            contexto="distintos nesta hora"), novos))
    saida += "</div>"
    if hora_sel is not None:
        saida += ("<p><a class='cal-btn' href='%s'>&larr; dia inteiro</a></p>"
                  % link_hora(None))
    return saida


def resumir_dias_achados(eventos):
    """
    [F-258] Agrega os eventos por dia para o calendario de ACHADOS.

    Por dia: achados DISTINTOS (o mesmo achado do mesmo host conta uma vez no
    dia, com a severidade mais alta vista), composicao por severidade desses
    achados, quantos sao NOVOS (primeira vez que aquele host mostra aquele
    achado na janela carregada), descobertas (os demais eventos, exceto o
    registro da propria captura), capturas e hosts.

    PARAMETER eventos: dicts de EventStore.daily_rows, em ordem de tempo.
    """
    return _resumir_achados(eventos, _dia)


def render_mes_achados(ano, mes, dias, link_dia, link_mes, geral,
                       dia_sel=None):
    """[F-258] Calendario de ACHADOS E DESCOBERTAS, mesmas cores do outro."""
    def celula(d, r):
        hosts = (" &middot; %d hosts" % len(r["hosts"])) if geral else ""
        marcas = ""
        if r["novos"]:
            marcas += ("<span class='cal-marca cal-delta' title='Achados que "
                       "apareceram pela primeira vez neste dia'>novos %d"
                       "</span>" % r["novos"])
        if r["descobertas"]:
            marcas += ("<span class='cal-marca' style='color:#888' "
                       "title='Demais eventos: processos, conexoes, arquivos, "
                       "persistencia, sessoes, comandos'>%d eventos</span>"
                       % r["descobertas"])
        atencao = ""
        if geral and r["hosts_atencao"]:
            atencao = ("<div style='color:#ffd166'>%d host(s) com achado novo"
                       "</div>" % len(r["hosts_atencao"]))
        interno = ("<div>%d achados%s</div>%s<div>%s</div>%s"
                   % (len(r["achados"]), hosts, _faixa(r["composicao"]), marcas,
                      atencao))
        return (_cor_borda(r["composicao"]), link_dia(d), interno,
                "Achados distintos do dia; clique para abrir a lista de "
                "eventos do dia")
    legenda = (LEGENDA_CORES + "Aqui a faixa conta os achados distintos do "
               "dia (o mesmo achado do mesmo host conta uma vez). "
               "<span class='cal-delta'>novos</span> achados vistos pela "
               "primeira vez. Clique no dia para a lista completa de eventos.")
    return _grade(ano, mes, dias, link_mes, celula, legenda, dia_sel)


def _hora(ts):
    return datetime.datetime.fromtimestamp(ts).hour


def render_horas(do_dia, link_hora, hora_sel=None):
    """
    Faixa das 24 horas de um dia, com as mesmas cores do mes.

    Com uma captura a cada ~40 s, um dia tem centenas de capturas: medido em
    2026-10-09, a .161 tinha 148 so naquele dia, e a lista inteira nao deixava
    o Mario achar nada. A faixa e o mesmo raciocinio do mes, um nivel abaixo:
    quantas capturas em cada hora e a composicao da pior delas.

    PARAMETER link_hora: funcao(hora ou None) -> URL; None volta ao dia todo.
    """
    por_hora = defaultdict(list)
    for it in do_dia:
        por_hora[_hora(it["captured_at"])].append(it)
    saida = ("<div class='cal-titulo' style='margin-top:10px'><b>Horas do "
             "dia</b> %s</div><div class='cal-horas'>"
             % bolha("Horas do dia", "Cada coluna e uma hora: quantas capturas "
                     "houve, a faixa da pior delas e as marcas (&Delta; mudaram, "
                     "&ne; fora do padrao, cen cenario de teste). Clique numa "
                     "hora para listar so ela.<br><br>" + AJUDA_FAIXA))
    for h in range(24):
        caps = por_hora.get(h)
        sel = " sel" if h == hora_sel else ""
        if not caps:
            saida += ("<div class='cal-hora%s' style='border-top-color:#333'>"
                      "<b>%02dh</b><div style='color:#555'>sem captura</div></div>"
                      % (sel, h))
            continue
        pior = {s: max(c["sev"][s] for c in caps) for s in SEVERIDADES}
        mudou = sum(1 for c in caps if c["mudou"])
        fora = sum(1 for c in caps if c["fora_do_padrao"])
        cenario = sum(1 for c in caps if c["capture_type"] == "chaos")
        extra = ""
        if mudou:
            extra += ("<span class='cal-delta' title='%d captura(s) com achados "
                      "Medio ou acima diferentes da anterior'>&Delta;%d</span> "
                      % (mudou, mudou))
        if fora:
            extra += ("<span class='cal-desvio' title='%d captura(s) fora do "
                      "padrao do host'>&ne;%d</span> " % (fora, fora))
        if cenario:
            extra += ("<span style='color:#ffd166' title='%d captura(s) de "
                      "cenario de teste'>cen %d</span>" % (cenario, cenario))
        saida += ("<a class='cal-hora%s' href='%s' style='border-top-color:%s' "
                  "title='Clique para listar so esta hora'><b>%02dh</b>"
                  "<div>%d</div>%s<div style='font-size:9px'>%s</div></a>"
                  % (sel, link_hora(h), _cor_borda(pior), h, len(caps),
                     _faixa(pior, contexto="na pior captura desta hora"),
                     extra))
    saida += "</div>"
    if hora_sel is not None:
        saida += ("<p><a href='%s'>&larr; dia inteiro</a></p>"
                  % link_hora(None))
    return saida


def render_lista_do_dia(dia, itens, selo, link_captura, hora=None,
                        link_hora=None, link_eventos=None):
    """
    Capturas de um dia, agrupadas por host, com a faixa de horas no topo.

    PARAMETER selo: funcao(capture_type) -> HTML do selo de tipo.
    PARAMETER link_captura: funcao(agent_uuid, id) -> URL do relatorio.
    PARAMETER hora: se informada (0 a 23), lista so as capturas daquela hora.
    PARAMETER link_hora: funcao(hora ou None) -> URL; sem ela, nao ha faixa.
    PARAMETER link_eventos: funcao(agent_uuid, id) -> URL da lista de eventos
              daquela captura na Linha do tempo.
    """
    do_dia = [i for i in itens if _dia(i["captured_at"]) == dia]
    if not do_dia:
        return "<p style='color:#888'>Nenhuma captura em %s.</p>" % dia
    faixa_horas = render_horas(do_dia, link_hora, hora) if link_hora else ""
    if hora is not None:
        do_dia = [i for i in do_dia if _hora(i["captured_at"]) == hora]
    por_host = defaultdict(list)
    for it in do_dia:
        por_host[it["host"]].append(it)
    saida = faixa_horas + ("<h3 style='font-weight:300'>Capturas de %s%s</h3>"
                           % (dia.strftime("%d/%m/%Y"),
                              (", %02dh" % hora) if hora is not None else ""))
    for host in sorted(por_host, key=lambda h: str(h)):
        caps = por_host[host]
        grupos = agrupar_iguais(caps)
        saida += ("<h4 style='margin:14px 0 4px;color:#4ec9b0'>%s "
                  "<span style='color:#777;font-weight:normal'>(%d capturas em "
                  "%d grupos)</span></h4>"
                  % (html.escape(str(host)), len(caps), len(grupos)))
        saida += ("<table><tr><th>Capturado</th><th>Coletado</th>"
                  "<th title='Coletado menos capturado: quanto a captura levou "
                  "para chegar ao servidor'>Atraso da coleta</th>"
                  "<th>Tipo</th><th>Achados</th><th><span class='cal-titulo'>"
                  "Marcas %s</span></th><th></th></tr>"
                  % bolha("Marcas", AJUDA_MARCAS))
        for grupo in grupos:
            if len(grupo) == 1:
                saida += _linha_captura(grupo[0], selo, link_captura,
                                        link_eventos)
                continue
            primeira, ultima = grupo[0], grupo[-1]
            atrasos = [c["atraso"] for c in grupo if c["atraso"] is not None]
            baixos = [c["sev"][SEV_LOW] for c in grupo]
            pior = {sv: max(c["sev"][sv] for c in grupo) for sv in SEVERIDADES}
            variacao = ("" if min(baixos) == max(baixos) else
                        "<div class='cal-detalhe'>Baixo de %d a %d</div>"
                        % (min(baixos), max(baixos)))
            saida += ("<tr class='item cal-grupo'><td>%s a %s</td><td>varios</td>"
                      "<td>ate %s</td><td>%s</td><td style='width:220px'>%s</td>"
                      "<td>%s<b>%d capturas iguais</b>%s</td>"
                      "<td style='white-space:nowrap'>"
                      "<a class='cal-btn' href='%s'>primeira</a>"
                      "<a class='cal-btn' href='%s'>ultima</a></td></tr>"
                      % (_fmt_hora(primeira["captured_at"]),
                         _fmt_hora(ultima["captured_at"]),
                         fmt_atraso(max(atrasos)) if atrasos else "nao medido",
                         selo(primeira["capture_type"]),
                         _faixa(pior, contexto="no maximo do grupo"),
                         _marcas_captura(primeira), len(grupo), variacao,
                         link_captura(primeira["agent_uuid"], primeira["id"]),
                         link_captura(ultima["agent_uuid"], ultima["id"])))
            internas = "".join(_linha_captura(c, selo, link_captura,
                                              link_eventos) for c in grupo)
            saida += ("<tr><td colspan='7' style='padding:0 10px 6px'>"
                      "<details><summary style='cursor:pointer;color:#888;"
                      "font-size:11px'>ver as %d capturas</summary>"
                      "<table>%s</table></details></td></tr>"
                      % (len(grupo), internas))
        saida += "</table>"
    return saida


def agrupar_iguais(caps):
    """
    Capturas seguidas do mesmo host com a mesma leitura viram um grupo.

    Pedido do Mario em 2026-10-09 olhando a lista do dia: 144 linhas
    identicas (C2 A2 B2) a cada ~36 s, e "esta confuso". Mesma leitura =
    mesmos achados Medio ou acima, mesmo tipo e mesma marca de fora do
    padrao. O Baixo nao separa grupo (varia com a atividade normal) e aparece
    no grupo como intervalo. Uma captura que MUDOU, ou que vem depois de uma LACUNA, sempre abre
    grupo novo: o que muda nunca fica escondido dentro de uma sequencia.

    PARAMETER caps: capturas de UM host, em ordem de captura.
    """
    grupos = []
    for c in caps:
        if grupos:
            ref = grupos[-1][0]
            igual = (c["relevante"] == ref["relevante"]
                     and c["capture_type"] == ref["capture_type"]
                     and c["fora_do_padrao"] == ref["fora_do_padrao"]
                     and not c["mudou"] and not c["lacuna_antes"])
            if igual:
                grupos[-1].append(c)
                continue
        grupos.append([c])
    return grupos


def _diferenca(antes, depois):
    """'Alto 2->4, Critico 2->3' com as severidades Medio+ que mudaram."""
    partes = []
    for sv in RELEVANTES:
        a, d = (antes or {}).get(sv, 0), depois.get(sv, 0)
        if a != d:
            partes.append("%s %d&rarr;%d" % (NOME[sv], a, d))
    return ", ".join(partes)


def _marcas_captura(c):
    """
    Marcas de uma captura, com o DETALHE de cada uma: o que mudou, qual e o
    padrao do host e quanto durou a lacuna. Pedido do Mario: a marca sozinha
    dizia que algo era diferente, mas nao o que.
    """
    marcas = ""
    if c["mudou"]:
        marcas += ("<div><span class='cal-marca cal-delta'>&Delta; mudou</span>"
                   "<span class='cal-detalhe'>%s</span></div>"
                   % _diferenca(c["anterior_sev"], c["sev"]))
    if c["fora_do_padrao"]:
        marcas += ("<div><span class='cal-marca cal-desvio'>&ne; fora do "
                   "padrao</span><span class='cal-detalhe'>%d achado(s) Medio ou "
                   "acima; o comum neste host nas 24h anteriores e %d</span>"
                   "</div>"
                   % (c["total_relevante"], c["padrao"]))
    if c["lacuna_antes"]:
        marcas += ("<div><span class='cal-marca cal-lacuna'>&#9888; lacuna"
                   "</span><span class='cal-detalhe'>%s sem captura antes desta"
                   "</span></div>" % fmt_atraso(c["lacuna_s"]))
    return marcas


def _linha_captura(c, selo, link_captura, link_eventos):
    """Uma linha da lista: uma captura."""
    capt = _fmt_hora(c["captured_at"])
    if c["captura_estimada"]:
        capt = ("<span title='Captura sem data na custodia: usada a "
                "data de coleta'>%s*</span>" % capt)
    return ("<tr class='item'><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td style='width:220px'>%s</td><td>%s</td>"
            "<td style='white-space:nowrap'><a class='cal-btn' href='%s'>"
            "relatorio</a>%s</td></tr>"
            % (capt, _fmt_hora(c["collected_at"]),
               fmt_atraso(c["atraso"]), selo(c["capture_type"]),
               _faixa(c["sev"]), _marcas_captura(c) or "nenhuma",
               link_captura(c["agent_uuid"], c["id"]),
               ("<a class='cal-btn' href='%s'>eventos</a>"
                % link_eventos(c["agent_uuid"], c["id"]))
               if link_eventos else ""))
