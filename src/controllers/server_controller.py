# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/controllers/server_controller.py
# DESCRIPTION: Controller logic for 'Server' mode.
#              Acts as the Central Manager for multiple agents.
#              - GET /: Dashboard of Agents
#              - POST /upload: Ingestion API for Agent Data
#              - GET /agent/<uuid>: View specific Agent Snapshot
#
# OPTIONS:
#
# PARAMETERS:
#   db_handler: Instance of DatabaseHandler
#   config: Configuration dictionary
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import ssl
import json
import time
import threading
import logging
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse as urlparse

# Internal Modules
from src.exporters.html_report import generate_report
from src.collectors.process_tree import ProcessTree, ProcessNode
from src.core.crypto import load_private_key, decrypt_data
from src.core.ingest import IngestQueue, process_batch
from src.core.retention import RetentionPolicy
from src.core.notify import Notifier
from src.core.capabilities import summarize, missing_for_scenarios
from src.core.events import EventStore, events_from_capture
from src.core import risk
from src.core.attack import describe, technique_url
from src.version import __version__
from src.core.correlation import correlate
from src.core.commands import CommandQueue, ALLOWED, STUCK_LIMIT
from src.core.tls import ensure_self_signed_cert
from src.core.outbox import PATH_SLOT, PATH_INGEST, PATH_COMMAND_RESULT
from src.core.snapshot_diff import (diff_snapshots, has_changes, classify,
                                    summarize_risk, build_timeline)
from src.exporters.html_report import _esc



def _fmt_ts(valor):
    """
    Momento da captura, data e hora completas, local e UTC.

    Delega ao formato unico da ferramenta (`_fmt_datahora`), para as telas nao
    divergirem no jeito de mostrar tempo, que num laudo forense e informacao
    sensivel: fuso omitido pode inverter a ordem de eventos entre maquinas.
    """
    return _fmt_datahora(valor, compacto=False)


def _selo_risco(score):
    """
    Risco de um processo como NIVEL nomeado, com o numero cru ao lado.

    O painel exibia o `anomaly_score` sozinho, e "130" nao diz o que pontuou nem
    quanto pesa; pior, o numero e um campo de bits e estava sendo comparado como
    magnitude, o que invertia a gravidade (ver src/core/risk.py). O rotulo passa
    a ser a leitura, e o numero continua visivel porque ele e o dado coletado: a
    interpretacao nao substitui a evidencia.

    Score sem sinal algum devolve um traco, e nao vazio: campo em branco nao
    distingue "nada foi levantado" de "nao foi avaliado" (D-020).
    """
    nivel = risk.level(score)
    if not nivel:
        return ("<span title='Avaliado: nenhum sinal de risco levantado neste "
                "processo' style='color:#555;font-size:11px'>&mdash;</span>")

    sinais = risk.summary(score)
    desconhecidos = risk.unknown_bits(score)
    if desconhecidos:
        sinais += (" + %d sinal(is) que esta versao ainda nao sabe nomear"
                   % bin(desconhecidos).count("1"))

    return ("<span title='%s (score %s): %s' style='background:%s;color:#000;"
            "border-radius:3px;padding:1px 7px;font-size:10px;font-weight:bold'>"
            "%s</span> <span style='color:#666;font-size:10px'>%s</span>"
            % (_esc(nivel), _esc(score), _esc(sinais), risk.color(score),
               _esc(nivel), _esc(score)))


# ------------------------------------------------------------------------------
# IDENTIDADE VISUAL
# ------------------------------------------------------------------------------
# As telas do servidor nasceram cada uma com o seu proprio bloco de estilo, e por
# isso o painel do gerente, as telas auxiliares e o laudo pareciam tres produtos.
# Aqui ficam a paleta e o cabecalho, definidos UMA vez.
#
# Deliberadamente CSS puro e inline: sem fonte externa, sem folha adicional, sem
# framework. A pagina da frota recarrega a cada 30 segundos e o laudo passa de
# 10MB; identidade visual nao pode custar requisicao nem tempo de carga.
#
# As variaveis abaixo tambem consertam um defeito silencioso: o painel ja usava
# `var(--acc)` e `var(--red)` sem nunca declarar `:root`, entao a borda do botao
# no hover e o fundo do contador de comandos simplesmente nao pintavam.
_PALETA = (":root{--bg:#121212;--fg:#e0e0e0;--acc:#0078d4;--red:#ff6b6b;"
           "--grn:#51cf66;--yel:#fcc419;--gry:#777;--drk:#252526;"
           "--border:#333;--cyn:#4ec9b0;}")

_CSS_IDENTIDADE = _PALETA + (
    "body{font-family:'Segoe UI','Roboto',sans-serif;background:var(--bg);"
    "color:var(--fg);font-size:13px;margin:0;padding:0}"
    ".hdr{display:flex;justify-content:space-between;align-items:center;"
    "background:#1a1a1a;border-bottom:2px solid var(--acc);padding:14px 30px}"
    ".title h1{margin:0;font-weight:300;font-size:26px;color:var(--acc);"
    "letter-spacing:-0.5px}"
    ".title h1 span{font-size:0.6em;color:#666;margin-left:10px}"
    ".subtitle{color:var(--gry);font-size:0.85em;text-transform:uppercase;"
    "letter-spacing:2px;margin-top:4px;font-weight:bold}"
    ".meta{text-align:right;color:#888;font-size:0.9em}"
    ".navlink{color:var(--cyn);text-decoration:none;border:1px solid #444;"
    "border-radius:4px;padding:4px 10px;margin-left:8px;font-size:11px;"
    "white-space:nowrap}"
    ".navlink:hover{border-color:var(--cyn);background:#222}"
    ".conteudo{padding:24px 30px}"
    # Barra de controles no mesmo desenho da aba Processes do laudo: o analista
    # alterna entre as telas o tempo todo, e um controle que muda de forma a
    # cada tela obriga a reaprender onde clicar.
    ".controles{display:flex;align-items:center;flex-wrap:wrap;gap:6px;"
    "background:var(--drk);border:1px solid #444;border-radius:4px;"
    "padding:8px 12px;margin-bottom:10px}"
    ".controles .rotulo{color:#777;font-size:10px;text-transform:uppercase;"
    "letter-spacing:1px;margin-right:4px}"
    ".sep{color:#444;margin:0 6px}"
    # Bolha de ajuda, igual a do "?" na arvore de processos.
    ".ajuda{position:relative;display:inline-block}"
    ".ajuda>.icone{cursor:help;border:1px solid #555;border-radius:50%;"
    "width:18px;height:18px;display:inline-flex;align-items:center;"
    "justify-content:center;color:#aaa;font-size:11px;background:#222}"
    ".ajuda>.balao{display:none;position:absolute;right:0;top:24px;z-index:50;"
    "background:#1a1a1a;border:1px solid #555;border-radius:4px;padding:12px;"
    "width:520px;box-shadow:0 8px 24px rgba(0,0,0,.6);text-align:left}"
    ".ajuda:hover>.balao{display:block}"
    ".ajuda table{width:100%;border-spacing:0}"
    ".ajuda td{padding:2px 6px;font-size:11px}"
    # Selo de tecnica ATT&CK, com a mesma forma em toda tela.
    ".attck{font-family:monospace;font-size:10px;color:var(--yel);"
    "border:1px solid #555;padding:1px 6px;border-radius:3px;"
    "text-decoration:none;white-space:nowrap}"
    ".attck:hover{border-color:var(--yel);background:#222}")

# Barra de navegacao entre as telas do servidor, uma so definicao para todas.
_NAVEGACAO = (("&#127968;", "/", "Frota"),
              ("&#128337;", "/timeline", "Linha do tempo"),
              ("&#128203;", "/queue", "Fila"),
              ("&#128220;", "/log", "Comandos"),
              ("&#129513;", "/capacidades", "Capacidades"))


def _barra_navegacao(atual=""):
    """Links entre as telas do servidor, com a atual marcada."""
    saida = ""
    for icone, destino, rotulo in _NAVEGACAO:
        # /capabilities e a rota real; o rotulo e que e traduzido.
        destino = "/capabilities" if destino == "/capacidades" else destino
        marca = ("background:#222;border-color:#4ec9b0;"
                 if destino == atual else "")
        saida += ("<a class='navlink' href='%s' style='%s'>%s %s</a>"
                  % (destino, marca, icone, rotulo))
    return saida


def _cabecalho_identidade(direita=""):
    """
    Cabecalho unico das telas do servidor.

    O mesmo titulo, subtitulo e versao do laudo. A versao vem da fonte unica:
    quem le a tela precisa saber qual codigo a produziu, e o painel nao pode
    afirmar uma versao diferente da que o laudo afirma.
    """
    return ("<div class='hdr'><div class='title'>"
            "<h1>Sys-Inspector<span>v%s</span></h1>"
            "<div class='subtitle'>OBSERVABILITY SUITE - Enterprise Forensic "
            "Report</div></div><div class='meta'>%s</div></div>"
            % (__version__, direita))


def _selo_attck(tecnica, texto=None):
    """
    Tecnica ATT&CK como selo clicavel, com nome e tatica no tooltip.

    Um identificador como "T1574.006" nao diz nada sozinho, e era exatamente
    assim que ele aparecia fora da aba ATT&CK do laudo. Aqui ele leva o nome da
    tecnica, a tatica a que pertence e uma frase do que ela significa, alem do
    link para o MITRE para quem tiver conectividade. O catalogo e local, entao a
    leitura funciona em rede isolada.
    """
    if not tecnica:
        return ""
    dados = describe(tecnica)
    if dados:
        nome, tatica, resumo = dados
        titulo = "%s\nTatica: %s\n\n%s" % (nome, tatica, resumo)
    else:
        # Tecnica sem verbete: aparece assim mesmo, e o tooltip diz por que.
        titulo = ("Tecnica ainda sem verbete no catalogo local desta versao. O "
                  "identificador e valido; o que falta e a legenda.")
    return ("<a class='attck' target='_blank' rel='noopener' href='%s' "
            "title='%s'>%s</a>"
            % (technique_url(tecnica), _esc(titulo), _esc(texto or tecnica)))


def _bolha_ajuda(titulo, conteudo):
    """Bolha de ajuda no mesmo desenho do "?" da arvore de processos."""
    return ("<span class='ajuda'><span class='icone'>?</span>"
            "<span class='balao'>"
            "<b style='color:#4ec9b0;font-size:11px'>%s</b>%s</span></span>"
            % (_esc(titulo), conteudo))


def _identifica_agente(info, uuid=""):
    """
    Um agente identificado por nome, e nao por oito digitos de UUID.

    O UUID e a identidade tecnica correta e continua na tela, mas ele nao
    responde a pergunta que se faz lendo um registro de comandos: em QUAL
    maquina isso aconteceu. Um pedaco de UUID obriga a ir procurar em outra
    tela, e num laudo obriga o leitor a fazer a correspondencia sozinho.

    Os tres nomes aparecem juntos de proposito: o mesmo host aparece com nomes
    diferentes em sistemas diferentes, e o endereco muda sem o host mudar.

    PARAMETER info: dict do agente vindo da frota (pode ser None se ainda nao
                    reportou; nesse caso so o UUID e conhecido, e a tela diz
                    isso em vez de deixar a celula vazia).
    """
    info = info or {}
    uuid = info.get("uuid") or uuid or ""
    host = info.get("hostname")
    fqdn = info.get("fqdn")
    ip = info.get("ip_address")

    if not host:
        return ("<span style='color:#888'>agente ainda nao identificado</span>"
                "<div style='color:#666;font-family:monospace;font-size:10px'>"
                "%s</div>" % _esc(uuid))

    detalhe = []
    if fqdn and fqdn != host:
        detalhe.append(_esc(fqdn))
    if ip:
        detalhe.append(_esc(ip))

    return ("<b style='color:#4ec9b0'>%s</b>"
            "<div style='color:#888;font-size:10px'>%s</div>"
            "<div style='color:#555;font-family:monospace;font-size:10px'>%s"
            "</div>"
            % (_esc(host), " &middot; ".join(detalhe) or "&mdash;", _esc(uuid)))


def _legenda_risco():
    """
    O que a escala de risco significa, escrita a partir da propria tabela.

    Gerada de `risk.SINAIS` de proposito: uma legenda mantida a mao ao lado da
    tabela seria uma segunda fonte do mesmo fato, e as duas divergiriam na
    primeira vez que um sinal novo entrasse. E a mesma falha que ja apareceu no
    tag_map e na lista de artefatos do cenario.
    """
    itens = ""
    for _bit, _chave, rotulo, severidade, explicacao in risk.SINAIS:
        itens += ("<div style='margin:3px 0'>"
                  "<span style='display:inline-block;width:74px;color:%s;"
                  "font-size:10px;font-weight:bold'>%s</span>"
                  "<span style='color:#bbb;font-size:11px'>%s</span>"
                  "<span style='color:#666;font-size:11px'> &mdash; %s</span>"
                  "</div>"
                  % (risk.CORES.get(severidade, "#888"), _esc(severidade),
                     _esc(rotulo), _esc(explicacao)))

    return ("<div style='background:#1a1a1a;border-left:3px solid #333;"
            "padding:12px 16px;margin-top:8px'>"
            "<p style='color:#777;font-size:11px;margin:0 0 10px'>"
            "O numero ao lado do rotulo e um campo de bits: cada bit e um sinal "
            "observado, e o valor em si nao mede gravidade. O nivel exibido e o "
            "maior entre os sinais presentes, elevado um degrau quando dois ou "
            "mais sinais de peso coincidem no mesmo processo.</p>%s</div>"
            % itens)


def _ajuda_risco():
    """A legenda de risco na bolha "?", do mesmo jeito que a arvore explica."""
    return _bolha_ajuda("Sinais do anomaly score (campo de bits)",
                        _legenda_risco())


def _fmt_datahora(epoch, compacto=True):
    """
    Data e hora completas em hora LOCAL, com o carimbo UTC ao lado.

    Um so formato para toda a ferramenta (frota, linha do tempo, comandos,
    laudo): so a hora ("14:01:17") nao diz o dia e nao cruza com log de outro
    sistema, que quase sempre esta em UTC. A ausencia do fuso num laudo forense
    pode inverter a ordem de eventos entre maquinas.

    PARAMETER compacto: em duas linhas e letra pequena, para caber em coluna de
                        tabela sem roubar largura das demais.
    """
    try:
        valor = float(epoch)
    except (TypeError, ValueError):
        return "<span style='color:#555'>&mdash;</span>"
    local = datetime.datetime.fromtimestamp(valor).strftime("%Y-%m-%d %H:%M:%S")
    utc = datetime.datetime.utcfromtimestamp(valor).strftime("%Y-%m-%d %H:%M:%S")
    if compacto:
        return ("<div>%s</div><div style='color:#666;font-family:monospace;"
                "font-size:10px'>%s UTC</div>" % (local, utc))
    return ("%s <span style='color:#666;font-size:10px'>%s UTC</span>"
            % (local, utc))


def _human_age(seconds):
    """Idade legivel ("12s atras"), para o analista nao precisar calcular."""
    seconds = int(seconds)
    if seconds < 60:
        return "%ds ago" % seconds
    if seconds < 3600:
        return "%dm ago" % (seconds // 60)
    if seconds < 86400:
        return "%dh ago" % (seconds // 3600)
    return "%dd ago" % (seconds // 86400)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP Server."""
    daemon_threads = True


class ServerHTTPHandler(BaseHTTPRequestHandler):
    """
    Handles API and Dashboard requests for the Server Mode.
    """

    def _set_headers(self, content_type="text/html", status=200):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def _rehydrate_tree(self, json_data):
        """
        Converts JSON 'processes' dict back into a ProcessTree object.
        Needed to view Agent reports on the Server.
        """
        tree = ProcessTree()
        raw_procs = json_data.get('processes', {})

        for pid, pdata in raw_procs.items():
            node = ProcessNode(
                int(pid),
                int(pdata.get('ppid', 0)),
                pdata.get('cmd', '?'),
                int(pdata.get('uid', 0)),
                pdata.get('prio', 120),
                pdata.get('loginuid', None)
            )
            for k, v in pdata.items():
                if k == 'open_files': v = set(v)
                if k == 'connections': v = set(v)
                if hasattr(node, k):
                    setattr(node, k, v)
            tree.nodes[int(pid)] = node
        return tree

    def do_GET(self):
        controller = self.server.controller

        if self.path == '/':
            # --- DASHBOARD ---
            self._serve_dashboard(controller.db, controller.commands)

        elif self.path == '/log':
            self._serve_command_log(controller)

        elif self.path.startswith('/timeline'):
            self._serve_timeline(controller)

        elif self.path == '/capabilities':
            self._serve_capabilities(controller)

        elif self.path == '/queue':
            self._serve_queue(controller)

        elif self.path.startswith('/priority/'):
            # /priority/<uuid>/<valor>: reposiciona um agente na fila.
            partes = self.path.strip('/').split('/')
            if len(partes) == 3:
                try:
                    controller.queue.set_priority(partes[1], int(partes[2]))
                    controller.logger.info("[QUEUE] Priority of %s set to %s",
                                           partes[1], partes[2])
                except Exception as e:
                    controller.logger.error("[QUEUE] Could not set priority: %s", e)
            self.send_response(302)
            self.send_header("Location", "/queue")
            self.end_headers()
            return

        elif self.path.startswith('/history/'):
            self._serve_history(controller, self.path.split('/')[-1])

        elif self.path.startswith('/diff/'):
            self._serve_diff(controller)

        elif self.path.startswith('/cmd/'):
            # /cmd/<acao>/<uuid>: o analista enfileira; nada e executado aqui.
            partes = self.path.strip('/').split('/')
            if len(partes) == 3 and partes[1] in ALLOWED:
                try:
                    controller.commands.enqueue(partes[2], partes[1],
                                                requested_by="dashboard")
                    controller.logger.info("[CMD] '%s' queued for %s",
                                           partes[1], partes[2])
                except Exception as e:
                    controller.logger.error("[CMD] Could not queue: %s", e)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        elif self.path.startswith('/agent/'):
            # --- VIEW AGENT SNAPSHOT ---
            caminho, _, consulta = self.path.partition("?")
            agent_uuid = caminho.split('/')[-1]
            args = urlparse.parse_qs(consulta or "")
            # Captura ESPECIFICA pedida (?capture=<id>), ou a mais recente.
            #
            # O pivo da linha do tempo chega aqui apontando a captura DE ONDE o
            # evento saiu, e nao a atual: um processo efemero (um shell, um
            # sleep) ja nao existe na captura mais recente, entao abrir sempre a
            # ultima fazia o pivo cair em "nao esta nesta captura" quase sempre.
            # Abrindo a captura de origem, o processo esta la.
            captura_pedida = (args.get("capture") or [None])[0]
            snaps = controller.db.get_history(0, time.time(), agent_filter=agent_uuid)

            escolhido = None
            if snaps:
                if captura_pedida:
                    escolhido = next((s for s in snaps
                                      if str(s.get("id")) == str(captura_pedida)),
                                     None)
                escolhido = escolhido or snaps[0]

            if escolhido:
                # get_snapshot_details devolve o bundle cifrado; descriptografa.
                data = controller.decrypt(
                    controller.db.get_snapshot_details(escolhido['id']))
                if data:
                    snaps = [escolhido]  # o carimbo e a idade usam este
                    tree = self._rehydrate_tree(data)

                    # Generate HTML
                    tmp_filename = f"/tmp/sys_server_{threading.get_ident()}.html"
                    # A versao do laudo e a do codigo que o produziu, lida da
                    # fonte unica. Estava fixa em "0.61.00", entao todo laudo
                    # aberto pelo servidor se declarava produzido por uma versao
                    # que nao existe mais: para quem for reproduzir a analise
                    # depois, e uma informacao errada no lugar mais sensivel.
                    generate_report(data, tree, tmp_filename, __version__)

                    with open(tmp_filename, 'r', encoding='utf-8') as f:
                        html_content = f.read()

                    # Retorno para a frota: sem isso o analista entra no
                    # relatorio de um host e fica sem caminho de volta.
                    # Barra propria acima do relatorio, no fluxo do documento.
                    # Com position:fixed o botao flutuava sobre o titulo e
                    # cobria o nome da ferramenta; ocupando espaco real ele
                    # apenas empurra o conteudo para baixo.
                    # Barra de acoes do host: as mesmas acoes do gerente,
                    # ao alcance de quem ja esta lendo o laudo daquele agente.
                    def _acao(caminho, icone, titulo, extra=""):
                        return ("<a href=\"/cmd/%s/%s\" title=\"%s\" "
                                "style=\"color:#4ec9b0; border:1px solid #444; "
                                "border-radius:4px; padding:4px 8px; margin-left:6px; "
                                "text-decoration:none; font-size:14px;%s\">%s</a>"
                                % (caminho, agent_uuid, titulo, extra, icone))

                    # IDADE DA CAPTURA, em destaque.
                    #
                    # O laudo aberto aqui e sempre o mais recente que chegou, e
                    # nada na tela dizia de quando ele e. Um laudo de meia hora
                    # atras e indistinguivel de um recem-coletado, e a leitura
                    # que isso produziu em campo foi de que a captura pedida
                    # falhara, quando o que estava na tela era simplesmente a
                    # anterior. Amarelo a partir de 15 minutos, vermelho a partir
                    # de uma hora: nao e alarme, e a informacao de que o que se
                    # esta lendo pode nao descrever o estado atual do host.
                    idade_seg = time.time() - float(snaps[0].get('timestamp') or 0)
                    cor_idade = ("#ff4d4d" if idade_seg > 3600
                                 else "#ffd166" if idade_seg > 900 else "#6a9955")
                    carimbo = (
                        "<span title=\"Momento em que o agente coletou estes "
                        "dados. O laudo descreve o host NAQUELE instante, e nao "
                        "agora.\" style=\"margin-left:16px; font-size:11px; "
                        "font-family:sans-serif; color:#888\">"
                        "coletado em %s <b style=\"color:%s\">(%s)</b></span>"
                        % (datetime.datetime.fromtimestamp(
                            float(snaps[0].get('timestamp') or 0)
                        ).strftime("%Y-%m-%d %H:%M:%S"), cor_idade,
                           _human_age(idade_seg)))

                    back = (
                        "<div style=\"background:#1a1a1a; border-bottom:1px solid #333; "
                        "padding:8px 20px; display:flex; align-items:center\">"
                        "<a href=\"/\" style=\"color:#4ec9b0; border:1px solid #4ec9b0; "
                        "border-radius:4px; padding:5px 14px; font-size:12px; "
                        "font-family:sans-serif; text-decoration:none\">"
                        "&larr; Fleet</a>"
                        + carimbo
                        + ("<a href=\"/history/%s\" title=\"Capturas anteriores "
                           "deste agente e comparacao entre duas\" "
                           "style=\"color:#4ec9b0; border:1px solid #444; "
                           "border-radius:4px; padding:4px 8px; margin-left:12px; "
                           "text-decoration:none; font-size:14px\">&#128337;</a>"
                           % agent_uuid)
                        + _acao("collect", "&#128248;",
                                "Solicitar captura agora: entra na fila, o agente "
                                "executa no proximo check-in (ate ~1 ciclo)")
                        + _acao("chaos", "&#9760;",
                                "APENAS LAB: cenario de teste por 300s, depois captura")
                        + _acao("restart", "&#128260;", "Restart the agent (queued)")
                        + "</div>")
                    # Ancora o link no primeiro elemento do corpo, e nao na
                    # string "<body>": essa sequencia tambem aparece DENTRO do
                    # JavaScript do relatorio (win.document.write('</head><body>')),
                    # e injetar ali quebrava a sintaxe do script inteiro,
                    # derrubando as abas e todos os controles da arvore.
                    anchor = '<div class="sticky-wrapper">'
                    html_content = html_content.replace(anchor, back + anchor, 1)

                    self._set_headers()
                    self.wfile.write(html_content.encode('utf-8'))

                    try: os.remove(tmp_filename)
                    except: pass
                    return

            self._set_headers(status=404)
            self.wfile.write(b"Agent not found or no data received yet.")

        else:
            self._set_headers(status=404)
            self.wfile.write(b"Not Found")

    def _read_json(self):
        """Le o corpo da requisicao como JSON; None se invalido."""
        try:
            length = int(self.headers.get('Content-Length', 0))
            return json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            return None

    def _reply(self, payload, status=200):
        self._set_headers(status=status, content_type="application/json")
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def _authorized(self, controller):
        """
        Confere o token compartilhado enviado pelo agente.

        Sem token configurado no servidor a ingestao fica ABERTA, o que so faz
        sentido em laboratorio; o log avisa para isso nao passar despercebido.
        """
        expected = controller.ingest_token
        if not expected:
            return True
        header = self.headers.get('Authorization', '')
        return header == ('Bearer ' + expected)

    def do_POST(self):
        # --- API INGESTION ---
        controller = self.server.controller

        # Rotas versionadas do transporte (Fase 2). O servidor controla a fila:
        # o agente pergunta quanto pode enviar antes de despejar o acumulo.
        if self.path in (PATH_SLOT, PATH_INGEST, PATH_COMMAND_RESULT):
            if not self._authorized(controller):
                self._reply({"status": "unauthorized"}, status=401)
                return

            data = self._read_json()
            if data is None:
                self._reply({"status": "bad_request"}, status=400)
                return

            agent_uuid = data.get('agent_uuid') or self.headers.get('X-Agent-Id') or 'remote'

            if self.path == PATH_SLOT:
                resposta = controller.queue.grant_slots(agent_uuid, data.get('pending', 0))
                # A mesma resposta leva o que o analista pediu, evitando uma
                # segunda ida e volta so para perguntar por ordens.
                resposta["commands"] = controller.commands.take_for(agent_uuid)
                # Confirma o que ESTA GUARDADO, nao o que foi recebido. E o que
                # autoriza o agente a liberar espaco sem risco de a captura se
                # perder dos dois lados.
                pedidos = data.get("confirm_digests") or []
                if pedidos:
                    resposta["stored_digests"] = controller.db.digests_present(
                        pedidos[:500])
                # Identidade do host chega tambem no check-in, para um agente
                # ocioso continuar aparecendo corretamente na frota.
                host = data.get('host') or {}
                if host:
                    controller.db.update_agent_status(
                        agent_uuid, "ONLINE", hostname=host.get("hostname"),
                        ip=host.get("ip_address"), os_info=host.get("os_info"),
                        fqdn=host.get("fqdn"),
                                       cycle_seconds=host.get("cycle_seconds"))
                    controller.db.set_capabilities(agent_uuid,
                                                   host.get("capabilities"))
                self._reply(resposta)
                return

            if self.path == PATH_COMMAND_RESULT:
                controller.commands.report(data.get('id'), data.get('ok'),
                                           data.get('result', ''))
                self._reply({"status": "recorded"})
                return

            result = controller.queue.enqueue(agent_uuid, data, origin="remote")
            if result == "error":
                self._reply({"status": "error"}, status=500)
                return
            controller.logger.info("[INGEST] %s from %s", result, agent_uuid)

            # Avisa quem precisa agir. O resumo de achados chega em claro junto
            # da captura, entao o alerta sai sem decifrar nada e sem esperar a
            # fila ser drenada: um aviso que chega depois do incidente terminar
            # nao serve para agir.
            try:
                resumo = (data.get("findings_summary") or {}).get("items") or []
                if resumo:
                    controller.notifier.notify(
                        (data.get("host") or {}).get("hostname") or agent_uuid,
                        resumo,
                        url="%s/agent/%s" % (controller.public_url, agent_uuid))
            except Exception as e:
                controller.logger.error("[NOTIFY] Failed: %s", e)
            self._reply({"status": result}, status=201 if result == "received" else 200)
            return

        if self.path == '/upload':
            try:
                content_len = int(self.headers.get('Content-Length', 0))
                post_body = self.rfile.read(content_len)
                data = json.loads(post_body)

                # Ingestao (minima): o agente envia o bundle cifrado, seu
                # agent_uuid e as metricas quentes. O protocolo completo de
                # ingestao distribuida (fila, ack, lote) e da Fase 2 (W6).
                agent_uuid = data.get('agent_uuid', 'remote') if isinstance(data, dict) else 'remote'
                bundle = data.get('bundle', data) if isinstance(data, dict) else data
                metrics = data.get('metrics', {}) if isinstance(data, dict) else {}
                success = controller.db.insert_snapshot(bundle, agent_uuid=agent_uuid, metrics=metrics)

                if success:
                    controller.logger.info(f"[API] Received Snapshot from {data.get('agent_uuid', 'unknown')}")
                    self._set_headers(status=201, content_type="application/json")
                    self.wfile.write(b'{"status": "received"}')
                else:
                    self._set_headers(status=500, content_type="application/json")
                    self.wfile.write(b'{"status": "db_error"}')
            except Exception as e:
                controller.logger.error(f"[API] Error: {e}")
                self._set_headers(status=400)
                self.wfile.write(f'{{"status": "error", "msg": "{str(e)}"}}'.encode())
        else:
            self._set_headers(status=404)

    # --------------------------------------------------------------------------
    # HISTORICO E COMPARACAO
    # --------------------------------------------------------------------------
    def _pagina(self, titulo, corpo, voltar="/", refresh=0):
        """
        Moldura comum das telas auxiliares, na identidade do laudo.

        Titulo, subtitulo, versao e paleta sao os mesmos que o relatorio exibe,
        porque sao o mesmo produto: o analista transita entre as telas o tempo
        todo e nao deveria precisar reconhecer onde esta pela cor do fundo.

        PARAMETER refresh: segundos para recarregar sozinha; 0 desliga. So as
                           telas que acompanham algo em andamento usam.
        """
        atualiza = ("<meta http-equiv='refresh' content='%d'>" % refresh
                    ) if refresh else ""
        return ("<html><head><meta charset='UTF-8'><title>"
                "Sys-Inspector v%s | %s</title>{ATUALIZA}"
                "<style>%s"
                "table{width:100%%;border-collapse:separate;border-spacing:0 6px}"
                "th{text-align:left;color:#777;text-transform:uppercase;"
                "font-size:10px;padding:0 10px 8px}td{padding:8px 10px}"
                "tr.item{background:var(--drk)}"
                "a.btn{color:var(--cyn);text-decoration:none;"
                "border:1px solid var(--cyn);border-radius:4px;padding:5px 14px;"
                "font-size:12px}"
                "code{color:#ce9178;font-size:11px;word-break:break-all}"
                "h2{font-weight:300;margin:0 0 16px}</style></head><body>%s"
                "<div class='conteudo'>"
                "<a class='btn' href='%s'>&larr; Voltar</a>"
                "<h2 style='margin-top:16px'>%s</h2>%s</div></body></html>"
                % (__version__, titulo, _CSS_IDENTIDADE,
                   _cabecalho_identidade(_barra_navegacao(self.path.split("?")[0])),
                   voltar, titulo, corpo)).replace("{ATUALIZA}", atualiza)

    # Quantas capturas a linha do tempo percorre. Cada uma exige decifrar um
    # laudo inteiro, entao a janela e curta de proposito: cobre o passado
    # recente, que e onde a investigacao olha, sem transformar a abertura da
    # pagina em trabalho pesado no servidor.
    JANELA_TIMELINE = 12

    def _render_timeline(self, controller, capturas):
        """
        Comportamento ao longo do tempo, e nao o retrato de um instante.

        Uma captura responde "isto estava rodando". A pergunta que decide a
        resposta a um incidente e outra: "isto rodou UMA vez ou roda SEMPRE?".
        Um artefato que reaparece a cada poucos minutos tem persistencia ativa e
        vai voltar depois de morto; um que apareceu uma unica vez pode ter sido
        acao manual. Sao incidentes diferentes, com respostas diferentes, e a
        diferenca so aparece olhando varias capturas juntas.
        """
        recentes = list(reversed(capturas[:self.JANELA_TIMELINE]))
        if len(recentes) < 2:
            return ""

        payloads = []
        for c in recentes:
            dados = controller.decrypt(controller.db.get_snapshot_details(c["id"]))
            if dados:
                payloads.append(dados)

        linhas_tl = build_timeline(payloads)
        # So o que merece atencao: listar tudo que repete transformaria a tela
        # num inventario do sistema, e o ruido esconderia o sinal.
        linhas_tl = [r for r in linhas_tl if r["max_score"] > 0][:25]
        if not linhas_tl:
            return ""

        total = len(payloads)
        linhas = ""
        for r in linhas_tl:
            # Faixa visual: uma marca por captura em que o comando apareceu.
            faixa = ""
            presentes = set(r["captures"])
            for i in range(total):
                presente = i in presentes
                faixa += ("<span title='captura %d' style='display:inline-block;"
                          "width:11px;height:16px;margin-right:2px;background:%s;"
                          "border-radius:2px'></span>"
                          % (i + 1,
                             risk.color(r["max_score"]) if presente
                             else "#2a2a2a"))

            constante = r["count"] == total
            leitura = ("presente em TODAS as %d capturas" % total if constante
                       else "visto em %d de %d capturas" % (r["count"], total))

            linhas += ("<tr class='item'><td style='width:230px'>%s"
                       "<div style='color:#777;font-size:10px;margin-top:3px'>%s"
                       "</div></td>"
                       "<td style='width:170px'>%s</td>"
                       "<td><code>%s</code></td></tr>"
                       % (faixa, leitura, _selo_risco(r["max_score"]),
                          _esc(r["cmd"][:150])))

        # Sem cabecalho, as tres colunas (presenca, risco, comando) so se
        # identificavam por deducao, e a do meio era um numero solto.
        cabecalho = ("<thead><tr><th>Presenca nas capturas</th>"
                     "<th>Risco (maior observado)</th><th>Comando</th></tr>"
                     "</thead>")

        return ("<h3 style='font-weight:300;color:#4ec9b0;margin-bottom:2px'>"
                "Comportamento ao longo do tempo</h3>"
                "<p style='color:#777;font-size:11px;margin:0 0 10px'>"
                "As %d capturas mais recentes, da mais antiga (esquerda) para a "
                "mais nova (direita). Cada marca e uma captura em que o comando "
                "estava presente. Reaparecer sempre indica persistencia ativa: o "
                "artefato volta depois de morto. Aparecer uma vez so sugere acao "
                "pontual. Sao incidentes diferentes.</p>"
                "<table>%s<tbody>%s</tbody></table>"
                "<hr style='border:none;border-top:1px solid #2a2a2a;margin:26px 0'>"
                % (total, cabecalho, linhas))

    def _serve_history(self, controller, agent_uuid):
        """
        Capturas de um agente, para escolher duas e compara-las.

        Um laudo isolado responde como o host estava num instante. A pergunta
        que a investigacao faz e outra: o que mudou entre dois instantes.
        """
        capturas = controller.db.get_history(0, time.time(),
                                             agent_filter=agent_uuid)[:100]
        if not capturas:
            self._set_headers(status=404)
            self.wfile.write(b"No captures for this agent yet.")
            return

        linhas = ""
        for i, c in enumerate(capturas):
            # Compara com a captura imediatamente anterior, que e a comparacao
            # pedida na esmagadora maioria das vezes. As demais ficam a um
            # clique, escolhendo outra linha de partida.
            anterior = capturas[i + 1]["id"] if i + 1 < len(capturas) else None
            # Emoji no lugar da frase: o texto "comparar com a anterior" ocupava
            # uma coluna inteira para repetir em toda linha o que o cabecalho ja
            # diz uma vez. A explicacao continua acessivel no title.
            botao = ("<a class='btn' title='Comparar esta captura com a "
                     "imediatamente anterior (#%s)' "
                     "href='/diff/%s?a=%s&b=%s'>&#8646;</a>"
                     % (anterior, agent_uuid, anterior, c["id"])
                     ) if anterior else ("<span title='E a captura mais antiga "
                                         "guardada deste agente: nao ha anterior "
                                         "com que comparar' "
                                         "style='color:#555'>&mdash;</span>")

            idade = ("<span style='color:#666;font-size:10px'>%s</span>"
                     % _human_age(time.time() - float(c["timestamp"] or 0)))

            linhas += ("<tr class='item'><td style='color:#777;width:60px'>%s</td>"
                       "<td>%s<br>%s</td><td style='color:#888;width:70px'>%s%%</td>"
                       "<td style='width:170px'>%s</td>"
                       "<td style='width:70px'>%s</td></tr>"
                       % (c["id"], _fmt_ts(c["timestamp"]), idade,
                          round(c.get("cpu_avg") or 0, 1),
                          _selo_risco(c.get("alert_score")), botao))

        tabela = ("<p style='color:#777;font-size:12px'>%d capturas. "
                  "A comparacao roda no servidor: o laudo completo passa de "
                  "10MB e nao caberia no navegador.</p>"
                  "<table><thead><tr><th>Captura</th>"
                  "<th>Momento da coleta</th><th>CPU media</th>"
                  "<th>Risco (pior processo)</th><th>Comparar</th></tr></thead>"
                  "<tbody>%s</tbody></table>" % (len(capturas), linhas))

        barra = ("<div class='controles'>"
                 "<span class='rotulo'>Agente</span>%s"
                 "<span class='sep'>|</span>"
                 "<a class='btn' href='/timeline?min=360&agent=%s' "
                 "style='padding:3px 10px' title='Ver os eventos deste agente "
                 "em ordem, junto com os dos demais hosts'>&#128337; linha do "
                 "tempo deste agente</a>"
                 "<a class='btn' href='/agent/%s' style='padding:3px 10px;"
                 "margin-left:6px' title='Abrir o laudo da captura mais "
                 "recente'>&#128269; laudo atual</a>"
                 "<span style='margin-left:auto'>%s</span></div>"
                 % (_identifica_agente(
                     next((a for a in (controller.db.get_fleet_status() or [])
                           if a.get("uuid") == agent_uuid), None), agent_uuid),
                    agent_uuid, agent_uuid, _ajuda_risco()))

        corpo = barra + self._render_timeline(controller, capturas) + tabela
        self._set_headers()
        self.wfile.write(self._pagina("Historico do agente", corpo).encode("utf-8"))

    def _serve_diff(self, controller):
        """Mostra o que mudou entre duas capturas do mesmo agente."""
        caminho, _, consulta = self.path.partition("?")
        agent_uuid = caminho.strip("/").split("/")[-1]
        args = urlparse.parse_qs(consulta or "")

        try:
            id_a = int(args.get("a", [""])[0])
            id_b = int(args.get("b", [""])[0])
        except (ValueError, IndexError):
            self._set_headers(status=400)
            self.wfile.write(b"Informe as duas capturas a comparar.")
            return

        antes = controller.decrypt(controller.db.get_snapshot_details(id_a))
        depois = controller.decrypt(controller.db.get_snapshot_details(id_b))
        if not antes or not depois:
            self._set_headers(status=404)
            self.wfile.write(b"Capture not found or could not be decrypted.")
            return

        # Momento de cada captura: comparar "#467 com #469" nao diz nada sobre
        # o intervalo, e o intervalo e o que da sentido a diferenca.
        momentos = dict((c["id"], c["timestamp"]) for c in
                        controller.db.get_history(0, time.time(),
                                                  agent_filter=agent_uuid))
        ts_a = momentos.get(id_a)
        ts_b = momentos.get(id_b)

        resultado = diff_snapshots(antes, depois)
        resumo = resultado["summary"]

        # Linha de comando do pai, para responder "nasceu de onde". Um processo
        # novo importa menos por si do que por quem o criou: um shell nascido de
        # um servidor web nao e o mesmo que um shell nascido de um login.
        def _mapa_pais(payload):
            return dict((pr.get("pid"), pr.get("cmd") or "")
                        for pr in ((payload or {}).get("processes") or {}).values()
                        if isinstance(pr, dict))

        pais_depois = _mapa_pais(depois)
        pais_antes = _mapa_pais(antes)

        def _linha_proc(p, cor, pais=None):
            """
            Uma linha de processo com o que basta para julgar sem abrir o laudo.

            A primeira versao mostrava so o PID. Um numero sozinho nao diz nada:
            o analista precisava voltar ao relatorio completo para descobrir de
            que processo se tratava, e uma lista desses numeros nao e analise.
            Agora cada linha responde tres perguntas de imediato: o que e, se
            merece atencao e de onde veio.
            """
            selos = ""
            for nome_r, icone, explicacao in classify(p):
                selos += ("<span title='%s' style='margin-right:5px;"
                          "font-size:13px'>%s</span>" % (explicacao, icone))

            pai = (pais or {}).get(p.get("ppid"))
            origem = ""
            if pai:
                origem = ("<div style='color:#6a9955;font-size:11px'>"
                          "&#8627; criado por [%s] <code>%s</code></div>"
                          % (p.get("ppid"), _esc(pai[:110])))
            elif p.get("ppid"):
                origem = ("<div style='color:#a06;font-size:11px'>"
                          "&#8627; pai [%s] nao esta nesta captura: a origem se "
                          "perdeu</div>" % p.get("ppid"))

            conexoes = ""
            for c in (p.get("connections") or []):
                conexoes += ("<div style='color:#4ec9b0;font-size:11px'>"
                             "&#127760; %s</div>" % _esc(c))

            motivos = origem + conexoes
            for r in (p.get("reasons") or []):
                motivos += ("<div style='color:#a06; font-size:11px'>&bull; %s</div>"
                            % _esc(r))
            for campo, val in (p.get("changes") or {}).items():
                motivos += ("<div style='color:#7fb3d5;font-size:11px'>%s: "
                            "<code>%s</code> &rarr; <code>%s</code></div>"
                            % (_esc(campo), _esc(val["antes"]), _esc(val["depois"])))

            selo = _selo_risco(p.get("alert_score"))

            return ("<tr class='item'>"
                    "<td style='color:%s;font-weight:bold;width:70px'>%s</td>"
                    "<td style='width:110px'>%s</td>"
                    "<td style='color:#888;width:80px'>%s</td>"
                    "<td style='color:#888;width:70px'>%s</td>"
                    "<td><code>%s</code>%s</td>"
                    "<td style='width:150px;text-align:right'>%s</td></tr>"
                    % (cor, p.get("pid"), selos, _esc(p.get("user") or "-"),
                       _esc(p.get("duration") or "-"),
                       _esc(p.get("cmd") or "(sem linha de comando)"),
                       motivos, selo))

        def _secao(titulo, explicacao, itens, cor, render, pais=None):
            """
            Uma secao SEMPRE aparece, mesmo vazia.

            Omitir a secao sem itens deixava o analista sem saber se nada
            desapareceu ou se a tela nao trata desaparecimento. Numa ferramenta
            forense, "verifiquei e nao ha" e uma resposta diferente de silencio.
            """
            if itens:
                criticos = summarize_risk(itens)
                aviso = ("<p style='color:#ff4d4d;font-size:12px;margin:0 0 8px'>"
                         "&#128308; %d com risco alto.</p>" % criticos
                         ) if criticos else ""
                corpo = aviso + "<table><tbody>%s</tbody></table>" % "".join(
                    render(i, cor, pais) if pais is not None else render(i, cor)
                    for i in itens[:300])
                if len(itens) > 300:
                    corpo += ("<p style='color:#666;font-size:11px'>Exibindo 300 "
                              "de %d.</p>" % len(itens))
            else:
                corpo = ("<p style='color:#555;font-size:12px;padding:6px 10px'>"
                         "Nenhum.</p>")
            return ("<h3 style='font-weight:300;color:%s;margin-bottom:2px'>%s "
                    "<span style='color:#666'>(%d)</span></h3>"
                    "<p style='color:#777;font-size:11px;margin:0 0 8px'>%s</p>%s"
                    % (cor, titulo, len(itens), explicacao, corpo))

        def _linha_finding(f, cor):
            return ("<tr class='item'><td style='color:%s;width:110px'>%s</td>"
                    "<td style='width:90px;color:#888'>%s</td><td>%s</td></tr>"
                    % (cor, _esc(f.get("severity") or ""),
                       _esc(f.get("source") or ""),
                       _esc(f.get("title") or f.get("description") or "")))

        def _bloco(rotulo, valor, cor):
            return ("<div style='background:#252526;border-left:3px solid %s;"
                    "padding:10px 16px;min-width:120px'>"
                    "<div style='font-size:22px;color:%s'>%s</div>"
                    "<div style='color:#777;font-size:10px;text-transform:uppercase'>"
                    "%s</div></div>" % (cor, cor, valor, rotulo))

        cabecalho = (
            "<p style='color:#777;font-size:12px'>Captura #%s (%s) &rarr; #%s (%s)"
            "<br>%d processos antes, %d depois</p>"
            "<div style='display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 26px'>"
            "%s%s%s%s%s</div>"
            % (id_a, _fmt_ts(ts_a), id_b, _fmt_ts(ts_b),
               resumo["total_before"], resumo["total_after"],
               _bloco("achados novos", resumo["findings_new"], "#ff4d4d"),
               _bloco("apareceram", resumo["appeared"], "#ffd166"),
               _bloco("alterados", resumo["changed"], "#7fb3d5"),
               _bloco("sumiram", resumo["disappeared"], "#888"),
               _bloco("achados que sumiram", resumo["findings_gone"], "#666")))

        corpo = (cabecalho
                 + _secao("Achados novos",
                          "Apareceram na captura mais recente e nao existiam antes.",
                          resultado["findings"]["new"], "#ff4d4d", _linha_finding)
                 + _secao("Processos que apareceram",
                          "Nao existiam na captura anterior. Um processo novo com "
                          "risco alto e o ponto de partida usual da investigacao.",
                          resultado["processes"]["appeared"], "#ffd166",
                          _linha_proc, pais_depois)
                 + _secao("Processos alterados",
                          "Continuaram vivos, mas algo mudo neles: executavel, "
                          "dono, processo pai ou linha de comando. Uso de CPU e "
                          "memoria sao ignorados de proposito, porque oscilam a "
                          "cada ciclo e afogariam o que importa.",
                          resultado["processes"]["changed"], "#7fb3d5",
                          _linha_proc, pais_depois)
                 + _secao("Processos que sumiram",
                          "Existiam antes e nao existem mais. Importa tanto quanto "
                          "o que surgiu: pode ser o artefato que se apagou depois "
                          "de agir.",
                          resultado["processes"]["disappeared"], "#888",
                          _linha_proc, pais_antes)
                 + _secao("Achados que deixaram de aparecer",
                          "Sumir nao significa resolvido: o artefato pode ter sido "
                          "removido para encobrir rastro. O fato e relatado; a "
                          "conclusao cabe ao analista.",
                          resultado["findings"]["gone"], "#666", _linha_finding))

        self._set_headers()
        self.wfile.write(self._pagina("Comparacao de capturas", corpo,
                                      voltar="/history/%s" % agent_uuid
                                      ).encode("utf-8"))

    # Icone, cor e NOME de cada tipo de evento. Uma linha do tempo densa se le
    # por forma antes de se ler por texto; sem distincao visual ela vira
    # paragrafo. O nome existe para o filtro: um botao com so um icone obriga a
    # adivinhar o que ele filtra.
    ICONE_EVENTO = {
        "process.start": ("&#9679;", "#7fb3d5", "processo iniciou"),
        # circulo, nao "play": o triangulo sugeria botao clicavel e nao ha acao
        "process.end": ("&#9675;", "#666", "processo terminou"),
        "network.connect": ("&#127760;", "#4ec9b0", "conexao de rede"),
        "file.write": ("&#128221;", "#ffd166", "arquivo gravado"),
        "file.delete": ("&#128465;", "#ff8c42", "arquivo apagado"),
        "persistence.created": ("&#128204;", "#ffd166", "persistencia"),
        "finding.raised": ("&#9888;", "#ff4d4d", "achado"),
        "capture.taken": ("&#128248;", "#555", "captura"),
        "auth.session": ("&#128273;", "#c586c0", "sessao/autenticacao"),
        "command.executed": ("&#9881;", "#c586c0", "comando executado"),
    }

    def _serve_timeline(self, controller):
        """
        Tudo que aconteceu, em ordem, atravessando a frota.

        E o artefato central de uma pericia distribuida, e o unico que responde
        a pergunta que decide um laudo: o que veio ANTES. Cada captura, por mais
        completa, e um retrato; ordem nao e propriedade de retrato.

        A ordenacao usa o instante corrigido pelo desvio de relogio de cada
        host. Sem isso a sequencia entre maquinas sai plausivel e errada, que e
        pior que nao ter sequencia, porque parece resposta.
        """
        _, _, consulta = self.path.partition("?")
        args = urlparse.parse_qs(consulta or "")
        agente = (args.get("agent") or [None])[0]
        # A janela e de TEMPO, nao de contagem. Uma linha do tempo forense
        # responde "o que aconteceu neste intervalo", e limitar por quantidade
        # faz a janela encolher justamente quando ha mais atividade: com quatro
        # agentes, 300 eventos cobriam pouco mais de um minuto, de modo que um
        # cenario executado treze minutos antes ficava de fora e parecia nao ter
        # sido capturado.
        minutos = int((args.get("min") or ["60"])[0])
        limite = int((args.get("limit") or ["1500"])[0])
        desde = time.time() - (minutos * 60)
        # Tipos escolhidos pelo analista. Lista vazia significa "todos", e nao
        # "nenhum": a tela abre mostrando tudo.
        tipos = [t for t in (args.get("type") or []) if t]

        eventos = controller.events.timeline(inicio=desde, agent_uuid=agente,
                                             limit=limite)
        stats = controller.events.stats()

        # Contagem por tipo ANTES de filtrar, para o botao de cada tipo mostrar
        # quantos eventos ele traria de volta. Filtrar e escolher o que olhar; a
        # tela nao pode esconder que o resto existe.
        na_janela = {}
        for ev in eventos:
            na_janela[ev["type"]] = na_janela.get(ev["type"], 0) + 1
        total_janela = len(eventos)

        # A correlacao roda sobre a janela INTEIRA, nunca sobre o recorte visivel.
        # Ela existe para juntar sinais de tipos diferentes; alimenta-la com o
        # filtro de tela faria as conclusoes aparecerem e sumirem conforme o
        # analista escolhe o que olhar, e uma conclusao que depende do filtro nao
        # e conclusao.
        conclusoes = correlate(eventos)

        if tipos:
            eventos = [ev for ev in eventos if ev["type"] in tipos]

        nomes = {}
        for a in (controller.db.get_fleet_status() or []):
            nomes[a.get("uuid")] = a.get("hostname") or (a.get("uuid") or "")[:8]

        topo = ""
        if conclusoes:
            itens = ""
            for c in conclusoes[:10]:
                # A conclusao carrega severidade e tecnica; exibi-las aqui evita
                # que o analista precise abrir o laudo so para saber o peso e a
                # que tecnica a leitura corresponde.
                selos = ("<span style='background:%s;color:#000;"
                         "border-radius:3px;padding:1px 7px;font-size:10px;"
                         "font-weight:bold;margin-right:6px'>%s</span>"
                         % (risk.CORES.get(c.severity, "#888"), _esc(c.severity)))
                selos += _selo_attck(c.technique)
                itens += ("<div style='background:#2a1a1a;border-left:3px solid "
                          "#ff4d4d;padding:10px 14px;margin-bottom:8px'>"
                          "<div style='float:right'>%s</div>"
                          "<b style='color:#ff4d4d'>%s</b>"
                          "<div style='color:#bbb;font-size:12px;margin-top:4px'>%s</div>"
                          "<div style='color:#6a9955;font-size:11px;margin-top:6px'>"
                          "&#8627; %s</div></div>"
                          % (selos, _esc(c.title), _esc(c.description),
                             _esc(c.recommendation)))
            topo = ("<h3 style='font-weight:300;color:#ff4d4d;margin-bottom:2px'>"
                    "Leitura da sequencia</h3>"
                    "<p style='color:#777;font-size:11px;margin:0 0 10px'>"
                    "Sinais que isolados nao justificariam acao e que, juntos, "
                    "descrevem uma so coisa. Nenhuma destas afirmacoes conclui "
                    "comprometimento: dizem o que foi observado e o que "
                    "verificar.</p>%s<hr style='border:none;border-top:1px "
                    "solid #2a2a2a;margin:22px 0'>" % itens)

        linhas = ""
        anterior = None
        for ev in eventos:
            icone, cor, nome_tipo = self.ICONE_EVENTO.get(
                ev["type"], ("&#8226;", "#888", ev["type"]))
            # Data e hora completas, local e UTC, como no restante da ferramenta:
            # so "14:01:17" nao diz o dia e nao cruza com log de outro sistema,
            # que quase sempre esta em UTC.
            momento = _fmt_datahora(ev["corrected_ts"])

            # Intervalo desde o evento anterior: e o que transforma uma lista em
            # sequencia legivel. "4s depois" diz mais que dois horarios.
            delta = ""
            if anterior is not None:
                d = int(ev["corrected_ts"] - anterior)
                if d:
                    delta = ("<span style='color:#666;font-size:10px'>"
                             "+%ds</span>" % d)
            anterior = ev["corrected_ts"]

            desvio = ""
            if ev.get("clock_offset"):
                desvio = ("<span title='Relogio deste host desviava %ss; o "
                          "horario exibido ja esta corrigido' "
                          "style='color:#c586c0;font-size:10px'>&#9201;</span>"
                          % ev["clock_offset"])

            # RISCO do evento, que faltava por completo.
            #
            # Sem ele a linha do tempo dizia o que aconteceu e em que ordem, mas
            # nao dizia o que PESA: as vinte linhas de um processo banal e a do
            # binario apagado tinham exatamente a mesma aparencia, e o analista
            # precisava abrir a captura para descobrir qual era qual.
            detalhe = ev.get("detail") or {}
            if ev["type"] == "finding.raised":
                sev = ev.get("severity") or ""
                risco = (("<span style='background:%s;color:#000;"
                          "border-radius:3px;padding:1px 7px;font-size:10px;"
                          "font-weight:bold'>%s</span>")
                         % (risk.CORES.get(sev, "#888"), _esc(sev))) if sev else ""
            else:
                risco = _selo_risco(detalhe.get("score"))

            # QUEM executou e A PARTIR DE ONDE, sob a linha de comando. A
            # sequencia so vira reconstituicao quando cada passo diz de quem
            # partiu; ate aqui a coluna trazia a linha de comando sozinha, que
            # nao distingue um processo de root de um de usuario comum.
            contexto = ""
            if detalhe.get("user") or detalhe.get("pid"):
                partes = []
                if detalhe.get("user"):
                    partes.append("usuario <b>%s</b>" % _esc(detalhe["user"]))
                if detalhe.get("pid"):
                    partes.append("PID %s" % _esc(detalhe["pid"]))
                if detalhe.get("ppid"):
                    partes.append("filho de %s" % _esc(detalhe["ppid"]))
                contexto = ("<div style='color:#6a9955;font-size:10px'>%s</div>"
                            % " &middot; ".join(partes))
            if detalhe.get("signals"):
                contexto += ("<div style='color:#a06;font-size:10px'>&bull; %s"
                             "</div>" % _esc(detalhe["signals"]))
            if detalhe.get("target"):
                contexto += ("<div style='color:#888;font-size:10px'>"
                             "&#8627; <code>%s</code></div>"
                             % _esc(str(detalhe["target"])[:160]))

            # PIVO PARA A ARVORE. Um evento aponta um processo; a arvore mostra
            # de onde ele veio. O link abre a captura DE ONDE este evento saiu
            # (capture_id), e nao a mais recente: um processo efemero ja nao
            # existe na captura atual, e apontar a atual faria o pivo cair em
            # "nao esta nesta captura" quase sempre.
            pivo = ""
            if detalhe.get("pid") and ev.get("agent_uuid"):
                cap = ev.get("capture_id")
                destino = ("/agent/%s%s#pid=%s"
                           % (ev["agent_uuid"],
                              ("?capture=%s" % cap) if cap else "",
                              detalhe["pid"]))
                pivo = ("<a href='%s' title='Abrir este processo na arvore da "
                        "captura de onde este evento saiu. Se ainda assim ele "
                        "nao aparecer, a propria tela avisa.' "
                        "style='color:#4ec9b0;text-decoration:none;"
                        "font-size:13px'>&#8631;</a>" % destino)

            attck = _selo_attck(detalhe.get("technique"))

            linhas += ("<tr class='item'>"
                       "<td style='width:90px;color:#888'>%s %s</td>"
                       "<td style='width:30px;color:%s' title='%s'>%s</td>"
                       "<td style='width:130px;color:#4ec9b0;font-size:11px'>%s</td>"
                       "<td><code>%s</code>%s</td>"
                       "<td style='width:110px'>%s</td>"
                       "<td style='width:150px'>%s</td>"
                       "<td style='width:60px;text-align:right'>%s %s</td></tr>"
                       % (momento, delta, cor, _esc(nome_tipo), icone,
                          _esc(nomes.get(ev["agent_uuid"], ev["agent_uuid"][:8])),
                          _esc((ev.get("subject") or "")[:150]), contexto,
                          attck, risco, pivo, desvio))

        if not linhas:
            if tipos or agente:
                linhas = ("<tr><td colspan='7' style='color:#555;padding:30px;"
                          "text-align:center'>Nenhum evento com os filtros "
                          "ativos. Ha %d evento(s) nesta janela sem filtro "
                          "algum.</td></tr>" % total_janela)
            else:
                linhas = ("<tr><td colspan='7' style='color:#555;padding:30px;"
                          "text-align:center'>Nenhum evento nesta janela. A "
                          "linha do tempo e derivada das capturas conforme elas "
                          "chegam.</td></tr>")

        # ----------------------------------------------------------------------
        # FILTROS
        #
        # Todo filtro precisa ter volta. Os botoes anteriores so acrescentavam
        # criterio a URL: escolher um agente ou uma janela deixava o analista
        # dentro de um recorte sem nada na tela que o desfizesse, e a unica saida
        # era editar o endereco a mao. Um filtro sem retorno se confunde com
        # ausencia de dado, que numa ferramenta forense e a leitura mais cara de
        # todas.
        # ----------------------------------------------------------------------
        def _url(min_=None, agent=None, types=None):
            params = [("min", min_ if min_ is not None else minutos)]
            if agent:
                params.append(("agent", agent))
            for t in (types or []):
                params.append(("type", t))
            return "/timeline?" + urlparse.urlencode(params)

        atalhos = ""
        for m, rotulo in ((15, "15min"), (60, "1h"), (360, "6h"), (1440, "24h")):
            ativo = ("background:#333;" if m == minutos else "")
            atalhos += ("<a class='btn' href='%s' "
                        "style='margin-right:6px;padding:3px 10px;%s'>%s</a>"
                        % (_url(min_=m, agent=agente, types=tipos), ativo,
                           rotulo))

        # Chips de tipo: clicar liga, clicar de novo desliga. A contagem ao lado
        # mostra o que cada um traz de volta, para desligar um filtro nao ser um
        # salto no escuro.
        chips = ""
        for tipo, (icone, cor, nome) in sorted(self.ICONE_EVENTO.items(),
                                               key=lambda kv: kv[1][2]):
            quantos = na_janela.get(tipo, 0)
            ligado = tipo in tipos
            if ligado:
                destino = _url(agent=agente,
                               types=[t for t in tipos if t != tipo])
            else:
                destino = _url(agent=agente, types=tipos + [tipo])
            chips += ("<a href='%s' title='%s: %s' style='display:inline-block;"
                      "margin:0 6px 6px 0;padding:3px 9px;border-radius:12px;"
                      "font-size:11px;text-decoration:none;border:1px solid %s;"
                      "color:%s;background:%s'>%s %s <span style='color:#777'>"
                      "%d</span></a>"
                      % (destino, _esc(nome),
                         "clique para remover este filtro" if ligado
                         else "clique para ver so este tipo",
                         cor, "#000" if ligado else cor,
                         cor if ligado else "transparent",
                         icone, _esc(nome), quantos))

        limpar = ""
        if tipos or agente:
            ativos = []
            if agente:
                ativos.append("agente <b>%s</b>"
                              % _esc(nomes.get(agente, agente[:8])))
            if tipos:
                ativos.append("%d tipo(s) de evento" % len(tipos))
            limpar = ("<div style='background:#2a2a1a;border-left:3px solid "
                      "#ffd166;padding:8px 14px;margin:10px 0;font-size:11px;"
                      "color:#ffd166'>Filtrado por %s: exibindo %d de %d "
                      "evento(s) da janela. "
                      "<a class='btn' href='%s' style='margin-left:10px;"
                      "padding:2px 10px'>ver tudo</a></div>"
                      % (" e ".join(ativos), len(eventos), total_janela,
                         _url()))

        cabecalho_tabela = (
            "<thead><tr>"
            "<th title='Instante corrigido pelo desvio de relogio do host, "
            "para ser comparavel entre maquinas'>Hora</th>"
            "<th title='Natureza do evento; o icone repete o do filtro acima'>"
            "Tipo</th>"
            "<th>Agente</th>"
            "<th>O que aconteceu</th>"
            "<th title='Tecnica MITRE ATT&amp;CK associada, quando ha. Passe o "
            "mouse para o nome e a tatica.'>ATT&amp;CK</th>"
            "<th title='Nivel de risco e, ao lado, o numero cru do anomaly "
            "score. O numero e um campo de bits: cada bit e um sinal observado, "
            "nao uma magnitude. Veja o ? acima.'>Risco</th>"
            "<th title='A seta em espiral abre este processo na arvore da "
            "captura de onde o evento saiu; o relogio indica que a hora ja foi "
            "corrigida pelo desvio do host'>Arvore / relogio</th>"
            "</tr></thead>")

        # As duas barras no mesmo desenho da aba Processes do laudo, com a
        # ajuda no mesmo canto e na mesma forma.
        barras = ("<div class='controles'>"
                  "<span class='rotulo'>Janela</span>%s"
                  "<span class='sep'>|</span>"
                  "<span class='rotulo'>Tipo de evento</span>%s"
                  "<span style='margin-left:auto'>%s</span></div>%s"
                  % (atalhos, chips, _ajuda_risco(), limpar))

        corpo = (barras + topo
                 + "<p style='color:#777;font-size:12px'>%d eventos no total; "
                   "%d na janela de %d minuto(s), em ordem cronologica corrigida "
                   "pelo desvio de relogio de cada host. A correlacao acima "
                   "analisa exatamente esta janela. O simbolo &#8631; leva do "
                   "evento ao processo na arvore do laudo.</p>"
                   "<table>%s<tbody>%s</tbody></table>"
                   % (stats["total"], total_janela, minutos,
                      cabecalho_tabela, linhas))

        self._set_headers()
        self.wfile.write(self._pagina("Linha do tempo", corpo).encode("utf-8"))

    def _serve_capabilities(self, controller):
        """
        O que cada host consegue medir, e o que consegue exercitar.

        Existe para desfazer uma ambiguidade que ja custou caro: quando um
        agente acusa menos que outro, isso pode significar que a deteccao
        falhou OU que aquele host nunca teve como produzir o cenario. As duas
        situacoes sao opostas e produzem o mesmo resultado visivel, a ausencia.

        A tela responde antes de a pergunta ser feita, porque a alternativa e o
        analista deduzir, e deduzir errado aqui leva a tratar host saudavel
        como comprometido ou o contrario.
        """
        capacidades = controller.db.get_capabilities() or {}
        agentes = controller.db.get_fleet_status() or []

        linhas = ""
        for a in agentes:
            uuid = a.get("uuid") or ""
            caps = capacidades.get(uuid) or {}
            detectar = caps.get("detect") or {}
            faltando = missing_for_scenarios(caps)

            def _selo(ok, texto, titulo):
                cor = "#6bcB77" if ok else "#ff4d4d"
                return ("<span title='%s' style='border:1px solid %s;color:%s;"
                        "border-radius:3px;padding:1px 6px;font-size:10px;"
                        "margin-right:4px'>%s</span>"
                        % (_esc(titulo), cor, cor, texto))

            if not caps:
                deteccao = ("<span style='color:#777;font-size:11px'>ainda nao "
                            "reportou (agente anterior a esta versao)</span>")
            else:
                deteccao = (
                    _selo(detectar.get("ebpf"), "eBPF",
                          "Sem eBPF a captura se reduz ao que /proc mostra")
                    + _selo(detectar.get("btf"), "BTF",
                            "BTF no kernel permite o motor CO-RE")
                    + _selo(detectar.get("root"), "root",
                            "Sem privilegio o laudo sai incompleto sem erro aparente")
                    + _selo(detectar.get("cgroup_v2"), "cgroup2",
                            "Muda como conteiner e limite de recurso sao identificados"))

            if not caps:
                cenario = "-"
            elif faltando:
                cenario = ("<span style='color:#ffd166;font-size:11px'>limitado: "
                           "falta %s</span>" % _esc(", ".join(faltando)))
            else:
                cenario = ("<span style='color:#6bcB77;font-size:11px'>"
                           "completo</span>")

            linhas += ("<tr class='item'><td style='width:240px'>%s</td>"
                       "<td style='color:#888;font-size:11px'>%s"
                       "<div style='color:#666;font-size:10px'>%s</div></td>"
                       "<td>%s</td><td>%s</td></tr>"
                       % (_identifica_agente(a, uuid),
                          _esc(a.get("os_info") or "&mdash;"),
                          _esc(detectar.get("kernel") or "kernel nao reportado"),
                          deteccao, cenario))

        ajuda = _bolha_ajuda(
            "Duas perguntas diferentes",
            "<div style='color:#bbb;font-size:11px;margin-top:8px;"
            "line-height:1.6'>"
            "<b style='color:#4ec9b0'>Deteccao</b>: quanto vale um laudo "
            "produzido neste host. Sem eBPF a captura se reduz ao que /proc "
            "mostra; sem privilegio ela sai incompleta SEM erro aparente, que e "
            "o pior caso, porque o laudo parece integro.<br><br>"
            "<b style='color:#4ec9b0'>Cenario de teste</b>: o que a afericao "
            "pode cobrar deste host. Um agente com cenario limitado "
            "nao acusa menos por falha da ferramenta: ele "
            "nao tem como gerar o que falta.<br><br>"
            "As duas colunas existem porque as situacoes opostas "
            "&mdash; a deteccao falhou, ou nao havia o que detectar &mdash; "
            "produzem o mesmo resultado visivel: a ausencia. Sem esta tela, o "
            "analista deduz, e deduzir errado aqui leva a tratar host saudavel "
            "como comprometido, ou o contrario.</div>")

        corpo = ("<div class='controles'>"
                 "<span class='rotulo'>Capacidades da frota</span>"
                 "<span style='color:#777;font-size:11px'>%d agente(s). "
                 "Verde = disponivel; vermelho = ausente.</span>"
                 "<span style='margin-left:auto'>%s</span></div>"
                 "<table><thead><tr><th>Agente</th><th>Sistema</th>"
                 "<th>Deteccao</th><th>Cenario de teste</th></tr></thead>"
                 "<tbody>%s</tbody></table>" % (len(agentes), ajuda, linhas))

        self._set_headers()
        self.wfile.write(self._pagina("Capacidades da frota", corpo).encode("utf-8"))

    def _serve_queue(self, controller):
        """
        Situacao da fila de ingestao e ordem de atendimento dos agentes.

        A fila existe para o servidor nao ser derrubado por uma frota inteira
        reportando ao mesmo tempo. Numa investigacao, porem, um host importa
        mais que os outros: esta tela permite coloca-lo na frente sem parar a
        coleta dos demais.

        Numero MENOR e atendido primeiro; o padrao e 50, deixando espaco tanto
        para adiantar quanto para atrasar um agente.
        """
        stats = controller.queue.stats()
        agentes = controller.db.get_fleet_status() or []

        linhas = ""
        for a in agentes:
            uuid = a.get("uuid") or a.get("agent_uuid") or ""
            pendentes = (stats["by_agent"].get(uuid) or {}).get("pending", 0)
            prioridade = controller.queue.get_priority(uuid)

            botoes = ""
            for valor, rotulo, titulo in (
                    (10, "&#9650;", "Investigacao: atende este agente primeiro"),
                    (50, "&#9679;", "Padrao"),
                    (90, "&#9660;", "Baixa: atende depois dos demais")):
                ativo = ("background:#333;" if prioridade == valor else "")
                botoes += ("<a href='/priority/%s/%s' title='%s' class='btn' "
                           "style='margin-left:4px;padding:3px 8px;%s'>%s</a>"
                           % (uuid, valor, titulo, ativo, rotulo))

            linhas += ("<tr class='item'><td style='width:240px'>%s</td>"
                       "<td style='color:%s;font-weight:bold'>%s</td>"
                       "<td>%s</td><td>%s</td></tr>"
                       % (_identifica_agente(a, uuid),
                          "#ffd166" if pendentes else "#666", pendentes,
                          prioridade, botoes))

        ajuda = _bolha_ajuda(
            "O que esta fila faz",
            "<div style='color:#bbb;font-size:11px;margin-top:8px;"
            "line-height:1.6'>"
            "Toda captura passa por aqui antes de virar evidencia guardada, "
            "venha da rede ou da coleta local. A fila existe para o servidor "
            "nao ser derrubado por uma frota inteira reportando ao mesmo "
            "tempo.<br><br>"
            "Numa investigacao, porem, um host importa mais que os outros. A "
            "prioridade coloca esse host na frente sem parar a coleta dos "
            "demais: <b>numero MENOR e atendido primeiro</b>, e o padrao e 50, "
            "o que deixa espaco tanto para adiantar quanto para atrasar."
            "<br><br>Uma captura so e descartada da fila depois que o servidor "
            "CONFIRMA que ela esta guardada, e nao quando a recebe.</div>")

        # Os tres blocos respondem de imediato se a fila esta em dia. "0 na
        # fila" espalhado por quatro linhas nao responde isso.
        def _bloco(rotulo, valor, cor, titulo):
            return ("<div title='%s' style='background:var(--drk);"
                    "border-left:3px solid %s;padding:10px 16px;min-width:120px'>"
                    "<div style='font-size:22px;color:%s'>%s</div>"
                    "<div style='color:#777;font-size:10px;"
                    "text-transform:uppercase'>%s</div></div>"
                    % (_esc(titulo), cor, cor, valor, rotulo))

        painel = ("<div style='display:flex;gap:10px;flex-wrap:wrap;"
                  "margin:0 0 18px'>%s%s%s</div>"
                  % (_bloco("aguardando", stats["pending"],
                            "#ffd166" if stats["pending"] else "#666",
                            "Capturas recebidas e ainda nao gravadas"),
                     _bloco("processadas", stats["done"], "#6bcB77",
                            "Capturas ja gravadas como evidencia"),
                     _bloco("com falha", stats["failed"],
                            "#ff4d4d" if stats["failed"] else "#666",
                            "Capturas que nao puderam ser gravadas. Diferente "
                            "de zero aqui merece investigacao: e evidencia que "
                            "chegou e nao ficou.")))

        corpo = ("<div class='controles'>"
                 "<span class='rotulo'>Fila de ingestao</span>"
                 "<span style='color:#777;font-size:11px'>Numero menor e "
                 "atendido primeiro. O padrao e 50.</span>"
                 "<span style='margin-left:auto'>%s</span></div>%s"
                 "<table><thead><tr><th>Agente</th>"
                 "<th>Na fila</th><th>Prioridade</th><th>Ordem</th></tr></thead>"
                 "<tbody>%s</tbody></table>"
                 % (ajuda, painel, linhas))

        self._set_headers()
        self.wfile.write(self._pagina("Fila de ingestao", corpo).encode("utf-8"))

    def _serve_command_log(self, controller):
        """
        Registro de todos os pedidos feitos aos agentes.

        Uma acao pedida a distancia precisa deixar rastro auditavel: quem pediu,
        quando entrou na fila, quando o agente recolheu, quando terminou e qual
        foi o resultado. Sem isso nao ha como responder "esse comando chegou a
        rodar?", que foi exatamente a duvida que motivou esta tela.
        """
        commands = controller.commands
        commands.expire_stuck()
        registros = commands.list_for(limit=200)

        # Identidade legivel de cada agente, buscada uma vez.
        frota = {}
        for a in (controller.db.get_fleet_status() or []):
            frota[a.get("uuid")] = a

        cores = {"PENDING": "#7fb3d5", "SENT": "#ffd166",
                 "DONE": "#6bcB77", "FAILED": "#ff4d4d"}

        # O que cada acao faz, e a tecnica que ela exercita quando for o caso.
        # Sem isso "chaos" e uma palavra sem significado para quem nao escreveu
        # a ferramenta, e o registro de uma acao precisa dizer que acao foi.
        ACOES = {
            "collect": ("&#128248;", "Captura sob demanda: o agente coleta "
                        "agora, em vez de esperar o proximo ciclo.", ""),
            "chaos": ("&#9760;", "APENAS LAB: executa o cenario de teste, que "
                      "planta artefatos conhecidos para aferir a deteccao.",
                      "T1574.006"),
            "restart": ("&#128260;", "Reinicia o processo do agente no host "
                        "inspecionado.", ""),
        }

        linhas = ""
        for r in registros:
            cor = cores.get(r["status"], "#888")
            duracao = "-"
            if r.get("delivered_at") and r.get("finished_at"):
                duracao = "%ds" % int(r["finished_at"] - r["delivered_at"])
            espera = "-"
            if r.get("delivered_at"):
                espera = "%ds" % int(r["delivered_at"] - r["created_at"])

            icone, explicacao, tecnica = ACOES.get(
                r["command"], ("&#9881;", "Acao sem descricao nesta versao.", ""))
            acao = ("<span title='%s'>%s %s</span>%s"
                    % (_esc(explicacao), icone, _esc(r["command"]),
                       ("<div style='margin-top:3px'>%s</div>"
                        % _selo_attck(tecnica)) if tecnica else ""))

            # O RESULTADO deixa de ser texto solto e vira caminho: um comando
            # que produziu captura leva ao laudo, e todo comando leva ao
            # historico e a janela da linha do tempo em que ele aconteceu. Sem
            # isso, o registro diz que algo aconteceu e obriga o analista a
            # procurar o efeito em outra tela, a mao.
            resultado = _esc((r.get("result") or "")[:120]) or (
                "<span style='color:#555'>&mdash;</span>")
            atalhos = ""
            if r.get("agent_uuid"):
                quando = r.get("finished_at") or r.get("created_at") or 0
                # Janela centrada no comando, com folga para os dois lados: o
                # efeito de uma captura chega depois do comando terminar.
                minutos = max(15, int((time.time() - quando) / 60) + 5)
                atalhos = ("<div style='margin-top:4px'>"
                           "<a href='/agent/%s' title='Laudo mais recente deste "
                           "agente' style='color:#4ec9b0;text-decoration:none;"
                           "font-size:11px;margin-right:8px'>&#128269; laudo</a>"
                           "<a href='/history/%s' title='Capturas deste agente, "
                           "para achar a que este comando produziu' "
                           "style='color:#4ec9b0;text-decoration:none;"
                           "font-size:11px;margin-right:8px'>&#128337; "
                           "capturas</a>"
                           "<a href='/timeline?min=%d&agent=%s' title='Eventos "
                           "deste agente na janela que cobre este comando' "
                           "style='color:#4ec9b0;text-decoration:none;"
                           "font-size:11px'>&#8631; eventos</a></div>"
                           % (r["agent_uuid"], r["agent_uuid"], minutos,
                              r["agent_uuid"]))

            linhas += ("<tr class='item'>"
                       "<td style='color:#777;width:40px'>%s</td>"
                       "<td style='color:#4ec9b0;width:110px'>%s</td>"
                       "<td style='width:220px'>%s</td>"
                       "<td style='color:%s; font-weight:bold;width:80px'>%s</td>"
                       "<td style='width:160px;color:#aaa;font-size:11px'>%s</td>"
                       "<td style='width:60px'>%s</td>"
                       "<td style='width:60px'>%s</td>"
                       "<td style='color:#888;width:90px'>%s</td>"
                       "<td style='color:#aaa; font-size:11px'>%s%s</td></tr>"
                       % (r["id"], acao,
                          _identifica_agente(frota.get(r["agent_uuid"]),
                                             r["agent_uuid"]),
                          cor, r["status"], _fmt_datahora(r["created_at"]),
                          espera, duracao, r.get("requested_by") or "-",
                          resultado, atalhos))

        if not linhas:
            linhas = ("<tr><td colspan='9' style='color:#555; padding:30px; "
                      "text-align:center'>Nenhum pedido registrado.</td></tr>")

        ajuda = _bolha_ajuda(
            "Como ler este registro",
            "<div style='color:#bbb;font-size:11px;margin-top:8px;"
            "line-height:1.6'>"
            "<b style='color:#7fb3d5'>PENDING</b> o pedido esta na fila; o "
            "servidor NUNCA inicia conexao com o host inspecionado, quem busca "
            "e o agente.<br>"
            "<b style='color:#ffd166'>SENT</b> foi entregue ao agente. Entregue "
            "nao e aceito: o desfecho so se conhece quando ele reporta.<br>"
            "<b style='color:#6bcB77'>DONE</b> o agente reportou conclusao.<br>"
            "<b style='color:#ff4d4d'>FAILED</b> falhou, ou passou de %ds sem "
            "desfecho e foi encerrado como sem retorno.<br><br>"
            "<b>Espera</b> = tempo ate o agente recolher o pedido, limitado "
            "pelo ciclo dele. <b>Duracao</b> = tempo de execucao no agente."
            "<br><br>Os atalhos de cada linha levam ao efeito do comando: o "
            "laudo, a lista de capturas e a janela da linha do tempo que cobre "
            "aquele momento.</div>" % STUCK_LIMIT)

        corpo = ("<div class='controles'>"
                 "<span class='rotulo'>Registro de comandos</span>"
                 "<span style='color:#777;font-size:11px'>%d pedido(s), do mais "
                 "recente para o mais antigo. Recarrega sozinho a cada 15s."
                 "</span><span style='margin-left:auto'>%s</span></div>"
                 "<table><thead><tr><th>#</th><th>Acao</th><th>Agente</th>"
                 "<th>Estado</th><th>Pedido (local e UTC)</th><th>Espera</th>"
                 "<th>Duracao</th><th>Solicitante</th>"
                 "<th>Resultado e para onde ele leva</th></tr></thead><tbody>"
                 % (len(registros), ajuda)
                 + linhas + "</tbody></table>")
        # Esta era a ultima tela com folha de estilo propria, e por isso a unica
        # sem cabecalho, sem versao e sem a barra de navegacao.
        html = self._pagina("Registro de comandos", corpo, refresh=15)
        self._set_headers()
        self.wfile.write(html.encode("utf-8"))

    def _serve_dashboard(self, db, db_commands=None):
        """Renders the Server Manager Dashboard HTML."""
        # Envia a status line e os headers antes do corpo. Sem isto a resposta
        # sai sem cabecalho HTTP (o cliente ve conexao malformada / HTTP 000).
        self._set_headers()
        # Usa a tabela 'agents' (colunas em claro) via get_agents, em vez de
        # extrair campos com json_extract do blob, que agora esta cifrado.
        # Estado de RISCO da frota, nao apenas a lista de agentes: com
        # achados criticos acontecendo, o gerente precisa mostrar isso na
        # primeira tela, senao o analista so descobre entrando host a host.
        agents = db.get_fleet_status()

        def _risk(item):
            f = item.get('findings') or {}
            return (f.get('Critical', 0) * 1000 + f.get('High', 0) * 100
                    + f.get('Medium', 0) * 10 + f.get('Low', 0))

        # Mais comprometido primeiro: a ordem responde "por onde comeco?".
        agents = sorted(agents, key=_risk, reverse=True)

        rows = ""
        for a in agents:
            uuid = a.get('uuid', '')
            host = a.get('hostname') or "Unknown Host"
            ip = a.get('ip_address') or "Unknown IP"
            seen = a.get('last_seen', '')

            # last_seen vem do CURRENT_TIMESTAMP do SQLite, que e UTC. O resto
            # do laudo usa a hora local do host, e misturar fusos numa
            # ferramenta forense pode inverter a ordem dos eventos numa linha
            # do tempo. O horario e comparado em UTC e exibido com o fuso
            # explicito, para nao restar ambiguidade.
            try:
                last_ts = datetime.datetime.strptime(seen, "%Y-%m-%d %H:%M:%S")
                idade = (datetime.datetime.utcnow() - last_ts).total_seconds()
                is_online = idade < 90
                # A coluna mostra a hora LOCAL curta, que e a que o analista
                # compara com o relogio dele. O carimbo completo em UTC, que
                # nao pode faltar num laudo, vai em letra miuda junto do host.
                local = last_ts + (datetime.datetime.now() - datetime.datetime.utcnow())
                # Data e hora completas, local e UTC, no MESMO formato das
                # demais telas (linha do tempo, comandos, laudo). Antes esta
                # coluna mostrava so a hora local curta ("22:01:23"), que nao diz
                # o dia; a idade legivel ("35s ago") continua ao lado.
                local_epoch = local.timestamp()
                seen = ("%s<div style='color:#777;font-size:10px'>(%s)</div>"
                        % (_fmt_datahora(local_epoch), _human_age(idade)))
                seen_full = ""

                # Proximo contato esperado, a partir do ciclo que o proprio
                # agente informou. Substitui o timeout fixo de 90s, que marcava
                # como offline um agente saudavel de ciclo longo e demorava a
                # perceber a ausencia de um de ciclo curto.
                ciclo = int(a.get('cycle_seconds') or 0)
                if ciclo:
                    restante = ciclo - idade
                    # Atrasar um ciclo inteiro ainda e tolerado; dois ja indica
                    # que o agente parou de conversar.
                    is_online = idade < (ciclo * 2)
                    if restante > 0:
                        proximo = "em %s" % _human_age(restante).replace(" ago", "")
                        cor = "#6bcB77"
                    else:
                        proximo = "atrasado %s" % _human_age(-restante).replace(" ago", "")
                        cor = "#ffd166" if idade < ciclo * 2 else "#ff4d4d"
                    proximo_html = ("<div style='color:%s; font-size:11px'>%s</div>"
                                    "<div style='color:#777; font-size:10px'>ciclo %ss</div>"
                                    % (cor, proximo, ciclo))
                else:
                    proximo_html = "<span style='color:#555'>-</span>"
            except Exception:
                is_online = str(a.get('status', '')).upper() == 'ONLINE'
                seen_full = ""
                proximo_html = "<span style='color:#555'>-</span>"

            # Quantos pedidos aguardam este agente perguntar. Deixa claro que a
            # acao foi enfileirada e ainda nao executada: o servidor nao alcanca
            # o agente, quem busca e ele.
            # Estado do ultimo comando pedido. Sem isso o analista clica e nao
            # sabe se o agente ja pegou, se esta executando ou se terminou: a
            # acao vira um botao que aparentemente nao faz nada.
            aguardando = db_commands.pending_count(uuid) if db_commands else 0
            cmd_badge = ("<span class='cmd-badge' title='queued, waiting for the "
                         "agent to check in'>%d</span>" % aguardando) if aguardando else ""

            cmd_state = ""
            historico = db_commands.list_for(uuid, limit=1) if db_commands else []
            if historico:
                ultimo = historico[0]
                rotulos = {
                    "PENDING": ("aguardando o agente perguntar", "#7fb3d5"),
                    "SENT": ("em execucao no agente", "#ffd166"),
                    "DONE": ("concluido", "#6bcB77"),
                    "FAILED": ("falhou", "#ff4d4d"),
                }
                texto, cor = rotulos.get(ultimo["status"], (ultimo["status"], "#888"))
                detalhe = (ultimo.get("result") or "").strip()
                cmd_state = ("<div style='color:%s; font-size:10px; margin-top:3px'>"
                             "%s: %s</div>" % (cor, ultimo["command"], texto))
                if detalhe:
                    cmd_state += ("<div style='color:#666; font-size:10px'>%s</div>"
                                  % detalhe[:60])

            fqdn = a.get('fqdn') or ""
            # Mostra o FQDN so quando acrescenta informacao ao nome curto.
            fqdn_html = ("<br><small style='color:#777; font-family:monospace'>%s</small>"
                         % fqdn) if fqdn and fqdn != host else ""
            # O carimbo completo agora vive na coluna LAST SEEN; sob o host
            # ficam apenas os identificadores (UUID e FQDN).
            seen_html = ""

            # Contagem por severidade, vinda em claro com a captura.
            findings = a.get('findings') or {}
            sev_colors = {'Critical': '#ff4d4d', 'High': '#ff8c42',
                          'Medium': '#ffd166', 'Low': '#6bcB77'}
            sev_cells = ""
            for level, color in sev_colors.items():
                qty = findings.get(level, 0)
                style = (f"background:{color}; color:#1e1e1e; font-weight:bold"
                         if qty else "background:#2a2a2a; color:#555")
                sev_cells += (f"<td><span style='{style}; padding:2px 8px; "
                              f"border-radius:3px; font-size:11px'>{qty}</span></td>")

            # A borda da linha acompanha a pior severidade encontrada.
            worst = next((c for lv, c in sev_colors.items() if findings.get(lv)), None)
            risk_border = f"border-left: 4px solid {worst};" if worst else ""

            status_style = "color:#51cf66" if is_online else "color:#ff6b6b"
            status_text = "ONLINE" if is_online else "OFFLINE"
            border_style = risk_border or ("border-left: 4px solid #51cf66;" if is_online else "border-left: 4px solid #ff6b6b;")

            rows += f"""
            <tr style='background:#252526; border-bottom:1px solid #333; {border_style}'>
                <td>
                    <a href='/agent/{uuid}' style='color:#4ec9b0; font-size:1.1em; font-weight:bold; text-decoration:none;'>{host}</a>
                    <br><small style='color:#666; font-family:monospace'>{uuid}</small>
                    {fqdn_html}{seen_html}
                </td>
                <td style='color:#ccc'>{ip}</td>
                {sev_cells}
                <td style='color:#aaa'>{seen}</td>
                <td>{proximo_html}</td>
                <td><span style='{status_style}; font-weight:bold; font-size:11px; border:1px solid; padding:2px 6px; border-radius:3px'>{status_text}</span></td>
                <td style='white-space:nowrap'>
                    <a href='/agent/{uuid}' class='btn-ico' title='Open the forensic report'>&#128269;</a>
                    <a href='/history/{uuid}' class='btn-ico' title='Capturas anteriores deste agente e comparacao entre duas: mostra o que mudou de uma para a outra'>&#128337;</a>
                    <a href='/cmd/collect/{uuid}' class='btn-ico' title='Solicitar captura agora. Entra na fila e o agente executa no proximo check-in (ate ~1 ciclo); a captura leva o tempo configurado (capture_duration)'>&#128248;</a>
                    <a href='/cmd/chaos/{uuid}' class='btn-ico btn-lab' title='APENAS LAB: gera cenario de teste por 300s e captura em seguida. Entra na fila; o agente executa no proximo check-in'>&#9760;</a>
                    <a href='/cmd/restart/{uuid}' class='btn-ico btn-warn' title='Restart the agent (queued)'>&#128260;</a>
                    {cmd_badge}
                    {cmd_state}
                </td>
            </tr>"""

        cabecalho = _cabecalho_identidade(
            _barra_navegacao("/")
            + ("<div style='margin-top:6px'>%d agente(s)</div>" % len(agents)))

        html = f"""
        <html><head><meta charset="UTF-8">
        <title>Sys-Inspector v{__version__} | Manager</title>
        <meta http-equiv="refresh" content="30">
        <style>
            {_CSS_IDENTIDADE}
            table {{ width: 90%; margin: 30px auto; border-collapse: separate; border-spacing: 0 10px; }}
            th {{ text-align: left; color: #777; text-transform: uppercase; font-size: 0.85em; padding: 0 15px 10px 15px; letter-spacing: 1px; }}
            td {{ padding: 15px; }}
            tr {{ transition: transform 0.2s; }}
            tr:hover {{ transform: scale(1.01); background: #2a2d2e !important; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }}
            .btn-view {{ background: #333; color: #fff; text-decoration: none; padding: 6px 12px; font-size: 10px; border-radius: 3px; border: 1px solid #555; transition:0.2s; }}
            .btn-ico {{ display:inline-block; text-decoration:none; font-size:15px; padding:3px 6px; border:1px solid #444; border-radius:4px; margin-right:3px; filter:grayscale(35%); }}
            .btn-ico:hover {{ border-color:var(--acc); background:#2a2d2e; filter:none; }}
            .btn-lab:hover {{ border-color:#ff8c42; }}
            .btn-warn:hover {{ border-color:var(--red); }}
            .cmd-badge {{ background:var(--acc); color:#fff; font-size:10px; padding:1px 7px; border-radius:8px; margin-left:4px; }}
            .btn-view:hover {{ background: #0078d4; border-color: #0078d4; }}
        </style>
        </head><body>
        {cabecalho}
        <table>
            <thead><tr><th>Hostname / UUID</th><th>IP Address</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Last Seen</th><th>Next</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
        </body></html>
        """
        self.wfile.write(html.encode('utf-8'))


class ServerController:
    """
    Orchestrates the Server Mode.
    """
    def __init__(self, config, db_handler, shutdown_event):
        self.config = config
        self.db = db_handler
        self.shutdown_event = shutdown_event
        self.logger = logging.getLogger("ServerCtrl")

        # Fila de ingestao: TODA captura passa por ela antes de virar evidencia
        # guardada, venha da rede ou da coleta local. Um so mecanismo para os
        # modos server e live.
        self.queue = IngestQueue(config['storage']['sqlite_path'])
        # Fila de comandos: o analista pede, o AGENTE recolhe quando fala com o
        # servidor. O servidor nunca inicia conexao com o host inspecionado.
        self.commands = CommandQueue(config['storage']['sqlite_path'])

        # Aviso ativo. Desligado por padrao: um alerta que sai sem alguem ter
        # pedido e um vazamento, nao uma comodidade.
        self.notifier = Notifier(config)
        # Linha do tempo, ao lado das capturas e no mesmo banco.
        self.events = EventStore(config['storage']['sqlite_path'])
        rede = config.get('network', {}) or {}
        self.public_url = (rede.get('public_url')
                           or "https://%s:%s" % (rede.get('bind_address', 'localhost'),
                                                 rede.get('bind_port', 8080)))
        if self.notifier.enabled:
            self.logger.info("[NOTIFY] Alerts enabled from severity %s",
                             self.notifier.min_severity)
        self.ingest_token = (config.get('server', {}) or {}).get('auth_token', '') or ''
        if not self.ingest_token:
            self.logger.warning(
                "[INGEST] No auth_token configured: ingestion is OPEN. Set "
                "server.auth_token before using this outside a lab.")

        # Modelo unico cifrado: para renderizar o snapshot de um agente, o
        # server descriptografa com a chave privada local, se presente. Num
        # cenario zero-knowledge a chave pode nao existir aqui (o analista
        # descriptografa noutro ponto); nesse caso o view avisa.
        self.priv_key = None
        priv_path = config.get('security', {}).get('private_key_path', 'conf/private_key.pem')
        if os.path.exists(priv_path):
            try:
                self.priv_key = load_private_key(priv_path)
            except Exception as e:
                self.logger.error(f"[SECURITY] Failed to load Private Key: {e}")
        else:
            self.logger.warning("[SECURITY] Private Key not found; agent snapshots cannot be rendered here.")

    def decrypt(self, bundle):
        """Descriptografa um bundle cifrado; retorna dict em claro ou None."""
        if not self.priv_key or not bundle:
            return None
        try:
            return decrypt_data(bundle, self.priv_key)
        except Exception as e:
            self.logger.error(f"[SECURITY] Decryption failed: {e}")
            return None

    def _wrap_tls(self, server):
        """
        Protege a porta do servidor com TLS, gerando um certificado
        autoassinado se ainda nao houver um.

        As capturas ja viajam cifradas com a chave do analista, mas o TLS
        protege o que esta ao redor: o token de ingestao, os metadados em claro
        (hostname, endereco, contagem de achados) e o proprio painel, que
        expoe a situacao da frota. Sem ele, tudo isso trafega legivel na rede.

        Autoassinado e o padrao para nao exigir uma PKI antes do primeiro uso;
        num ambiente com CA propria basta apontar cert e key na configuracao.
        """
        srv_cfg = self.config.get('server', {}) or {}
        cert = srv_cfg.get('ssl_cert', '/etc/sys-inspector/server_cert.pem')
        key = srv_cfg.get('ssl_key', '/etc/sys-inspector/server_key.pem')

        try:
            ensure_self_signed_cert(cert, key)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=cert, keyfile=key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            self.logger.info("[HTTPS] TLS enabled using %s", cert)
            return True
        except Exception as exc:
            # Falhar aqui nao pode deixar o servidor mudo: ele volta a HTTP e
            # avisa, para o operador decidir, em vez de simplesmente sumir.
            self.logger.error("[HTTPS] Could not enable TLS (%s); serving plain HTTP", exc)
            return False

    def run(self):
        """Starts the Server HTTP Daemon."""
        port = self.config['network']['bind_port']

        server = ThreadingHTTPServer(('0.0.0.0', port), ServerHTTPHandler)
        server.controller = self

        # TLS opcional, desligado por padrao para nao quebrar instalacoes que
        # ja apontam agentes para HTTP.
        scheme = "http"
        if bool(self.config.get('network', {}).get('tls_enabled', False)):
            if self._wrap_tls(server):
                scheme = "https"
        self.scheme = scheme

        t_server = threading.Thread(target=server.serve_forever)
        t_server.daemon = True
        t_server.start()

        # Processador da fila: drena para o armazenamento definitivo em ritmo
        # proprio, para uma rajada de entregas nao bloquear quem esta recebendo.
        # A retencao roda no MESMO laco da ingestao, logo apos gravar: e o
        # unico momento em que se sabe que a captura ja esta salva. Aplica-la em
        # paralelo arriscaria remover algo que ainda estava a caminho do disco.
        politica = RetentionPolicy(self.db.db_path, self.config)
        if politica.preserves_everything:
            self.logger.warning(
                "[RETENTION] Modo forense: nada sera apagado. O disco cresce "
                "sem limite, e essa e a escolha correta para investigacao.")
        else:
            self.logger.info("[RETENTION] Modo seguranca: payload mantido por "
                             "%dd, teto de %dMB, %d por agente. A cadeia de "
                             "custodia e preservada por lapide.",
                             politica.max_age_days, politica.max_total_mb,
                             politica.max_per_agent)

        def _registrar_eventos(snap_id, agent_uuid, payload):
            """
            Deriva a linha do tempo da captura recem-gravada.

            Acontece na ingestao porque e o unico momento em que o servidor ja
            tem a chave e o dado junto; derivar sob demanda obrigaria a
            decifrar tudo de novo a cada abertura da tela.
            """
            dados = self.decrypt(payload.get("bundle"))
            if not dados:
                return
            desvio = float((payload.get("host") or {}).get("clock_offset", 0.0))
            n = self.events.add(events_from_capture(dados, agent_uuid,
                                                    snap_id, desvio))
            if n:
                self.logger.debug("[EVENTS] %d event(s) from capture %s",
                                  n, snap_id)

        def _drain():
            ciclos = 0
            while not self.shutdown_event.is_set():
                try:
                    done = process_batch(self.queue, self.db,
                                         on_stored=_registrar_eventos)
                    if done:
                        self.logger.info("[INGEST] %d capture(s) stored from the queue", done)
                except Exception as e:
                    self.logger.error(f"[INGEST] Queue processing error: {e}")

                # Nao a cada volta: varrer o banco a cada 3s custaria mais que o
                # espaco que economiza.
                ciclos += 1
                if ciclos % 100 == 0:
                    try:
                        r = politica.apply()
                        if r.get("purged"):
                            self.logger.info(
                                "[RETENTION] %d capture(s) purged (chain kept "
                                "by tombstone)", r["purged"])
                    except Exception as e:
                        self.logger.error("[RETENTION] Failed: %s", e)

                self.shutdown_event.wait(3)

        t_queue = threading.Thread(target=_drain)
        t_queue.daemon = True
        t_queue.start()

        self.logger.info(f"[HTTP] Server Manager listening on port {port} ({scheme})")
        self.logger.info(f"[INFO] Dashboard available at {scheme}://<server-ip>:{port}")

        try:
            while not self.shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.logger.info("[MODE] Stopping Server...")
            server.shutdown()
