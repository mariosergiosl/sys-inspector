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
from src.core.commands import CommandQueue, ALLOWED
from src.core.tls import ensure_self_signed_cert
from src.core.outbox import PATH_SLOT, PATH_INGEST, PATH_COMMAND_RESULT
from src.core.snapshot_diff import (diff_snapshots, has_changes, classify,
                                    summarize_risk, build_timeline)
from src.exporters.html_report import _esc



def _fmt_ts(valor):
    """
    Momento da captura em hora local, com o carimbo UTC ao lado.

    As duas formas juntas porque servem a leitores diferentes: o analista compara
    com o proprio relogio, e o laudo precisa de referencia absoluta.
    """
    try:
        momento = datetime.datetime.fromtimestamp(float(valor))
    except (TypeError, ValueError):
        return "-"
    return ("%s <span style='color:#666;font-size:10px'>%s UTC</span>"
            % (momento.strftime("%Y-%m-%d %H:%M:%S"),
               datetime.datetime.utcfromtimestamp(float(valor)
                                                  ).strftime("%H:%M:%S")))


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
            self._serve_command_log(controller.commands)

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
            agent_uuid = self.path.split('/')[-1]
            # Get latest snapshot for this agent
            snaps = controller.db.get_history(0, time.time(), agent_filter=agent_uuid)

            if snaps:
                # get_snapshot_details devolve o bundle cifrado; descriptografa.
                data = controller.decrypt(controller.db.get_snapshot_details(snaps[0]['id']))
                if data:
                    tree = self._rehydrate_tree(data)

                    # Generate HTML
                    tmp_filename = f"/tmp/sys_server_{threading.get_ident()}.html"
                    # Use version to get new Icons/CSS
                    generate_report(data, tree, tmp_filename, "0.61.00")

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

                    back = (
                        "<div style=\"background:#1a1a1a; border-bottom:1px solid #333; "
                        "padding:8px 20px; display:flex; align-items:center\">"
                        "<a href=\"/\" style=\"color:#4ec9b0; border:1px solid #4ec9b0; "
                        "border-radius:4px; padding:5px 14px; font-size:12px; "
                        "font-family:sans-serif; text-decoration:none\">"
                        "&larr; Fleet</a>"
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
    def _pagina(self, titulo, corpo, voltar="/"):
        """Moldura comum das telas auxiliares, no mesmo tema do painel."""
        return ("<html><head><meta charset='UTF-8'><title>%s</title>"
                "<style>body{background:#121212;color:#e0e0e0;"
                "font-family:'Segoe UI',sans-serif;padding:30px}"
                "table{width:100%%;border-collapse:separate;border-spacing:0 6px}"
                "th{text-align:left;color:#777;text-transform:uppercase;"
                "font-size:10px;padding:0 10px 8px}td{padding:8px 10px}"
                "tr.item{background:#252526}"
                "a.btn{color:#4ec9b0;text-decoration:none;border:1px solid #4ec9b0;"
                "border-radius:4px;padding:5px 14px;font-size:12px}"
                "code{color:#ce9178;font-size:11px;word-break:break-all}"
                "h2{font-weight:300}</style></head><body>"
                "<a class='btn' href='%s'>&larr; Voltar</a>"
                "<h2>%s</h2>%s</body></html>" % (titulo, voltar, titulo, corpo))

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
                             ("#ff4d4d" if r["max_score"] >= 70 else "#ffd166")
                             if presente else "#2a2a2a"))

            constante = r["count"] == total
            leitura = ("presente em TODAS as %d capturas" % total if constante
                       else "visto em %d de %d capturas" % (r["count"], total))

            linhas += ("<tr class='item'><td style='width:230px'>%s"
                       "<div style='color:#777;font-size:10px;margin-top:3px'>%s"
                       "</div></td>"
                       "<td style='width:60px;text-align:center;color:%s;"
                       "font-weight:bold'>%s</td>"
                       "<td><code>%s</code></td></tr>"
                       % (faixa, leitura,
                          "#ff4d4d" if r["max_score"] >= 70 else "#ffd166",
                          r["max_score"], _esc(r["cmd"][:150])))

        return ("<h3 style='font-weight:300;color:#4ec9b0;margin-bottom:2px'>"
                "Comportamento ao longo do tempo</h3>"
                "<p style='color:#777;font-size:11px;margin:0 0 10px'>"
                "As %d capturas mais recentes, da mais antiga (esquerda) para a "
                "mais nova (direita). Cada marca e uma captura em que o comando "
                "estava presente. Reaparecer sempre indica persistencia ativa: o "
                "artefato volta depois de morto. Aparecer uma vez so sugere acao "
                "pontual. Sao incidentes diferentes.</p>"
                "<table><tbody>%s</tbody></table>"
                "<hr style='border:none;border-top:1px solid #2a2a2a;margin:26px 0'>"
                % (total, linhas))

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
            botao = ("<a class='btn' href='/diff/%s?a=%s&b=%s'>comparar com a "
                     "anterior</a>" % (agent_uuid, anterior, c["id"])
                     ) if anterior else "<span style='color:#555'>primeira</span>"
            linhas += ("<tr class='item'><td style='color:#777'>%s</td>"
                       "<td>%s</td><td style='color:#888'>%s%%</td>"
                       "<td style='color:%s'>%s</td><td>%s</td></tr>"
                       % (c["id"], _fmt_ts(c["timestamp"]),
                          round(c.get("cpu_avg") or 0, 1),
                          "#ff4d4d" if c.get("is_alert") else "#6bcB77",
                          c.get("alert_score") or 0, botao))

        corpo = (self._render_timeline(controller, capturas)
                 + "<p style='color:#777;font-size:12px'>%d capturas. "
                 "A comparacao roda no servidor: o laudo completo passa de 10MB "
                 "e nao caberia no navegador.</p>"
                 "<table><thead><tr><th>#</th><th>Momento</th><th>CPU</th>"
                 "<th>Risco</th><th></th></tr></thead><tbody>%s</tbody></table>"
                 % (len(capturas), linhas))
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

            risco = p.get("alert_score") or 0
            selo = ("<span style='background:%s;color:#000;border-radius:3px;"
                    "padding:1px 6px;font-size:10px;font-weight:bold'>%s</span>"
                    % ("#ff4d4d" if risco >= 70 else
                       "#ffd166" if risco >= 30 else "#444", risco)) if risco else ""

            return ("<tr class='item'>"
                    "<td style='color:%s;font-weight:bold;width:70px'>%s</td>"
                    "<td style='width:110px'>%s</td>"
                    "<td style='color:#888;width:80px'>%s</td>"
                    "<td style='color:#888;width:70px'>%s</td>"
                    "<td><code>%s</code>%s</td>"
                    "<td style='width:60px;text-align:right'>%s</td></tr>"
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

            linhas += ("<tr class='item'><td><b>%s</b>"
                       "<div style='color:#666;font-size:10px'>%s</div></td>"
                       "<td style='color:#888;font-size:11px'>%s</td>"
                       "<td>%s</td><td>%s</td></tr>"
                       % (_esc(a.get("hostname") or "?"),
                          _esc(detectar.get("kernel") or ""),
                          _esc(a.get("os_info") or ""), deteccao, cenario))

        corpo = ("<p style='color:#777;font-size:12px'>Duas perguntas "
                 "diferentes. <b>Deteccao</b>: quanto vale um laudo produzido "
                 "neste host. <b>Cenario</b>: o que a afericao pode cobrar "
                 "dele.<br>Um agente com cenario limitado nao acusa menos por "
                 "falha da ferramenta: ele nao tem como gerar o que falta.</p>"
                 "<table><thead><tr><th>Agente</th><th>Sistema</th>"
                 "<th>Deteccao</th><th>Cenario de teste</th></tr></thead>"
                 "<tbody>%s</tbody></table>" % linhas)

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

            linhas += ("<tr class='item'><td>%s</td>"
                       "<td style='color:#666;font-family:monospace;font-size:10px'>%s</td>"
                       "<td style='color:%s;font-weight:bold'>%s</td>"
                       "<td>%s</td><td>%s</td></tr>"
                       % (_esc(a.get("hostname") or "?"), _esc(uuid[:8]),
                          "#ffd166" if pendentes else "#666", pendentes,
                          prioridade, botoes))

        corpo = ("<p style='color:#777;font-size:12px'>Aguardando: <b>%d</b> "
                 "&nbsp;|&nbsp; processadas: %d &nbsp;|&nbsp; com falha: %d<br>"
                 "Numero menor e atendido primeiro. O padrao e 50.</p>"
                 "<table><thead><tr><th>Agente</th><th>UUID</th>"
                 "<th>Na fila</th><th>Prioridade</th><th>Ordem</th></tr></thead>"
                 "<tbody>%s</tbody></table>"
                 % (stats["pending"], stats["done"], stats["failed"], linhas))

        self._set_headers()
        self.wfile.write(self._pagina("Fila de ingestao", corpo).encode("utf-8"))

    def _serve_command_log(self, commands):
        """
        Registro de todos os pedidos feitos aos agentes.

        Uma acao pedida a distancia precisa deixar rastro auditavel: quem pediu,
        quando entrou na fila, quando o agente recolheu, quando terminou e qual
        foi o resultado. Sem isso nao ha como responder "esse comando chegou a
        rodar?", que foi exatamente a duvida que motivou esta tela.
        """
        commands.expire_stuck()
        registros = commands.list_for(limit=200)

        cores = {"PENDING": "#7fb3d5", "SENT": "#ffd166",
                 "DONE": "#6bcB77", "FAILED": "#ff4d4d"}

        def _hora(valor):
            if not valor:
                return "-"
            return datetime.datetime.fromtimestamp(valor).strftime("%H:%M:%S")

        linhas = ""
        for r in registros:
            cor = cores.get(r["status"], "#888")
            duracao = "-"
            if r.get("delivered_at") and r.get("finished_at"):
                duracao = "%ds" % int(r["finished_at"] - r["delivered_at"])
            espera = "-"
            if r.get("delivered_at"):
                espera = "%ds" % int(r["delivered_at"] - r["created_at"])
            linhas += ("<tr style='background:#252526; border-bottom:1px solid #333'>"
                       "<td style='color:#777'>%s</td>"
                       "<td style='color:#4ec9b0'>%s</td>"
                       "<td style='font-family:monospace; font-size:11px; color:#999'>%s</td>"
                       "<td style='color:%s; font-weight:bold'>%s</td>"
                       "<td>%s</td><td>%s</td><td>%s</td>"
                       "<td style='color:#888'>%s</td>"
                       "<td style='color:#aaa; font-size:11px'>%s</td></tr>"
                       % (r["id"], r["command"], (r["agent_uuid"] or "")[:8],
                          cor, r["status"], _hora(r["created_at"]),
                          espera, duracao, r.get("requested_by") or "-",
                          (r.get("result") or "")[:90]))

        if not linhas:
            linhas = ("<tr><td colspan='9' style='color:#555; padding:30px; "
                      "text-align:center'>Nenhum pedido registrado.</td></tr>")

        html = ("<html><head><meta charset='UTF-8'><title>Command log</title>"
                "<meta http-equiv='refresh' content='15'>"
                "<style>body{background:#121212;color:#e0e0e0;"
                "font-family:'Segoe UI',sans-serif;padding:30px}"
                "table{width:100%;border-collapse:separate;border-spacing:0 6px}"
                "th{text-align:left;color:#777;text-transform:uppercase;"
                "font-size:10px;padding:0 10px 8px}td{padding:8px 10px}"
                "a{color:#4ec9b0;text-decoration:none;border:1px solid #4ec9b0;"
                "border-radius:4px;padding:5px 14px;font-size:12px}</style></head>"
                "<body><a href='/'>&larr; Fleet</a>"
                "<h2 style='font-weight:300'>Command log</h2>"
                "<p style='color:#777;font-size:12px'>Espera = tempo ate o agente "
                "recolher o pedido. Duracao = tempo de execucao no agente.</p>"
                "<table><thead><tr><th>#</th><th>Acao</th><th>Agente</th>"
                "<th>Estado</th><th>Pedido</th><th>Espera</th><th>Duracao</th>"
                "<th>Solicitante</th><th>Resultado</th></tr></thead><tbody>"
                + linhas + "</tbody></table></body></html>")
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
                # Os dois formatos ficam juntos na coluna: a hora local, que o
                # analista compara com o relogio dele, e o carimbo absoluto em
                # UTC, que um laudo exige. Em duas linhas e letra pequena para
                # nao roubar largura das colunas de severidade.
                seen = ("<div style='font-size:12px'>%s</div>"
                        "<div style='color:#777; font-size:10px; font-family:monospace'>"
                        "%s UTC (%s)</div>"
                        % (local.strftime("%H:%M:%S"),
                           last_ts.strftime("%Y-%m-%d %H:%M:%S"),
                           _human_age(idade)))
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

        html = f"""
        <html><head><title>Sys-Inspector Manager</title>
        <meta http-equiv="refresh" content="30">
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #1e1e1e; color: #eee; padding: 0; margin: 0; }}
            .header {{ background: #2d2d30; padding: 15px 30px; border-bottom: 2px solid #0078d4; display: flex; align-items: center; justify-content: space-between; }}
            h1 {{ margin: 0; font-weight: 300; letter-spacing: 1px; }}
            table {{ width: 90%; margin: 40px auto; border-collapse: separate; border-spacing: 0 10px; }}
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
        <div class="header">
            <h1>Sys-Inspector <span style="color:#0078d4; font-weight:bold">Manager</span></h1>
            <div style="font-size:0.9em; color:#aaa; font-weight:bold">
                <a href="/log" style="color:#4ec9b0; text-decoration:none; border:1px solid #444; border-radius:4px; padding:4px 10px; margin-right:12px; font-size:11px">&#128220; Command log</a>
                <a href="/queue" style="color:#4ec9b0; text-decoration:none; border:1px solid #444; border-radius:4px; padding:4px 10px; margin-right:12px; font-size:11px">&#128203; Fila</a>
                <a href="/capabilities" style="color:#4ec9b0; text-decoration:none; border:1px solid #444; border-radius:4px; padding:4px 10px; margin-right:12px; font-size:11px">&#129513; Capacidades</a>
                {len(agents)} AGENTS</div>
        </div>
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

        def _drain():
            ciclos = 0
            while not self.shutdown_event.is_set():
                try:
                    done = process_batch(self.queue, self.db)
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
