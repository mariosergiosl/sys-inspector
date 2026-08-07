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
# VERSION: v0.90.16
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

# Internal Modules
from src.exporters.html_report import generate_report
from src.collectors.process_tree import ProcessTree, ProcessNode
from src.core.crypto import load_private_key, decrypt_data
from src.core.ingest import IngestQueue, process_batch
from src.core.commands import CommandQueue, ALLOWED
from src.core.tls import ensure_self_signed_cert
from src.core.outbox import PATH_SLOT, PATH_INGEST, PATH_COMMAND_RESULT



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
                        + _acao("collect", "&#128248;",
                                "Request a capture now (queued; the agent picks it "
                                "up on its next check-in)")
                        + _acao("chaos", "&#9760;",
                                "LAB ONLY: run the chaos generator and capture")
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
                # Identidade do host chega tambem no check-in, para um agente
                # ocioso continuar aparecendo corretamente na frota.
                host = data.get('host') or {}
                if host:
                    controller.db.update_agent_status(
                        agent_uuid, "ONLINE", hostname=host.get("hostname"),
                        ip=host.get("ip_address"), os_info=host.get("os_info"),
                        fqdn=host.get("fqdn"))
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
                seen = local.strftime("%H:%M:%S")
                seen_full = "%s UTC (%s)" % (
                    last_ts.strftime("%Y-%m-%d %H:%M:%S"), _human_age(idade))
            except Exception:
                is_online = str(a.get('status', '')).upper() == 'ONLINE'
                seen_full = ""

            # Quantos pedidos aguardam este agente perguntar. Deixa claro que a
            # acao foi enfileirada e ainda nao executada: o servidor nao alcanca
            # o agente, quem busca e ele.
            aguardando = db_commands.pending_count(uuid) if db_commands else 0
            cmd_badge = ("<span class='cmd-badge' title='queued, waiting for the "
                         "agent to check in'>%d</span>" % aguardando) if aguardando else ""

            fqdn = a.get('fqdn') or ""
            # Mostra o FQDN so quando acrescenta informacao ao nome curto.
            fqdn_html = ("<br><small style='color:#777; font-family:monospace'>%s</small>"
                         % fqdn) if fqdn and fqdn != host else ""
            seen_html = ("<br><small style='color:#666; font-family:monospace'>%s</small>"
                         % seen_full) if seen_full else ""

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
                <td><span style='{status_style}; font-weight:bold; font-size:11px; border:1px solid; padding:2px 6px; border-radius:3px'>{status_text}</span></td>
                <td style='white-space:nowrap'>
                    <a href='/agent/{uuid}' class='btn-ico' title='Open the forensic report'>&#128269;</a>
                    <a href='/cmd/collect/{uuid}' class='btn-ico' title='Request a capture now (queued; the agent picks it up on its next check-in)'>&#128248;</a>
                    <a href='/cmd/chaos/{uuid}' class='btn-ico btn-lab' title='LAB ONLY: run the chaos generator and capture'>&#9760;</a>
                    <a href='/cmd/restart/{uuid}' class='btn-ico btn-warn' title='Restart the agent (queued)'>&#128260;</a>
                    {cmd_badge}
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
            <div style="font-size:0.9em; color:#aaa; font-weight:bold">{len(agents)} AGENTS</div>
        </div>
        <table>
            <thead><tr><th>Hostname / UUID</th><th>IP Address</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Last Seen</th><th>Status</th><th>Action</th></tr></thead>
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
        def _drain():
            while not self.shutdown_event.is_set():
                try:
                    done = process_batch(self.queue, self.db)
                    if done:
                        self.logger.info("[INGEST] %d capture(s) stored from the queue", done)
                except Exception as e:
                    self.logger.error(f"[INGEST] Queue processing error: {e}")
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
