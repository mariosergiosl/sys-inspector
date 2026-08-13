# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/outbox.py
# DESCRIPTION: Agent side of the store-and-forward transport: takes captures
#              from the local database and delivers them to the central server.
#
# WHY:         Collecting is worthless if the evidence stays on a host that may
#              be compromised, wiped or simply unreachable later. The agent
#              therefore stores locally first and forwards when it can, so a
#              server outage or a network cut delays delivery instead of losing
#              the capture.
#
# DESIGN:      The server decides how much it accepts: the agent asks for a
#              slot before sending, and honours the answer. That keeps a fleet
#              of agents from overwhelming a single server after a long outage,
#              when everyone has a backlog to flush at once.
#
#              Delivery is idempotent: each capture is identified by its custody
#              digest, so a retry after a lost acknowledgement does not create a
#              duplicate on the server.
#
# NOTES:       Uses only the standard library (urllib), deliberately: adding a
#              runtime dependency would have to be carried by the RPM into every
#              inspected host. Compatible with Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import ssl
import json
import time
import socket
import logging
import platform
import urllib.request
import urllib.error

LOG = logging.getLogger("Outbox")

# Caminhos do protocolo, versionados para o servidor poder evoluir sem quebrar
# agentes antigos ainda em campo.
PATH_SLOT = "/api/v1/queue/request"
PATH_INGEST = "/api/v1/ingest"
# O agente PERGUNTA se ha algo para ele; o servidor nunca inicia conexao.
PATH_COMMANDS = "/api/v1/commands"
PATH_COMMAND_RESULT = "/api/v1/commands/result"

# Backoff exponencial limitado: um servidor fora do ar nao pode virar uma
# tempestade de tentativas vinda da frota inteira.
BACKOFF_BASE = 5
BACKOFF_MAX = 300


class Outbox(object):
    """
    Entrega as capturas pendentes ao servidor central.

    Mantem o estado de backoff entre ciclos, para que falhas consecutivas
    espacem as tentativas em vez de repeti-las na mesma cadencia.
    """

    def __init__(self, db, config):
        self.db = db
        self.config = config
        daemon_cfg = (config.get("daemon", {}) or {})

        self.server_ip = daemon_cfg.get("server_ip", "")
        self.server_port = daemon_cfg.get("server_port", 443)
        self.token = daemon_cfg.get("auth_token", "")
        self.batch_size = int(daemon_cfg.get("batch_size", 10) or 10)
        self.timeout = int(daemon_cfg.get("timeout", 15) or 15)
        # TLS ligado por padrao na porta 443; em laboratorio o operador pode
        # apontar para uma porta HTTP explicitamente.
        self.use_tls = bool(daemon_cfg.get("use_tls", self.server_port == 443))
        self.verify_tls = bool(daemon_cfg.get("verify_tls", True))

        self._failures = 0
        self._next_attempt = 0.0
        # Ordens trazidas pelo ultimo check-in.
        self.pending_commands = []
        # Instante em que este agente subiu, para reportar ha quanto ele coleta.
        # Distinto do uptime do HOST: um agente reiniciado num host antigo, ou um
        # host recem-ligado com o agente de sempre, sao situacoes diferentes na
        # triagem, e so os dois numeros juntos as separam.
        self._agent_started = time.time()

    # --------------------------------------------------------------------------
    # ESTADO
    # --------------------------------------------------------------------------
    @property
    def enabled(self):
        """
        O envio so acontece quando o operador configurou um destino e um token.
        O valor de exemplo do arquivo de configuracao nao conta como configurado.
        """
        return bool(self.server_ip and self.token and self.token != "CHANGE_ME")

    def _base_url(self):
        scheme = "https" if self.use_tls else "http"
        return "%s://%s:%s" % (scheme, self.server_ip, self.server_port)

    def _ssl_context(self):
        if not self.use_tls:
            return None
        if self.verify_tls:
            return ssl.create_default_context()
        # Certificado autoassinado em laboratorio: a verificacao e desligada
        # apenas quando o operador pede explicitamente.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _should_wait(self):
        return time.time() < self._next_attempt

    def _register_failure(self):
        self._failures += 1
        delay = min(BACKOFF_BASE * (2 ** (self._failures - 1)), BACKOFF_MAX)
        self._next_attempt = time.time() + delay
        LOG.warning("[OUTBOX] Delivery failed (%d in a row); next attempt in %ds",
                    self._failures, delay)

    def _register_success(self):
        self._failures = 0
        self._next_attempt = 0.0

    # --------------------------------------------------------------------------
    # TRANSPORTE
    # --------------------------------------------------------------------------
    def _post(self, path, payload):
        """
        Envia um documento JSON e devolve a resposta decodificada.
        Levanta em caso de falha, para o chamador aplicar o backoff.
        """
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._base_url() + path, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Authorization", "Bearer " + self.token)
        request.add_header("X-Agent-Id", str(getattr(self.db, "agent_id", "")))

        with urllib.request.urlopen(request, timeout=self.timeout,
                                    context=self._ssl_context()) as response:
            body = response.read().decode("utf-8", "replace")
            return json.loads(body) if body else {}

    def _host_identity(self):
        """
        Identidade minima do host, em claro, para o servidor listar a frota.

        Sao dados de inventario (nome, endereco, sistema), nao conteudo da
        coleta: o que e sensivel continua cifrado.
        """
        hostname = platform.node()
        address = ""
        try:
            # Descobre o endereco pela rota de saida, sem depender de DNS.
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.settimeout(1)
            probe.connect((self.server_ip, int(self.server_port)))
            address = probe.getsockname()[0]
            probe.close()
        except Exception:
            address = ""
        # platform.linux_distribution foi removido no Python 3.8; ler
        # /etc/os-release funciona em qualquer distribuicao atual.
        os_info = platform.system()
        try:
            with open("/etc/os-release", "r") as handle:
                for line in handle:
                    if line.startswith("PRETTY_NAME="):
                        os_info = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass
        # O FQDN identifica o host no dominio, e frequentemente e o nome que
        # aparece em inventarios e chamados; o hostname curto sozinho pode ser
        # ambiguo entre redes.
        try:
            fqdn = socket.getfqdn()
        except Exception:
            fqdn = ""
        # Capacidades: o que ESTE host consegue fazer, nas duas pontas. Sem
        # isso, "o agente X nao acusou o cenario Y" fica ambiguo entre falha da
        # deteccao e incapacidade do host, e foi essa ambiguidade que atrasou um
        # diagnostico inteiro no laboratorio.
        capacidades = {}
        try:
            from src.core.capabilities import describe_host
            capacidades = describe_host()
        except Exception:
            capacidades = {}

        # O agente informa seu proprio ciclo para o servidor conseguir prever
        # o proximo contato. Sem isso a frota so pode usar um timeout fixo, que
        # marca como offline um agente saudavel de ciclo longo e demora a
        # perceber a ausencia de um agente de ciclo curto.
        daemon_cfg = (self.config.get("daemon", {}) or {})
        ciclo = (int(daemon_cfg.get("capture_duration", 15) or 15)
                 + int(daemon_cfg.get("interval", 15) or 15))

        # Desvio de relogio MEDIDO deste host, para a linha do tempo entre hosts
        # ser ordenada por instante comparavel (D-019). Grava-se o valor E se ele
        # foi medido: 0.0 medido afirma sincronia, 0.0 assumido nao afirma nada.
        clock = {"offset": 0.0, "measured": False, "source": "unavailable"}
        try:
            from src.core.clock import measure_offset
            clock = measure_offset()
        except Exception:
            pass

        # Uptime do HOST (segundos desde o boot) e do AGENTE (desde que subiu).
        # Os dois separam casos que a triagem confunde: host recem-ligado com o
        # agente de sempre versus agente reiniciado num host antigo.
        host_uptime = None
        try:
            with open("/proc/uptime", "r") as handle:
                host_uptime = int(float(handle.readline().split()[0]))
        except Exception:
            host_uptime = None
        agent_uptime = int(time.time() - self._agent_started)

        return {"hostname": hostname, "ip_address": address,
                "os_info": os_info, "fqdn": fqdn, "cycle_seconds": ciclo,
                "capabilities": capacidades,
                "host_uptime": host_uptime, "agent_uptime": agent_uptime,
                "clock_offset": clock.get("offset", 0.0),
                "clock_measured": clock.get("measured", False),
                "clock_source": clock.get("source", "unavailable")}

    def request_slot(self, pending):
        """
        Pergunta ao servidor quantas capturas ele aceita agora.

        E o servidor quem controla a fila: ele conhece a frota inteira e pode
        priorizar um host sob investigacao. Se a resposta nao trouxer um numero,
        assume-se o lote configurado, para um servidor antigo continuar
        funcionando com um agente novo.
        """
        # Aproveita a MESMA ida e volta para perguntar o que ja esta guardado
        # no servidor. Uma rotina separada so para isso criaria um segundo
        # relogio e mais trafego, quando a conversa ja acontece a cada ciclo.
        candidatos = []
        try:
            candidatos = self.db.get_confirmed_candidates()
        except Exception:
            pass

        answer = self._post(PATH_SLOT, {
            "agent_uuid": getattr(self.db, "agent_id", ""),
            "pending": pending,
            "host": self._host_identity(),
            "confirm_digests": [c["digest"] for c in candidatos],
        })

        # Libera localmente SOMENTE o que o servidor afirma ter guardado.
        # Entregue nao e o mesmo que guardado: a entrega termina na fila de
        # ingestao, e entre a fila e o disco ha um passo que pode falhar. Apagar
        # com base no aceite da entrega perderia a captura nas duas pontas.
        guardados = set(answer.get("stored_digests") or [])
        if guardados:
            liberar = [c["id"] for c in candidatos if c["digest"] in guardados]
            if liberar:
                n = self.db.purge_confirmed(liberar)
                if n:
                    LOG.info("[OUTBOX] %d capture(s) released locally after the "
                             "server confirmed storage", n)
        # A MESMA ida e volta ja traz o que o analista pediu. Perguntar por
        # comandos numa requisicao separada dobraria o trafego e criaria dois
        # relogios diferentes para a mesma conversa com o servidor.
        #
        # ACUMULA, nunca substitui. O servidor entrega cada comando UMA UNICA
        # vez: qualquer resposta sobrescrita aqui significa um pedido perdido em
        # silencio, com o painel exibindo "entregue" para algo que nao rodou.
        # Entrega e check-in fazem esta mesma chamada no mesmo ciclo, entao a
        # lista so pode ser esvaziada por quem for de fato executa-la.
        self.pending_commands.extend(answer.get("commands", []) or [])
        if not answer.get("granted", True):
            return 0, int(answer.get("retry_after", BACKOFF_BASE) or BACKOFF_BASE)
        return int(answer.get("slots", self.batch_size) or self.batch_size), 0

    def check_in(self):
        """
        Conversa periodica com o servidor: informa o que ha para entregar e
        recolhe o que o analista pediu, na MESMA requisicao.

        A conversa parte sempre do agente. O host inspecionado nao abre porta
        nem mantem servico escutando, o que evita acrescentar superficie de
        ataque justamente na maquina sob investigacao e funciona com agentes
        atras de NAT ou firewall restritivo.

        Acontece mesmo sem captura pendente: e assim que um agente ocioso
        continua aparecendo vivo na frota e recebe ordens sem esperar o proximo
        dado a enviar.
        """
        if not self.enabled or self._should_wait():
            return []
        try:
            pendentes = len(self.db.get_pending_snapshots(limit=self.batch_size))
        except Exception:
            pendentes = 0
        try:
            self.request_slot(pendentes)
            self._register_success()
        except Exception as exc:
            LOG.debug("[OUTBOX] Check-in failed: %s", exc)
            self._register_failure()

        # Entrega para quem vai executar e esvazia: como o servidor nao repete um
        # comando ja entregue, deixa-lo na lista o executaria de novo a cada
        # ciclo, e nao o remover perderia o pedido.
        recolhidos = self.pending_commands
        self.pending_commands = []
        if recolhidos:
            LOG.info("[OUTBOX] %d command(s) received from the server",
                     len(recolhidos))
        return recolhidos

    def report_command(self, command_id, ok, result=""):
        """Devolve ao servidor o desfecho de um comando executado."""
        if not self.enabled:
            return
        try:
            self._post(PATH_COMMAND_RESULT, {
                "agent_uuid": getattr(self.db, "agent_id", ""),
                "id": command_id, "ok": bool(ok), "result": str(result)[:2000],
            })
        except Exception as exc:
            LOG.debug("[OUTBOX] Could not report command %s: %s", command_id, exc)

    def deliver_once(self):
        """
        Executa um ciclo de entrega.

        Retorna o numero de capturas confirmadas pelo servidor. Nunca levanta:
        uma falha de rede nao pode derrubar o laco de coleta do agente, que e a
        funcao principal.
        """
        if not self.enabled or self._should_wait():
            return 0

        try:
            pending = self.db.get_pending_snapshots(limit=self.batch_size)
        except Exception as exc:
            LOG.error("[OUTBOX] Could not read the local queue: %s", exc)
            return 0

        if not pending:
            return 0

        try:
            slots, retry_after = self.request_slot(len(pending))
        except Exception as exc:
            LOG.debug("[OUTBOX] Slot request failed: %s", exc)
            self._register_failure()
            return 0

        if slots <= 0:
            # O servidor pediu para esperar; nao e falha, e controle de fluxo.
            self._next_attempt = time.time() + retry_after
            LOG.info("[OUTBOX] Server asked to wait %ds before sending", retry_after)
            return 0

        delivered = []
        for item in pending[:slots]:
            try:
                answer = self._post(PATH_INGEST, {
                    "agent_uuid": getattr(self.db, "agent_id", ""),
                    # Identidade do host EM CLARO: hostname, endereco e sistema
                    # ficam dentro do payload cifrado, que o servidor so abre
                    # com a chave do analista. Sem envia-los ao lado, a frota
                    # lista todo agente como "unknown" e a triagem fica cega.
                    "host": self._host_identity(),
                    "bundle": item.get("data"),
                    "metrics": item.get("metrics") or {},
                    "custody": item.get("custody") or {},
                    "findings_summary": item.get("findings_summary") or {},
                })
            except Exception as exc:
                LOG.debug("[OUTBOX] Delivery of snapshot %s failed: %s",
                          item.get("id"), exc)
                self._register_failure()
                break

            # 'duplicate' tambem confirma: o servidor ja tem essa captura, e
            # reenvia-la para sempre seria pior do que aceitar o reconhecimento.
            if answer.get("status") in ("received", "duplicate"):
                delivered.append(item["id"])
            else:
                LOG.warning("[OUTBOX] Server rejected snapshot %s: %s",
                            item.get("id"), answer)
                break

        if delivered:
            # So marca como enviado o que o servidor confirmou: um ack perdido
            # faz reenviar (o servidor deduplica), o contrario perderia prova.
            try:
                self.db.mark_as_synced(delivered)
                self._register_success()
                LOG.info("[OUTBOX] Delivered %d capture(s) to %s",
                         len(delivered), self._base_url())
            except Exception as exc:
                LOG.error("[OUTBOX] Could not mark captures as delivered: %s", exc)

        return len(delivered)
