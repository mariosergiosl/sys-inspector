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
# VERSION: v0.91.0
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
        return {"hostname": hostname, "ip_address": address, "os_info": os_info}

    def request_slot(self, pending):
        """
        Pergunta ao servidor quantas capturas ele aceita agora.

        E o servidor quem controla a fila: ele conhece a frota inteira e pode
        priorizar um host sob investigacao. Se a resposta nao trouxer um numero,
        assume-se o lote configurado, para um servidor antigo continuar
        funcionando com um agente novo.
        """
        answer = self._post(PATH_SLOT, {
            "agent_uuid": getattr(self.db, "agent_id", ""),
            "pending": pending,
        })
        if not answer.get("granted", True):
            return 0, int(answer.get("retry_after", BACKOFF_BASE) or BACKOFF_BASE)
        return int(answer.get("slots", self.batch_size) or self.batch_size), 0

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
