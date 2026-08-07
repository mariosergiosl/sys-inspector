# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/notify.py
# DESCRIPTION: Avisa quem precisa saber, quando ainda da tempo de agir.
#
# WHY:         Ninguem fica olhando painel. Uma deteccao que so existe numa tela
#              que ninguem abriu equivale, na pratica, a deteccao que nao houve.
#              Este modulo fecha essa distancia: o achado grave sai da ferramenta
#              e chega a pessoa.
#
# THREE RULES: O que separa um alerta util de um ruido que sera silenciado:
#
#              1. AGRUPAMENTO. Um unico incidente produz dezenas de achados. Sem
#                 agrupar, o celular recebe 40 mensagens sobre a mesma coisa e a
#                 proxima vez que algo importar ja ninguem estara lendo.
#              2. REPETICAO CONTROLADA. O mesmo achado reaparece em toda captura
#                 enquanto durar. Avisar de novo a cada ciclo transforma um
#                 alerta legitimo em spam do proprio sistema.
#              3. NADA SENSIVEL NA MENSAGEM. O destino e um servico de terceiro,
#                 fora do controle de quem investiga. A mensagem diz que algo
#                 aconteceu e onde olhar; a linha de comando, o caminho e a
#                 evidencia ficam na ferramenta.
#
# NOTES:       Somente biblioteca padrao, como o resto do transporte: uma
#              dependencia nova aqui seria carregada para dentro do servidor por
#              causa de uma funcionalidade acessoria. Compativel com Python 3.6.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: v0.92.0
# ==============================================================================

import ssl
import json
import time
import logging
import urllib.parse
import urllib.request

from src.core.findings import SEVERITY_ORDER, SEV_HIGH

LOG = logging.getLogger("Notify")

# Silencio para o mesmo achado, em segundos. Uma hora e o intervalo em que
# reavisar deixa de ser informacao e vira insistencia: quem recebeu ja sabe.
JANELA_REPETICAO = 3600

# Teto por rodada. Um host recem-comprometido pode gerar dezenas de achados
# graves de uma vez, e mandar todos garante que nenhum seja lido.
MAXIMO_POR_RODADA = 3

TIMEOUT = 10


class Notifier(object):
    """
    Decide o que merece aviso e entrega ao destino configurado.

    A decisao (o que avisar) fica separada da entrega (por onde), para que
    acrescentar um destino novo nao exija repensar as regras.
    """

    def __init__(self, config=None):
        cfg = (config or {}).get("notify", {}) or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.min_severity = cfg.get("min_severity", SEV_HIGH)
        self.janela = int(cfg.get("repeat_window", JANELA_REPETICAO))
        self.maximo = int(cfg.get("max_per_round", MAXIMO_POR_RODADA))
        self.quiet = bool(cfg.get("quiet", False))

        self.telegram_token = cfg.get("telegram_token", "")
        self.telegram_chat = cfg.get("telegram_chat", "")
        self.webhook_url = cfg.get("webhook_url", "")
        self.verify_tls = bool(cfg.get("verify_tls", True))

        # Ultimo aviso por impressao digital, para nao repetir.
        self._avisados = {}

    # --------------------------------------------------------------------------
    # DECISAO
    # --------------------------------------------------------------------------
    def _grave_o_bastante(self, finding):
        atual = SEVERITY_ORDER.get(finding.get("severity"), 0)
        minimo = SEVERITY_ORDER.get(self.min_severity, 3)
        return atual >= minimo

    def _ja_avisado(self, chave, agora):
        anterior = self._avisados.get(chave)
        return anterior is not None and (agora - anterior) < self.janela

    def select(self, findings, agora=None):
        """
        Escolhe o que sera avisado, aplicando as tres regras.

        Devolve tambem quantos ficaram de fora, porque a mensagem precisa dizer
        isso: "3 achados criticos" quando havia 40 induziria a conclusao errada
        sobre o tamanho do incidente.
        """
        agora = agora or time.time()
        candidatos = [f for f in (findings or []) if self._grave_o_bastante(f)]

        novos = []
        for f in candidatos:
            chave = f.get("fingerprint") or f.get("title")
            if self._ja_avisado(chave, agora):
                continue
            novos.append(f)

        # Mais graves primeiro: se algo vai ficar de fora do aviso, que seja o
        # menos urgente.
        novos.sort(key=lambda f: -SEVERITY_ORDER.get(f.get("severity"), 0))
        return {"send": novos[:self.maximo],
                "suppressed": max(0, len(novos) - self.maximo),
                "total_matching": len(candidatos)}

    def _registrar(self, enviados, agora):
        for f in enviados:
            self._avisados[f.get("fingerprint") or f.get("title")] = agora

    # --------------------------------------------------------------------------
    # MENSAGEM
    # --------------------------------------------------------------------------
    def compose(self, host, selecao, url=""):
        """
        Monta o texto do aviso.

        Deliberadamente pobre em detalhe: o destino e um servico de terceiro. A
        mensagem responde onde e quao grave, e aponta para a ferramenta. Levar
        linha de comando ou caminho para fora seria vazar a propria investigacao
        por um canal que nao controlamos.
        """
        enviar = selecao["send"]
        if not enviar:
            return ""

        linhas = ["ALERTA Sys-Inspector", "", "Host: %s" % host,
                  "Achados graves: %d" % selecao["total_matching"], ""]
        for f in enviar:
            linhas.append("- [%s] %s" % (f.get("severity", "?"),
                                         (f.get("title") or "")[:120]))
        if selecao["suppressed"]:
            linhas.append("")
            linhas.append("(+%d nao listados nesta mensagem)"
                          % selecao["suppressed"])
        if url:
            linhas.append("")
            linhas.append("Detalhes: %s" % url)
        return "\n".join(linhas)

    # --------------------------------------------------------------------------
    # ENTREGA
    # --------------------------------------------------------------------------
    def _contexto_tls(self):
        if self.verify_tls:
            return None      # verificacao padrao
        contexto = ssl.create_default_context()
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        return contexto

    def _telegram(self, texto):
        if not (self.telegram_token and self.telegram_chat):
            return False
        url = "https://api.telegram.org/bot%s/sendMessage" % self.telegram_token
        dados = urllib.parse.urlencode({
            "chat_id": self.telegram_chat,
            "text": texto,
            "disable_notification": "true" if self.quiet else "false",
        }).encode("utf-8")
        try:
            req = urllib.request.Request(url, data=dados, method="POST")
            with urllib.request.urlopen(req, timeout=TIMEOUT,
                                        context=self._contexto_tls()) as r:
                return r.status == 200
        except Exception as exc:
            # Falhar em avisar nunca pode derrubar a coleta: o dado ja esta
            # guardado, e o aviso e acessorio ao registro.
            LOG.error("Telegram delivery failed: %s", exc)
            return False

    def _webhook(self, texto, host, selecao):
        if not self.webhook_url:
            return False
        corpo = json.dumps({"host": host, "text": texto,
                            "count": selecao["total_matching"]}).encode("utf-8")
        try:
            req = urllib.request.Request(self.webhook_url, data=corpo,
                                         method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=TIMEOUT,
                                        context=self._contexto_tls()) as r:
                return 200 <= r.status < 300
        except Exception as exc:
            LOG.error("Webhook delivery failed: %s", exc)
            return False

    # --------------------------------------------------------------------------
    def notify(self, host, findings, url="", agora=None):
        """
        Avalia os achados e avisa, se houver o que avisar.

        Retorna o que foi decidido e entregue, para o servidor registrar em log:
        um alerta que ninguem sabe se saiu nao ajuda a investigar depois.
        """
        if not self.enabled:
            return {"sent": 0, "reason": "disabled"}

        agora = agora or time.time()
        selecao = self.select(findings, agora)
        if not selecao["send"]:
            return {"sent": 0, "reason": "nothing new above threshold"}

        texto = self.compose(host, selecao, url)
        entregue = False
        entregue = self._telegram(texto) or entregue
        entregue = self._webhook(texto, host, selecao) or entregue

        if entregue:
            self._registrar(selecao["send"], agora)
            LOG.info("[NOTIFY] %d finding(s) reported for %s",
                     len(selecao["send"]), host)
        return {"sent": len(selecao["send"]) if entregue else 0,
                "suppressed": selecao["suppressed"],
                "delivered": entregue}
