# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/controllers/daemon_controller.py
# DESCRIPTION: Continuous Data Collector (Daemon Mode) for Sys-Inspector v0.80.
#              Operates in a Loop: Capture -> Encrypt -> Persist -> Sleep.
#              Acts as the Universal Local Collector.
#
# FEATURES:
#   - Persistent Engine Handling (Reuses eBPF probes).
#   - Secure Storage (Async Encryption).
#   - Configurable Duty Cycle.
#   - Network Aware (Captures IPs/Hostname for Agent ID).
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import time
import logging
# import threading
# import json

# Imports from Core
from src.core.engine import SysInspectorEngine
# [FIXED] Importing the function directly, not a non-existent class
from src.collectors.system_inventory import collect_full_inventory
from src.collectors.manager import (summarize_metrics, collect_findings,
                                    correlate_findings_with_processes)
from src.core.findings import summarize_by_severity
from src.core.database import CAPTURE_FULL, CAPTURE_CHAOS
from src.core.crypto import load_public_key, encrypt_data
from src.core.outbox import Outbox
from src.core.custody import build_for_capture
from src.core.commands import CMD_COLLECT, CMD_CHAOS_COLLECT, CMD_RESTART
from src.core.executed import ExecutionLedger


class DaemonController:
    def __init__(self, config, db_manager, shutdown_event):
        """
        Initialize the Daemon Controller.

        Args:
            config (dict): Configuration dictionary.
            db_manager (DatabaseManager): Initialized DB handler.
            shutdown_event (threading.Event): Signal for graceful shutdown.
        """
        self.config = config
        self.db = db_manager
        self.shutdown_event = shutdown_event
        self.logger = logging.getLogger("DaemonCtrl")

        # Identity (unificada: o mesmo agent_id do DatabaseManager, usado por
        # todos os modos, persistido ao lado do banco).
        self.agent_uuid = db_manager.agent_id

        # Load Security Keys
        try:
            self.pub_key = load_public_key(config['security']['public_key_path'])
            self.logger.info("Public Key loaded successfully.")
        except Exception as e:
            self.logger.critical(f"Failed to load Public Key: {e}")
            raise

        # Configuration - Duty Cycle
        # Default: Capture for 15s, Sleep for 15s (50% Duty Cycle)
        self.interval = config['daemon'].get('interval', 15)
        self.capture_duration = config['daemon'].get('capture_duration', 15)

        # Store-and-forward: coleta local primeiro, entrega ao servidor quando
        # possivel. Fica inativo enquanto nao houver destino e token
        # configurados, preservando o comportamento puramente local.
        self.outbox = Outbox(db_manager, config)
        if self.outbox.enabled:
            self.logger.info("[OUTBOX] Forwarding captures to %s",
                             self.outbox._base_url())

        # Registro do que ja foi executado. Permite ao servidor reentregar um
        # comando sem que ele rode duas vezes no host inspecionado.
        self.ledger = ExecutionLedger(getattr(db_manager, "db_path", ":memory:"))

        # Origem da configuracao e a marca de tempo do arquivo, para reler o que
        # o operador mudar sem exigir restart.
        self.config_path = config.get('_source_path')
        self._config_mtime = self._mtime_config()

    # --------------------------------------------------------------------------
    # CONFIGURACAO EM TEMPO DE EXECUCAO
    # --------------------------------------------------------------------------
    def _mtime_config(self):
        try:
            return os.path.getmtime(self.config_path) if self.config_path else 0
        except OSError:
            return 0

    def reload_config_if_changed(self):
        """
        Rele o arquivo de configuracao quando ele muda no disco.

        Sem isso, ajustar o destino ou o intervalo exigia reiniciar o agente, e
        reiniciar descarta a janela de captura em andamento. Pior: uma troca de
        transporte passava a falhar em silencio, com o agente tentando o
        endereco antigo em backoff enquanto o arquivo ja dizia outra coisa.

        Nem tudo pode mudar a quente. As chaves criptograficas e o modo de
        operacao continuam presos ao processo: troca-los no meio do caminho
        deixaria capturas da mesma sessao com identidades diferentes, e um laudo
        precisa ser coerente do inicio ao fim.
        """
        atual = self._mtime_config()
        if not atual or atual == self._config_mtime:
            return False

        try:
            from src.utils.config_loader import load_config
            novo = load_config(self.config_path)
        except (Exception, SystemExit) as exc:
            # Arquivo invalido nao pode derrubar a coleta: segue com o que ja
            # estava valendo e avisa.
            #
            # SystemExit entra na lista de proposito: load_config encerra o
            # processo quando o YAML nao parseia, o que e correto na partida,
            # mas fatal num agente em operacao. Um erro de digitacao do operador
            # mataria a coleta de um host sob investigacao.
            self.logger.error("[CONFIG] Reload failed, keeping previous: %s", exc)
            self._config_mtime = atual
            return False

        self._config_mtime = atual
        self.config = novo

        antes = self.outbox._base_url() if self.outbox.enabled else "local only"
        self.interval = novo['daemon'].get('interval', self.interval)
        self.capture_duration = novo['daemon'].get('capture_duration',
                                                   self.capture_duration)
        # Substitui o transmissor inteiro em vez de remendar campo por campo:
        # um estado de backoff herdado do destino antigo atrasaria a primeira
        # tentativa contra o destino novo.
        self.outbox = Outbox(self.db, novo)
        depois = self.outbox._base_url() if self.outbox.enabled else "local only"

        self.logger.info("[CONFIG] Reloaded: capture=%ss sleep=%ss transport=%s",
                         self.capture_duration, self.interval, depois)
        if antes != depois:
            self.logger.warning("[CONFIG] Transport changed: %s -> %s",
                                antes, depois)
        return True

    def run(self):
        """
        Main Execution Loop.
        Initializes the Engine ONCE and toggles collection cyclically.
        """
        self.logger.info(f"[DAEMON] Starting Universal Collector (v0.80). Agent ID: {self.agent_uuid}")
        self.logger.info(f"[DAEMON] Cycle Config: Capture={self.capture_duration}s | Sleep={self.interval}s")

        # 1. Initialize Engine ONCE to avoid recompilation overhead
        try:
            # Instantiating the correct class name
            engine = SysInspectorEngine(self.config)
            self.logger.info("[CORE] eBPF Engine initialized/compiled.")
        except Exception as e:
            self.logger.critical(f"eBPF Engine Init Failed: {e}")
            return

        cycle_count = 0

        # 2. Main Loop
        while not self.shutdown_event.is_set():
            cycle_count += 1

            # Antes de capturar: se o operador ajustou o arquivo, este ciclo ja
            # roda com o valor novo.
            self.reload_config_if_changed()

            try:
                # Delegate collection logic, passing the persistent engine
                self.collect_and_store(engine, cycle_count)
            except Exception as e:
                self.logger.error(f"[CYCLE #{cycle_count}] Critical Failure: {e}", exc_info=True)
                time.sleep(5)  # Backoff on error

            # 3. Entrega o que estiver pendente. Falha aqui nunca interrompe a
            # coleta: a captura ja esta salva e sera reenviada no proximo ciclo.
            # A mesma conversa com o servidor entrega o que ha e recolhe o que
            # foi pedido, em vez de duas rotinas com relogios diferentes.
            try:
                self.outbox.deliver_once()
                self._handle_commands(engine, self.outbox.check_in())
            except Exception as e:
                self.logger.error(f"[SYNC] Unexpected sync error: {e}")

            # 4. Sleep Interval (Idle Time)
            if not self.shutdown_event.is_set():
                self.logger.info(f"[WAIT] Sleeping for {self.interval}s...")
                self.shutdown_event.wait(self.interval)

        # Cleanup on exit
        # engine.cleanup()  # on future
        self.logger.info("[DAEMON] Shutdown complete.")

    def _handle_commands(self, engine, comandos):
        """
        Busca e executa os comandos pedidos pelo analista.

        Cada desfecho volta ao servidor, para o pedido ter rastro: quem pediu,
        quando chegou e o que aconteceu. Um comando que falha nao derruba o
        laco de coleta, que continua sendo a funcao principal do agente.
        """
        for cmd in comandos or []:
            nome = cmd.get("command")
            ident = cmd.get("id")

            # Reentrega e esperada: o servidor insiste enquanto nao souber o
            # desfecho, e e assim que um pedido deixa de se perder quando o
            # agente morre logo depois de receber. O preco disso e o mesmo
            # comando poder chegar duas vezes, e e aqui que ele e cobrado: um
            # pedido ja executado e confirmado de novo, NUNCA repetido. Repetir
            # significaria plantar o cenario de teste em cima de si mesmo ou
            # reiniciar o agente no meio de uma captura.
            anterior = self.ledger.already_done(ident)
            if anterior is not None:
                self.logger.info("[CMD] '%s' (#%s) ja executado; reconfirmando "
                                 "sem repetir", nome, ident)
                self.outbox.report_command(ident, True, anterior)
                continue

            self.logger.info("[CMD] Executing '%s' requested by the analyst", nome)
            try:
                if nome == CMD_COLLECT:
                    self.collect_and_store(engine, "on-demand")
                    self.outbox.deliver_once()
                    self._concluir(ident, nome,
                                   "captura de %ss concluida e entregue"
                                   % self.capture_duration)

                elif nome == CMD_CHAOS_COLLECT:
                    saida = self._run_chaos(cmd.get("params") or {})
                    self.collect_and_store(engine, "chaos")
                    self.outbox.deliver_once()
                    self._concluir(ident, nome,
                                   "%s; captura de %ss entregue"
                                   % (saida, self.capture_duration))

                elif nome == CMD_RESTART:
                    # Anota e confirma ANTES de sair: depois do exit nao ha quem
                    # relate, e sem o registro o pedido voltaria no proximo
                    # check-in, deixando o agente num ciclo de reinicios.
                    self._concluir(ident, nome, "restarting")
                    self._reiniciar_processo()
                    self.logger.warning("[CMD] Restart requested; stopping agent")
                    self.shutdown_event.set()
                    return

                else:
                    self.outbox.report_command(ident, False, "unknown command")
            except Exception as exc:
                self.logger.error("[CMD] '%s' failed: %s", nome, exc)
                self.outbox.report_command(ident, False, str(exc))

    def _concluir(self, ident, nome, resultado):
        """
        Fecha um comando: anota localmente e so entao reporta ao servidor.

        A ordem importa. Anotar primeiro garante que, se a confirmacao se perder
        na rede e o servidor reentregar, o agente ja sabe que executou. A ordem
        inversa deixaria justamente a janela que este mecanismo existe para
        fechar.
        """
        self.ledger.remember(ident, nome, resultado)
        self.outbox.report_command(ident, True, resultado)

    def _reiniciar_processo(self):
        """
        Reinicia o proprio agente, sem depender de supervisor.

        Antes o comando apenas encerrava, na premissa de que o systemd traria o
        agente de volta. Fora do systemd, e o laboratorio inteiro roda assim, o
        agente simplesmente PARAVA: um pedido de reinicio derrubava a coleta do
        host e ninguem percebia ate a frota acusar offline, minutos depois.

        Trocar a propria imagem do processo funciona nos dois casos: sob
        supervisor, o servico segue vivo com codigo novo; sem supervisor, o
        agente volta por conta propria. Nao ha caminho em que o pedido termine
        com o host descoberto.
        """
        import os
        import sys
        try:
            self.logger.warning("[CMD] Re-executing agent to apply restart")
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as exc:
            # Se nem isso funcionar, o operador precisa saber que o host ficou
            # sem coleta, e nao descobrir depois pelo silencio.
            self.logger.critical(
                "[CMD] Restart failed and the agent is stopping: %s. This host "
                "is no longer being collected.", exc)

    # Marcador que o chaos_maker imprime quando TODOS os artefatos ja estao
    # plantados e vivos. Capturar antes disso pega a cena vazia: o cenario ainda
    # esta compilando os artefatos em C, plantando arquivos e subindo processos.
    CHAOS_READY_MARK = "SYSTEM READY FOR COLLECTION"
    CHAOS_SETUP_TIMEOUT = 40

    def _run_chaos(self, params):
        """
        Dispara o gerador de cenario de teste e ESPERA ele ficar pronto.

        E uma ferramenta de laboratorio: valida a deteccao ponta a ponta. Se o
        script nao estiver instalado, o comando falha de forma explicita em vez
        de fingir que rodou.

        A espera pelo "SYSTEM READY" e o ponto central: o chaos_maker roda em
        background e leva alguns segundos para montar tudo (compila artefatos em
        C, planta arquivos, sobe processos). Capturar no instante em que ele e
        LANCADO pega uma cena que ainda nao existe -- foi o que fazia a captura
        logo apos o chaos parecer "nao detectar", enquanto pedir a captura depois
        do READY pegava tudo. Aqui a captura que vem em seguida (collect_and_store)
        so comeca quando o cenario esta de pe.
        """
        import os
        import subprocess

        duracao = str(int(params.get("duration", 300) or 300))
        candidatos = ["/opt/sys-inspector/tools/chaos_maker.sh",
                      "/usr/bin/chaos_maker.sh"]
        script = next((c for c in candidatos if os.path.exists(c)), None)
        if not script:
            raise RuntimeError("chaos_maker.sh not installed on this host")

        log_path = "/tmp/si_chaos_cmd.log"
        try:
            log_fh = open(log_path, "w")
        except OSError:
            log_fh = subprocess.DEVNULL
        # stdout num arquivo (nao DEVNULL) para poder esperar o marcador de
        # pronto sem bloquear o processo do chaos, que segue escrevendo la.
        subprocess.Popen(["/bin/bash", script, "--all", "--duration", duracao],
                         stdout=log_fh, stderr=subprocess.STDOUT,
                         start_new_session=True)
        if hasattr(log_fh, "close"):
            try: log_fh.close()
            except OSError: pass

        pronto = self._esperar_chaos_pronto(log_path, self.CHAOS_SETUP_TIMEOUT)
        estado = "pronto para captura" if pronto else \
            "setup nao confirmado em %ss (capturando mesmo assim)" \
            % self.CHAOS_SETUP_TIMEOUT
        return "chaos rodando por %ss; %s" % (duracao, estado)

    def _esperar_chaos_pronto(self, log_path, timeout):
        """
        Espera o chaos_maker imprimir o marcador de pronto, com teto de tempo.

        Le o arquivo de log em vez de consumir o stdout do processo, para nao
        arriscar um SIGPIPE que interromperia o cenario. Retorna True se o
        marcador apareceu, False no timeout (a captura ainda ocorre, para o
        comando nunca ficar sem desfecho).
        """
        import time

        fim = time.time() + timeout
        while time.time() < fim:
            if self.shutdown_event.is_set():
                return False
            try:
                with open(log_path, "r", errors="replace") as fh:
                    if self.CHAOS_READY_MARK in fh.read():
                        return True
            except OSError:
                pass
            time.sleep(0.5)
        return False

    def collect_and_store(self, engine, cycle_id):
        """
        Performs a single capture cycle using the existing engine instance.
        """
        self.logger.info(f"[CYCLE #{cycle_id}] Starting Capture Phase ({self.capture_duration}s)...")

        # A. Cada captura precisa descrever a janela dela, e nao a soma de tudo
        # que ja passou pelo agente. O motor e reaproveitado entre ciclos para
        # evitar recompilar os probes, mas a arvore que ele carrega tem que
        # comecar limpa: sem isso o laudo lista processos ha muito encerrados e a
        # comparacao entre capturas nunca acusa desaparecimento.
        engine.tree.reset()

        # B. Start eBPF Polling
        engine.start()

        # Wait for capture duration (responsive sleep)
        elapsed = 0
        while elapsed < self.capture_duration:
            if self.shutdown_event.is_set():
                break
            time.sleep(1)
            elapsed += 1

        # B. Stop eBPF Polling
        engine.stop()

        if self.shutdown_event.is_set():
            return

        # C. Retrieve Data
        # Finaliza a agregacao da arvore (tags, scores).
        engine.tree.aggregate_stats()

        # Modelo unico de captura: mesmo shape do snapshot e do live, com os
        # processos no topo em 'processes', para o renderizador reidratar sem
        # precisar conhecer formatos diferentes por modo.
        full_data = collect_full_inventory()
        full_data['processes'] = engine.tree.to_json()
        full_data['capture_duration'] = self.capture_duration
        full_data['mode'] = 'daemon'
        full_data['agent_uuid'] = self.agent_uuid
        full_data['cycle'] = cycle_id
        # O TIPO da captura vem do motivo que a disparou, que o chamador ja
        # informa em cycle_id. Fica DENTRO do payload (para o laudo poder dize-lo)
        # e tambem em coluna propria, em claro, porque a limpeza precisa
        # distinguir o descartavel do probatorio sem abrir a captura.
        # Uma captura feita logo apos plantar o cenario nasce marcada como tal:
        # ela mede a ferramenta, nao o host em uso, e misturar as duas na mesma
        # serie historica distorce a comparacao entre capturas.
        tipo = CAPTURE_CHAOS if cycle_id == "chaos" else CAPTURE_FULL
        full_data['capture_type'] = tipo

        # Achados estaticos (persistencia), mesmo conjunto dos demais modos.
        findings = collect_findings(full_data['processes'])
        serialized = [f.to_dict() for f in findings]
        # Liga o achado estatico ao runtime, como no modo snapshot: sem isso a
        # captura do agente nunca oferece o atalho do achado para o processo
        # que esta executando o caminho denunciado.
        correlate_findings_with_processes(serialized, full_data['processes'])
        full_data['findings'] = serialized
        full_data['findings_summary'] = summarize_by_severity(findings)

        # D. Metricas quentes (mesmo helper compartilhado do snapshot).
        metrics = summarize_metrics(full_data['processes'])

        # E. Encrypt
        self.logger.debug(f"[CYCLE #{cycle_id}] Encrypting payload...")
        encrypted_bundle = encrypt_data(full_data, self.pub_key)

        # F. Persist (DatabaseManager): atualiza status do agente para ONLINE e
        # insere o snapshot com as colunas quentes.
        # Mesma cadeia de custodia da coleta pontual: uma captura automatica
        # em campo precisa ser tao defensavel quanto uma feita a mao.
        custody = build_for_capture(self.db, self.config, full_data)

        # O TIPO da captura vem do motivo que a disparou, que o chamador ja
        # informa em cycle_id. Gravar isso e o que separa, mais tarde, o que a
        # limpeza automatica pode descartar do que e evidencia. Uma captura feita
        # logo apos plantar o cenario nasce marcada como tal: ela mede a
        # ferramenta, nao o host em uso, e misturar as duas na mesma serie
        # historica distorce qualquer comparacao entre capturas.
        success = self.db.insert_snapshot(
            encrypted_bundle,
            agent_uuid=self.agent_uuid,
            metrics=metrics,
            custody=custody,
            findings_summary=full_data.get('findings_summary'),
            capture_type=tipo
        )

        if success:
            self.logger.info(f"[CYCLE #{cycle_id}] Snapshot persisted successfully (PIDs: {metrics['pids']}).")
        else:
            self.logger.error(f"[CYCLE #{cycle_id}] Database Insert Failed.")
