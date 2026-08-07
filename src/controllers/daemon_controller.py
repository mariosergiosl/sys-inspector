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
# VERSION: v0.90.16
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
# from src.core.database import DatabaseManager
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

    def _run_chaos(self, params):
        """
        Dispara o gerador de cenario de teste, quando presente.

        E uma ferramenta de laboratorio: valida a deteccao ponta a ponta. Se o
        script nao estiver instalado, o comando falha de forma explicita em vez
        de fingir que rodou.
        """
        import os
        import subprocess

        duracao = str(int(params.get("duration", 300) or 300))
        candidatos = ["/opt/sys-inspector/tools/chaos_maker.sh",
                      "/usr/bin/chaos_maker.sh"]
        script = next((c for c in candidatos if os.path.exists(c)), None)
        if not script:
            raise RuntimeError("chaos_maker.sh not installed on this host")

        subprocess.Popen(["/bin/bash", script, "--all", "--duration", duracao],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        return "chaos rodando por %ss" % duracao

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

        # Achados estaticos (persistencia), mesmo conjunto dos demais modos.
        findings = collect_findings()
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

        success = self.db.insert_snapshot(
            encrypted_bundle,
            agent_uuid=self.agent_uuid,
            metrics=metrics,
            custody=custody,
            findings_summary=full_data.get('findings_summary')
        )

        if success:
            self.logger.info(f"[CYCLE #{cycle_id}] Snapshot persisted successfully (PIDs: {metrics['pids']}).")
        else:
            self.logger.error(f"[CYCLE #{cycle_id}] Database Insert Failed.")
