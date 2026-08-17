# Capturas de tela para o manual (Sys-Inspector v1.0.0)

Capturas do lab (openSUSE/161 sob chaos_maker), organizadas por tela, com nomes
autoidentificaveis. Acompanha `GUIA-elementos.md` (texto de todo tooltip, menu e
acao clicavel de cada tela).

## Telas de nivel de frota (Manager)

- `01_manager_frota/frota_overview.png` — dashboard da frota.
- `02_linha_do_tempo/` — `timeline_overview`, janelas `timeline_janela_15min/6h/24h`,
  filtros `timeline_filtro_achado/persistencia/processo_inicio/captura`, `timeline_ajuda`.
- `03_fila/fila_overview.png` — fila de comandos.
- `04_comandos/comandos_overview.png` — log de comandos.
- `05_capacidades/capacidades_overview.png` — capacidades por agente (eBPF/BTF/root/cgroup2).

## Laudo do agente

- `06_laudo_findings/` — `findings_overview`, filtros `findings_filtro_critical/high/low/info`,
  `findings_expandido_persistencia`, `findings_expandido_wx_memoria`, `findings_ajuda`.
- `07_laudo_processes/`
  - `processes_arvore` — arvore de processos expandida.
  - `processes_ordenar_cpu/io/memoria/rede/prioridade` — ordenacoes.
  - `processes_ajuda_anomaly_score` — legenda dos bits de alerta.
  - **Detalhe expandido por tipo de deteccao (chaos_maker):**
    - `processes_detalhe_systemd_pid1` — exemplo geral (todos os campos).
    - `processes_detalhe_binario_apagado` — deleted_sleep (Executable deleted from disk + unsafe path + unsafe lib).
    - `processes_detalhe_ferramenta_rede` — artifact_net (Network Resilience: Drops; unsafe path).
    - `processes_detalhe_firewall_edr` — artifact_fw (bloqueio de trafego/EDR).
    - `processes_detalhe_lib_nao_confiavel` — artifact_unsafe (Unsafe Library Path).
    - `processes_detalhe_prioridade_nice` — nice_test_low (prioridade anomala).
    - `processes_detalhe_mineracao_gpu` — kryptominer (assinatura de GPU/mineracao).
    - `processes_detalhe_zombie` — artifact_zombie (processo pai).
    - `processes_detalhe_lsattr_zombie` — lsattr defunct (ZOMBIE/DEFUNCT).
- `08_laudo_attack/` — `attack_overview`, `attack_ajuda`.
- `09_laudo_storage/storage_expandido.png` — disco -> particoes -> LVM -> mount.
- `10_historico/` — `historico_overview`, `historico_comparar` (diff entre duas capturas).

## Como reproduzir

Chrome headless grava o PNG direto no caminho. Estados interativos (abas, filtros,
detalhe de processo, baloes de ajuda) sao capturados injetando as funcoes da propria
pagina (`showTab`, `filterFindings`, `filterTable`, `toggleDet`, `toggleDisk`,
`sortView`) numa copia local do HTML. O detalhe de um processo do chaos e obtido
filtrando pelo nome (`filterTable`) e chamando `toggleDet(pid)` na linha que casa.
Os processos do chaos so existem enquanto o chaos_maker roda (janela de ~300s).
