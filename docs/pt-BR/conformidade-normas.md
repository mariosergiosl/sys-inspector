# Conformidade com normas e boas práticas forenses

> Este documento diz **o que a ferramenta cobre, o que cobre em parte e o que não
> cobre** em relação às normas e práticas correntes de forense digital.
>
> **Regra deste documento:** cada linha traz a evidência (arquivo, mecanismo ou
> item de backlog) que sustenta a afirmação. Uma tabela de conformidade sem
> evidência é pior que nenhuma tabela, porque promete o que ninguém conferiu.
>
> A ferramenta é de **forense de frota**, não de bancada (decisão D-024). Ela
> coleta o suficiente para **identificar e direcionar**, nunca a massa que prova
> (decisão D-032). Vários "não cobre" abaixo são escolha deliberada, e estão
> marcados como tal.

## Legenda

| Marca | Significado |
|---|---|
| **Coberto** | Implementado e verificado por teste ou medição em host real |
| **Parcial** | Implementado em parte; o que falta está dito na linha |
| **Não coberto** | Não implementado. Se for decisão, a decisão está citada |
| **Fora de escopo** | Deliberadamente não é trabalho desta ferramenta |

---

## 1. RFC 3227 — Guidelines for Evidence Collection and Archiving

Documento do IETF (2002) que estabelece a **ordem de volatilidade**: coletar
primeiro o que some primeiro.

| Item da norma | Situação | Evidência |
|---|---|---|
| Coletar antes registradores, cache e memória | **Fora de escopo** | Captura de memória bruta é bancada (D-032). A ferramenta aponta a região suspeita e encaminha (`src/core/acquisition.py`, campo `referral` em `src/core/findings.py`) |
| Tabela de rotas, cache ARP, tabela de processos, estatísticas de kernel | **Coberto** | `src/collectors/system_inventory.py` e `src/collectors/process_tree.py`; sondas eBPF em `src/probes/base_trace.c` |
| Sistemas de arquivos temporários | **Parcial** | Detecta execução a partir de `/tmp`, `/dev/shm`, `/var/tmp`, `/run/shm` (`UNSAFE_EXEC_PREFIXES`). Não preserva o conteúdo integral desses caminhos |
| Disco | **Parcial** | Hash e recorte de arquivos suspeitos, com cópia integral quando cabe no teto (`Acquirer.acquire_file`). Imagem de disco é bancada |
| Registro remoto e monitoramento | **Coberto** | Entrega ao servidor central por HTTPS com token (`src/core/outbox.py`, decisão D-033) |
| Configuração física e topologia de rede | **Coberto** | `get_net_info()` e `get_hw_info()` em `system_inventory.py` |
| Mídia de arquivamento | **Fora de escopo** | |
| **Registrar o relógio e o desvio** | **Parcial** | `clock_offset` existe (decisão D-019), mas há caso conhecido de host dessincronizado pós-boot com offset não medido |

**Lacuna honesta.** A ordem de volatilidade pressupõe observação contínua do que
é volátil. Hoje as sondas ficam atachadas mas o buffer só é drenado durante a
janela de captura (item `F-241`): entre janelas, evento volátil é perdido sem
aviso. É a maior distância entre esta ferramenta e a norma.

---

## 2. NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response

Organiza o trabalho em quatro fases: **coleta, exame, análise e apresentação**.

| Fase | Situação | Evidência |
|---|---|---|
| Coleta | **Coberto** | 33 pontos de instrumentação eBPF e 8 coletores estáticos |
| Exame (extrair o relevante do volume) | **Coberto** | `src/core/findings.py` (modelo `Finding` com escala única e impressão digital estável), deduplicação e ordenação por severidade |
| Análise (correlacionar entre fontes) | **Parcial** | `src/core/correlation.py` correlaciona achado estático com runtime e monta cadeias ATT&CK. A correlação **entre capturas** da mesma série é fraca (itens `C-156` e `F-218`) |
| Apresentação | **Parcial** | Laudo HTML com abas Findings, Processes e ATT&CK. Falta o laudo como **arquivo** exportável (item `C-149`) e o relatório executivo (`F-061`) |
| Timeline como produto da análise | **Parcial** | Existe tela de linha do tempo e `src/core/events.py`, mas os eventos são **derivados da captura** (`events_from_capture`), então herdam a cegueira do snapshot (item `C-155`) |

---

## 3. NIST SP 800-92 — Guide to Computer Security Log Management

O ponto central da norma para esta ferramenta: **o log durável é separado do
estado corrente**. A memória do que aconteceu não mora na fotografia.

| Item da norma | Situação | Evidência |
|---|---|---|
| Log em formato durável e append-only | **Parcial** | A série de capturas é encadeada por digest e nunca sofre `DELETE` cru: remoção é por lápide (`src/core/retention.py`). Mas o registro é de **estado periódico**, não de evento |
| Retenção declarada e aplicada | **Coberto** | Retenção granular por tipo de captura, com lápide |
| Proteção do log contra alteração | **Coberto** | Captura cifrada com chave pública do analista (RSA-4096) e assinada pelo agente (RSA-3072), em `src/core/crypto.py` e `src/core/custody.py` |
| Sincronização de tempo entre fontes | **Parcial** | Ver `clock_offset` acima |
| Centralização | **Coberto** | Modelo agente/servidor com store-and-forward |

**Distância declarada.** Esta é a norma de que a ferramenta está mais longe por
**desenho**, e não por descuido: ela é um observador periódico, não um coletor de
log contínuo. O item `C-155` discute inverter isso; o `C-156` discute extrair
mais do que já existe sem aumentar o que se guarda.

---

## 4. ISO/IEC 27037 — Identificação, coleta, aquisição e preservação

| Item da norma | Situação | Evidência |
|---|---|---|
| Identificação do dispositivo | **Coberto** | UUID do agente, hostname, todos os FQDNs e endereços (`collect_host_names`) |
| Aquisição com integridade verificável | **Coberto** | SHA-256 do objeto, com **escopo do hash declarado** (`full` ou `excerpt`), para que hash parcial nunca seja lido como identificação do objeto inteiro |
| Preservação e cadeia de custódia | **Coberto** | `src/core/custody.py`: digest do conteúdo em claro, assinatura do agente e elo com a captura anterior |
| Registro de quem, quando e como | **Parcial** | A captura registra o agente, o instante e a versão do coletor. Falta o **duplo tempo** (quando ocorreu × quando foi observado), item `C-157` |
| Documentar limitações da aquisição | **Coberto** | Quando o orçamento de bytes se esgota, ou o objeto não é arquivo comum, a custódia registra o motivo em vez de omitir |
| Minimizar alteração do alvo | **Coberto** | O agente não escreve laudo no host inspecionado, e o gerador de cenário planta artefatos discretos sem alterar o comportamento do resto do host (decisão D-025) |

---

## 5. Práticas de mercado usadas como referência

Não são normas, são o estado da prática. Servem para dizer onde esta ferramenta
se posiciona.

| Prática | Como esta ferramenta se compara |
|---|---|
| **osquery**: consultas agendadas rodam por padrão em modo **diferencial**, emitindo linhas adicionadas e removidas, e não fotografias completas | A ferramenta guarda fotografia completa e calcula o diferencial depois (`src/core/snapshot_diff.py`). Escolha ligada à custódia: a peça é a captura íntegra e assinada, não o delta. Custo: a transição entre duas fotos é inferida, não observada |
| **Sysmon**: evento discreto gravado no log do sistema, com carimbo próprio | Equivalente parcial nas sondas eBPF, mas o evento é agregado na árvore de processos antes de virar registro (item `C-155`) |
| **Super timeline** (log2timeline/plaso): fundir muitas fontes numa linha do tempo única | Existe tela de linha do tempo, alimentada por uma fonte só (a própria captura). Fundir com fontes externas do host é trabalho em aberto |
| **Bitemporalidade** (Snodgrass; período de aplicação no SQL:2011) | Não implementado. Item `C-157` |

---

## 6. O que esta ferramenta deliberadamente NÃO faz

Registrado para que a ausência não seja lida como esquecimento.

| Não faz | Decisão que tirou |
|---|---|
| Captura de memória bruta em massa (LiME e similares) | D-032; removido do escopo em 2026-08-19 |
| Análise de imagem de memória (Volatility) | Bancada, é o passo depois do laudo |
| Captura integral de tráfego | D-032: dizer que "500 MB foram para o IP X" é o trabalho; o conteúdo é bancada |
| Bloqueio, contenção ou resposta ativa | A ferramenta é forense, não EDR (D-024) |
| Deduzir quais achados vieram do cenário de teste | D-034: só o nome do script é mapeado; o resto tem que ser descoberta legítima, senão a prova é circular |

---

## Referências

- IETF **RFC 3227**, *Guidelines for Evidence Collection and Archiving*: https://www.rfc-editor.org/rfc/rfc3227
- NIST **SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response*: https://csrc.nist.gov/pubs/sp/800/86/final
- NIST **SP 800-92**, *Guide to Computer Security Log Management*: https://csrc.nist.gov/pubs/sp/800/92/final
- **ISO/IEC 27037:2012**, *Guidelines for identification, collection, acquisition and preservation of digital evidence*: https://www.iso.org/standard/44381.html
- **osquery**, modos de resultado (differential e snapshot): https://osquery.readthedocs.io/en/stable/deployment/logging/
- **plaso / log2timeline**: https://plaso.readthedocs.io/
