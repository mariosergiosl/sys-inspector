# Capturas de tela (Sys-Inspector v1.4.1)

Telas do painel do servidor no laboratório em 10/10/2026: servidor na `openSUSE`
(192.168.56.161) e três agentes (`openSUSE`, `gwlocal` e `sles15efiboot1`), em
modo ocioso. O texto de cada tooltip, balão de ajuda e ação clicável está em
[GUIA-elementos.md](GUIA-elementos.md), porque tooltip não aparece em captura de
tela.

As capturas de agosto (v1.0.0) foram substituídas: mostravam "Frota" e "Laudo",
nomes que a interface deixou na 1.4.0.

## 1. Hosts

Tela inicial (Manager): um host por linha, com severidade da última captura,
presença e ritmo do agente, e as ações.

![Hosts](01_hosts/hosts.jpg)

## 2. Linha do tempo

Calendário de achados e descobertas de todos os hosts. Cada dia mostra a faixa de
severidade dos achados distintos, os achados novos e o total de eventos.

![Linha do tempo: calendário de todos os hosts](02_linha_do_tempo/calendario_todos_os_hosts.jpg)

Lista de um dia: faixa das 24 horas, filtros por janela e por tipo de evento, a
leitura da sequência (correlação) e os eventos em ordem cronológica. A hora sem
evento diz "sem evento", e o processo sem sinal de risco diz "nada encontrado".

![Linha do tempo: lista de um dia](02_linha_do_tempo/dia_todos_os_hosts.jpg)

O mesmo dia, dentro de um host: o título diz o host e o dia, e o corte da lista é
avisado.

![Linha do tempo: um host num dia](02_linha_do_tempo/dia_de_um_host.jpg)

## 3. Capturas / Coletas

Calendário de capturas de todos os hosts: quantas capturas, a faixa da pior
captura do dia e as marcas (mudaram, fora do padrão, lacunas).

![Capturas / Coletas: calendário de todos os hosts](03_capturas_coletas/calendario_todos_os_hosts.jpg)

Dia selecionado, com a faixa das 24 horas abaixo do mês. A hora sem captura diz
"sem captura".

![Capturas / Coletas: dia selecionado](03_capturas_coletas/dia_selecionado.jpg)

Lista do dia por host: horário capturado (agente) e coletado (servidor), atraso
da coleta, tipo, achados e marcas com o detalhe de cada uma. Capturas iguais em
sequência viram um grupo, com "primeira" e "ultima".

![Capturas / Coletas: horas e lista do dia](03_capturas_coletas/dia_horas_e_lista.jpg)

## 4. Fila de ingestão

![Fila de ingestão](04_fila/fila.jpg)

## 5. Registro de comandos

![Registro de comandos](05_comandos/comandos.jpg)

## 6. Capacidades dos hosts

![Capacidades dos hosts](06_capacidades/capacidades.jpg)

## 7. Relatório do agente

Aba Findings: barra de navegação entre capturas (com o tipo da captura e os botões
Linha do tempo e Capturas / Coletas do host), inventário e achados por prioridade.

![Relatório: achados](07_relatorio/achados.jpg)

Achado de kernel tingido aberto: os módulos que carregam a marca, com horário de
carga, arquivo conferido contra a memória, sha256, pacote e assinante.

![Relatório: kernel tingido](07_relatorio/achado_kernel_tingido.jpg)

Achado com o bloco "Encaminhamento para analise": o que a ferramenta não conclui,
por quê, e sobre qual objeto.

![Relatório: encaminhamento para análise](07_relatorio/achado_encaminhamento_para_analise.jpg)

Aba Processes, com o inventário recolhido e a árvore aberta.

![Relatório: árvore de processos](07_relatorio/processos_arvore.jpg)

Detalhe de um processo.

![Relatório: detalhe do processo](07_relatorio/processo_detalhe.jpg)

Aba ATT&CK: as técnicas citadas pelos achados, na ordem do kill chain.

![Relatório: ATT&CK](07_relatorio/attack.jpg)

## 8. Histórico do agente

Comportamento ao longo das capturas recentes e a lista de capturas para comparar
ou baixar.

![Histórico do agente](08_historico/historico.jpg)

## Como reproduzir

As capturas foram feitas no Chrome, janela de 1600 por 1000, a partir do painel
`https://192.168.56.161:8443/`. O guia de elementos foi extraído das mesmas
páginas por um script que lê o HTML servido e reúne os atributos `title`, os
balões `.balao` e `.score-tooltip` e os manipuladores `onclick`, agrupando valores
que mudam a cada captura.
