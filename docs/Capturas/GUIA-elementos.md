# Guia de elementos, tooltips e menus (Sys-Inspector v1.0.0)

Referencia para o manual: cada tela, seus tooltips (`title=`), acoes clicaveis e baloes de ajuda.

Tooltips nativos (`title=`) nao aparecem em captura headless; o texto deles esta aqui.


---

## Manager / Frota  (`/`)


### Tooltips (passar o mouse)

- AGENDADOR: proxima coleta esperada, a partir do ciclo do agente (capture_duration + interval). O agente coleta sozinho nessa cadencia; o icone de captura na acao pede uma coleta agora, fora do ciclo.
- APENAS LAB: gera cenario de teste, ESPERA ficar pronto e captura em seguida. Entra na fila; o agente executa no proximo check-in
- Abrir laudo, historico, pedir captura agora, cenario de teste (lab), reiniciar
- Abrir o laudo forense deste agente
- Achados criticos na ultima captura
- Achados de severidade alta
- Achados de severidade baixa
- Achados de severidade media
- Capturas anteriores deste agente e comparacao entre duas: mostra o que mudou de uma para a outra
- Endereco pela rota de saida ate o servidor
- Ha quanto tempo o AGENTE esta coletando (desde que subiu)
- Ha quanto tempo o HOST esta ligado (desde o boot)
- Momento da ultima captura recebida, hora local e UTC
- Nome curto e UUID estavel da origem da captura
- Nome de dominio: o mesmo host aparece com nomes diferentes em sistemas diferentes
- ONLINE: reportou dentro do intervalo esperado
- Reiniciar o agente (entra na fila)
- Solicitar captura agora. Entra na fila e o agente executa no proximo check-in (ate ~1 ciclo); a captura leva o tempo configurado (capture_duration)
- Uptime do host (desde o boot) e do agente (desde que subiu)
- Verde = reportou dentro do intervalo esperado; vermelho = passou de dois ciclos sem reportar
- chaos rodando por 300s; pronto para captura; captura de 15s entregue
- chaos rodando por 300s; pronto para captura; captura de 20s entregue

---

## Linha do tempo  (`/timeline`)


### Tooltips (passar o mouse)

- A seta em espiral abre este processo na arvore da captura de onde o evento saiu; o relogio indica que a hora ja foi corrigida pelo desvio do host
- Abrir este processo na arvore da captura de onde este evento saiu. Se ainda assim ele nao aparecer, a propria tela avisa.
- Account Manipulation: SSH Authorized Keys
Tatica: Persistence

Adicionar uma chave publica ao authorized_keys da acesso remoto silencioso e sem senha, que sobrevive a troca de senha.
- Avaliado: nenhum sinal de risco levantado neste processo
- Boot or Logon Autostart Execution
Tatica: Persistence, Privilege Escalation

Mecanismo generico de autostart que roda o codigo do atacante como parte da inicializacao do sistema ou do usuario.
- Create or Modify System Process: Systemd Service
Tatica: Persistence, Privilege Escalation

Uma unit do systemd sobe o payload no boot, em geral como root, e pode reinicia-lo sozinho quando ele morre.
- Critical (score 11): executa de diretorio gravavel + binario apagado em execucao + biblioteca de local nao confiavel
- Critical (score 131): executa de diretorio gravavel + biblioteca de local nao confiavel + processo defunto
- Critical (score 19): executa de diretorio gravavel + biblioteca de local nao confiavel + EDR/AV
- Critical (score 3): executa de diretorio gravavel + biblioteca de local nao confiavel
- Critical (score 35): executa de diretorio gravavel + assinatura de mineracao / uso de GPU + biblioteca de local nao confiavel
- Critical (score 67): executa de diretorio gravavel + biblioteca de local nao confiavel + falha de rede
- File and Directory Permissions Modification: Linux
Tatica: Defense Evasion

Mudar atributos do arquivo, como o flag imutavel, faz o artefato resistir a remocao e a inspecao; e tecnica comum de anti-forense e anti-remocao sobre o proprio arquivo.
- High (score 49): assinatura de mineracao / uso de GPU + biblioteca de local nao confiavel + EDR/AV
- Info (score 128): processo defunto
- Instante corrigido pelo desvio de relogio do host, para ser comparavel entre maquinas
- Low (score 64): falha de rede
- Medium (score 1): biblioteca de local nao confiavel
- Natureza do evento; o icone repete o do filtro acima
- Nivel de risco e, ao lado, o numero cru do anomaly score. O numero e um campo de bits: cada bit e um sinal observado, nao uma magnitude. Veja o ? acima.
- Process Injection
Tatica: Defense Evasion, Privilege Escalation

Codigo do atacante roda DENTRO de um processo legitimo, herdando a identidade e os privilegios dele e sem deixar um processo separado para notar.
- Scheduled Task/Job
Tatica: Execution, Persistence, Privilege Escalation

Um mecanismo de agendamento relanca o payload sozinho, o que transforma uma execucao pontual em algo que volta.
- Scheduled Task/Job: Cron
Tatica: Execution, Persistence, Privilege Escalation

Uma entrada de cron relanca o payload do atacante em horario marcado, restaurando o acesso mesmo depois de o processo ser morto.
- Tecnica MITRE ATT&CK associada, quando ha. Passe o mouse para o nome e a tatica.
- achado
- achado: clique para ver so este tipo
- arquivo apagado: clique para ver so este tipo
- arquivo gravado: clique para ver so este tipo
- captura
- captura: clique para ver so este tipo
- comando executado: clique para ver so este tipo
- conexao de rede: clique para ver so este tipo
- persistencia
- persistencia: clique para ver so este tipo
- processo iniciou
- processo iniciou: clique para ver so este tipo
- processo terminou: clique para ver so este tipo
- sessao/autenticacao: clique para ver so este tipo

---

## Fila  (`/queue`)


### Tooltips (passar o mouse)

- Baixa: atende depois dos demais
- Capturas ja gravadas como evidencia
- Capturas que nao puderam ser gravadas. Diferente de zero aqui merece investigacao: e evidencia que chegou e nao ficou.
- Capturas recebidas e ainda nao gravadas
- Investigacao: atende este agente primeiro
- Padrao

---

## Comandos  (`/log`)


### Tooltips (passar o mouse)

- APENAS LAB: executa o cenario de teste, que planta artefatos conhecidos para aferir a deteccao.
- Captura sob demanda: o agente coleta agora, em vez de esperar o proximo ciclo.
- Capturas deste agente, para achar a que este comando produziu
- Eventos deste agente na janela que cobre este comando
- Hijack Execution Flow: Dynamic Linker Hijacking
Tatica: Persistence, Privilege Escalation, Defense Evasion

Precarregar uma biblioteca pelo ld.so.preload injeta codigo do atacante em todo processo dinamicamente ligado, o classico rootkit de userland.
- Laudo mais recente deste agente
- Reinicia o processo do agente no host inspecionado.

---

## Capacidades da frota  (`/capabilities`)


### Tooltips (passar o mouse)

- BTF no kernel permite o motor CO-RE
- Muda como conteiner e limite de recurso sao identificados
- Sem eBPF a captura se reduz ao que /proc mostra
- Sem privilegio o laudo sai incompleto sem erro aparente

---

## Laudo do agente  (`/agent/<uuid>`)


### Tooltips (passar o mouse)

- A ferramenta olhou e nao havia valor. A ausencia aqui e uma observacao, e nao uma falha de coleta.
- A linha literal encontrada no arquivo: a prova crua.
- APENAS LAB: cenario de teste por 300s, depois captura
- Accessing GPU Resources
- Active SSH Connection
- Aliases de /etc/hosts e DNS reverso por interface. O mesmo host aparece com nomes diferentes em logs de sistemas diferentes.
- Anomaly Score Rules
- AppArmor Profile:
Name (Mode)
- Atributos do arquivo lidos por lsattr (ex.: imutavel).
- Binario apagado do disco com o processo em execucao
- Capturas anteriores deste agente e comparacao entre duas
- Comentario/identidade de cada chave, para reconhecer o dono.
- Confianca (confirmado): fato verificado: o objeto foi lido ou existe
- Confianca (heuristico): regra local; admite falso positivo conhecido
- Confianca (provavel): forte indicio, coerente, mas nao confirmado
- Contagem de itens inventariados nesta captura (baseline).
- Containerized
- Containerized Process
- Crypto Mining Signature
- Current Disk I/O (Bytes/sec) - Hot Activity
- Custodia: o que foi preservado do artefato para a pericia. Hoje a ferramenta coleta metadado; hash e copia do artefato entram no roadmap.
- Filtra a aba Findings para os 1 achado(s) que citam esta tecnica
- Filtra a aba Findings para os 2 achado(s) que citam esta tecnica
- GPU Activity
- Identificador do processo envolvido.
- Identificador estavel da origem da captura: hostname e endereco mudam, este nao.
- Kernel Limits (v1/v2)
- Limpa o filtro de severidade e volta a mostrar todos os achados desta captura
- Linha de comando do processo envolvido.
- Metadados do arquivo (dono, permissao, datas mtime/ctime/atime): permite datar o artefato e ver quem podia escrever.
- Mining Signature
- Momento em que o agente coletou estes dados. O laudo descreve o host NAQUELE instante, e nao agora.
- Network Errors
- Network Issues: 1 Drops, 0 Retransmits
- Network Issues: 168 Drops, 0 Retransmits
- Network Issues: 2 Drops, 0 Retransmits
- Network Issues: 5 Drops, 0 Retransmits
- Network Issues: 5148 Drops, 0 Retransmits
- Network Issues: 5322 Drops, 0 Retransmits
- Network Issues: 5353 Drops, 0 Retransmits
- Network Issues: 6 Drops, 0 Retransmits
- Network Issues: 9 Drops, 0 Retransmits
- Network Receive: Current Delta / Total Session
- Network Transmit: Current Delta / Total Session
- New Process
- New Processes
- Nome curto que o proprio host responde.
- Nome qualificado. Vazio significa que 'hostname -f' nao resolve neste host, o que e comum e legitimo.
- O alvo real que o mecanismo dispara: o que de fato roda.
- Objeto afetado: caminho de arquivo, unit, PID ou usuario
- Ordem sugerida para ler este laudo
- PID 1
- PID 101
- PID 102
- PID 103
- PID 1077
- PID 108
- PID 1083
- PID 1089
- PID 11
- PID 110
- PID 111
- PID 1141
- PID 1180
- PID 1181
- PID 1183
- PID 1195
- PID 12
- PID 12026
- PID 13
- PID 14
- PID 1474
- PID 1475
- PID 1486
- PID 1496
- PID 1498
- PID 15
- PID 15233
- PID 1569
- PID 157
- PID 16
- PID 1603
- PID 1610
- PID 1611
- PID 1624
- PID 16390
- PID 16620
- PID 16621
- PID 16635
- PID 16638
- PID 16641
- PID 16647
- PID 16652
- PID 16655
- PID 16662
- PID 16668
- PID 16680
- PID 16683
- PID 16686
- PID 1669
- PID 16690
- PID 16691
- PID 16694
- PID 16700
- PID 16701
- PID 16705
- PID 16716
- PID 16735
- PID 16747
- PID 16786
- PID 16828
- PID 16845
- PID 17
- PID 176
- PID 178
- PID 17814
- PID 17958
- PID 18
- PID 18312
- PID 18316
- PID 18317
- PID 18318
- PID 18319
- PID 18323
- PID 18324
- PID 18325
- PID 18326
- PID 18330
- PID 18331
- PID 18332
- PID 18333
- PID 18334
- PID 18338
- PID 18339
- PID 18340
- PID 18341
- PID 18345
- PID 18346
- PID 18347
- PID 18348
- PID 18352
- PID 18353
- PID 18354
- PID 18355
- PID 18359
- PID 18360
- PID 18361
- PID 18362
- PID 18366
- PID 18367
- PID 18368
- PID 18369
- PID 18373
- PID 18374
- PID 18375
- PID 18376
- PID 18380
- PID 1896
- PID 19
- PID 1900
- PID 1913
- PID 1914
- PID 1929
- PID 1931
- PID 1934
- PID 1940
- PID 1969
- PID 2
- PID 20
- PID 21
- PID 214
- PID 217
- PID 218
- PID 22
- PID 221
- PID 224
- PID 227
- PID 23
- PID 239
- PID 25
- PID 2555
- PID 2556
- PID 2557
- PID 2564
- PID 26
- PID 2643
- PID 2644
- PID 27
- PID 28
- PID 29
- PID 3
- PID 31
- PID 32
- PID 33
- PID 34
- PID 35
- PID 37
- PID 38
- PID 39
- PID 4
- PID 40
- PID 41
- PID 42
- PID 43
- PID 44
- PID 446
- PID 45
- PID 453
- PID 46
- PID 464
- PID 465
- PID 47
- PID 477
- PID 479
- PID 48
- PID 49
- PID 5
- PID 50
- PID 500
- PID 501
- PID 503
- PID 51
- PID 515
- PID 516
- PID 518
- PID 519
- PID 52
- PID 53
- PID 541
- PID 542
- PID 544
- PID 55
- PID 56
- PID 57
- PID 58
- PID 59
- PID 6
- PID 61
- PID 617
- PID 632
- PID 639
- PID 640
- PID 67
- PID 68
- PID 689
- PID 69
- PID 70
- PID 71
- PID 72
- PID 73
- PID 74
- PID 75
- PID 76
- PID 77
- PID 78
- PID 785
- PID 79
- PID 80
- PID 81
- PID 82
- PID 83
- PID 839
- PID 84
- PID 85
- PID 86
- PID 877
- PID 88
- PID 89
- PID 90
- PID 9041
- PID 935
- PID 937
- PID 947
- PID 956
- PID 958
- PID 961
- PID 962
- PID 964
- PID 97
- Privileged (Sudo)
- Process Frozen by EDR/AV (Wchan Wait)
- Process is running without mandatory access control enforcement.
- Qual coletor produziu este achado (ebpf, persistence, integrity, heuristic...)
- Quantas chaves SSH aceitam login para este usuario.
- Quantos achados citam esta tecnica
- Regioes de memoria gravaveis e executaveis ao mesmo tempo.
- Reset Tree View
- Restart the agent (queued)
- Running via Sudo
- SSH Connections
- Save PDF
- Se o processo gera codigo por natureza (JIT), o que explica o W+X sem inocenta-lo.
- Security Inspectors - EDR (Endpoint Detection and Response) / AV (Antivirus)
- Security Inspectors - EDR/AV
- Severidade Critical. O numero e um campo de bits, nao uma magnitude: cada bit e um sinal observado.
Sinais presentes (score 11):
- executa de diretorio gravavel (+2, High): A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software instalado nao roda de la; e o local escolhido justamente por ser gravavel por qualquer um.
- binario apagado em execucao (+8, High): O executavel sumiu do disco com o processo vivo. Apagar a amostra apos executar e tecnica corrente para impedir analise (ATT&CK T1070.004).
- biblioteca de local nao confiavel (+1, Medium): Carregou biblioteca fora dos diretorios do sistema, caminho usado para injetar codigo em processo legitimo.
- Severidade Critical. O numero e um campo de bits, nao uma magnitude: cada bit e um sinal observado.
Sinais presentes (score 19):
- executa de diretorio gravavel (+2, High): A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software instalado nao roda de la; e o local escolhido justamente por ser gravavel por qualquer um.
- biblioteca de local nao confiavel (+1, Medium): Carregou biblioteca fora dos diretorios do sistema, caminho usado para injetar codigo em processo legitimo.
- EDR/AV (+16, Info): A propria ferramenta de seguranca do host. Aparece para explicar o que esta observando o sistema, nao como suspeita.
- Severidade Critical. O numero e um campo de bits, nao uma magnitude: cada bit e um sinal observado.
Sinais presentes (score 3):
- executa de diretorio gravavel (+2, High): A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software instalado nao roda de la; e o local escolhido justamente por ser gravavel por qualquer um.
- biblioteca de local nao confiavel (+1, Medium): Carregou biblioteca fora dos diretorios do sistema, caminho usado para injetar codigo em processo legitimo.
- Severidade Critical. O numero e um campo de bits, nao uma magnitude: cada bit e um sinal observado.
Sinais presentes (score 35):
- executa de diretorio gravavel (+2, High): A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software instalado nao roda de la; e o local escolhido justamente por ser gravavel por qualquer um.
- assinatura de mineracao / uso de GPU (+32, Medium): Nome ou acesso a dispositivo compativel com mineracao. Legitimo em host de computacao grafica, anomalo em servidor.
- biblioteca de local nao confiavel (+1, Medium): Carregou biblioteca fora dos diretorios do sistema, caminho usado para injetar codigo em processo legitimo.
- Severidade Critical. O numero e um campo de bits, nao uma magnitude: cada bit e um sinal observado.
Sinais presentes (score 67):
- executa de diretorio gravavel (+2, High): A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software instalado nao roda de la; e o local escolhido justamente por ser gravavel por qualquer um.
- biblioteca de local nao confiavel (+1, Medium): Carregou biblioteca fora dos diretorios do sistema, caminho usado para injetar codigo em processo legitimo.
- falha de rede (+64, Low): Retransmissoes ou descartes TCP no processo. Indica problema de rede ou destino que nao responde; sozinho nao e indicio de seguranca.
- Severidade Info (score 128), o pior da subarvore.
Este processo soma 49.
Sinais no maximo da subarvore:
- processo defunto (+128, Info): Terminou e aguarda o pai recolher o status. E rotina de sistema; so informa quando acumula ou quando o pai desapareceu.
- Severidade Info. O numero e um campo de bits, nao uma magnitude: cada bit e um sinal observado.
Sinais presentes (score 128):
- processo defunto (+128, Info): Terminou e aguarda o pai recolher o status. E rotina de sistema; so informa quando acumula ou quando o pai desapareceu.
- Severidade Low (score 64), o pior da subarvore.
Este processo soma 0.
Sinais no maximo da subarvore:
- falha de rede (+64, Low): Retransmissoes ou descartes TCP no processo. Indica problema de rede ou destino que nao responde; sozinho nao e indicio de seguranca.
- Severidade Low. O numero e um campo de bits, nao uma magnitude: cada bit e um sinal observado.
Sinais presentes (score 64):
- falha de rede (+64, Low): Retransmissoes ou descartes TCP no processo. Indica problema de rede ou destino que nao responde; sozinho nao e indicio de seguranca.
- Solicitar captura agora: entra na fila, o agente executa no proximo check-in (ate ~1 ciclo)
- Standard: Normal application.
Inspector: Security tool monitoring other processes via Fanotify.
- T1053.003 - Scheduled Task/Job: Cron
Tatica: Execution, Persistence, Privilege Escalation
Clique para ver na aba ATT&CK.
- T1055 - Process Injection
Tatica: Defense Evasion, Privilege Escalation
Clique para ver na aba ATT&CK.
- T1098.004 - Account Manipulation: SSH Authorized Keys
Tatica: Persistence
Clique para ver na aba ATT&CK.
- T1222.002 - File and Directory Permissions Modification: Linux
Tatica: Defense Evasion
Clique para ver na aba ATT&CK.
- T1543.002 - Create or Modify System Process: Systemd Service
Tatica: Persistence, Privilege Escalation
Clique para ver na aba ATT&CK.
- T1547 - Boot or Logon Autostart Execution
Tatica: Persistence, Privilege Escalation
Clique para ver na aba ATT&CK.
- Tamanho total das regioes suspeitas, em KB.
- Top CPU Usage
- Top Disk I/O
- Top Memory (RSS)
- Top Network Activity
- Top Priority (Nice)
- Total Disk I/O during Session (Accumulated in Tree)
- Unsafe Path
- Unsafe Path (/tmp, /dev/shm)
- Usuario dono do mecanismo (ex.: dono do authorized_keys).
- Veio de pacote? verificado? Separa o que pertence ao sistema do que foi plantado (packaged:false = fora do gerenciador).
- Zombie Process
Parent PID 0 not found in tree.
- Zombie Process
Parent PID 2712 not found in tree.
- Zombie Process
Waiting for Parent PID: 16621
Parent Cmd: /bin/bash /opt/sys-inspector/tools/chaos_maker.sh --all --duration 300
Parent User: root
- Zombie Process
Waiting for Parent PID: 16690
Parent Cmd: python3 /tmp/chaos_artifacts/artifact_zombie.py
Parent User: root
- Zombies

### Baloes de ajuda (icone "?")

- **Sinais do anomaly score (campo de bits)** - +2 executa de diretorio gravavel High +8 binario apagado em execucao High +256 atributo imutavel Medium +32 assinatura de mineracao / uso de GPU Medium +1 biblioteca de local nao confiavel Medium +4 ferramenta de rede Low +64 falha de rede Low +16 EDR/AV Info +128 processo defunto Info * Cada bit e um sinal observado. O VALOR somado nao mede gravidade: o nivel exibido vem dos sinais presentes, e s
- **Como ler os achados** - Cada linha e um achado : o que foi encontrado, quao grave, QUEM encontrou (a fonte) e a evidencia bruta que sustenta a conclusao. Clique num achado para abrir a evidencia, a acao recomendada, a confianca e a custodia . Severidade e o que fazer: Critical artefato ativo de alto risco: conter agora (confirmar, preservar, isolar) High forte indicio: investigar hoje Medium sinal relevante: revisar no t
- **O que e a matriz ATT&CK** - MITRE ATT&CK e um catalogo publico de tecnicas de ataque observadas em invasoes reais, organizadas por tatica (o objetivo do atacante naquele passo: executar, persistir, evadir, exfiltrar...). As tecnicas abaixo sao as que os achados desta captura citam, apresentadas na ordem do kill chain (das primeiras taticas as ultimas), para se ler como uma progressao e nao como etiquetas soltas. O numero e q

### Acoes clicaveis (funcao -> rotulos)

- `filterFindings()` : Ver todos os niveis
- `filterFindingsByTechnique()` : ◀ Ver achados
- `printStorage()` : Print
- `resetTree()` : ⟳
- `setFilter()` : ☢️, ⛏️, ✨, ❌, 💊, 📦, 🔌, 🕹️
- `showTab()` : ATT&CK, Findings, Processes
- `sortView()` : ⚖️, 🌐, 💾, 🔥, 🧠
- `toggleDet()` : (icone)
- `toggleDisk()` : +
- `toggleFinding()` : (icone)