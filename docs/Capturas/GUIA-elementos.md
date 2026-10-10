# Guia de elementos, tooltips e menus (Sys-Inspector v1.4.1)

Referência para o manual: cada tela, seus tooltips (`title=`), balões de ajuda (ícone `?`) e ações clicáveis. O texto foi extraído das páginas servidas pelo laboratório em 10/10/2026, com três agentes; o texto das telas não tem acento porque o código é US-ASCII.

Valores que mudam a cada captura (números de captura, contagens, scores) foram agrupados: aparece um exemplo de cada família. As capturas de tela de cada página estão no [README](README.md) desta pasta.

---

## Hosts (Manager) (`/`)

### Tooltips (passar o mouse)

- AGENDADOR: proxima captura esperada, a partir do ciclo do agente (capture_duration + interval). O agente captura sozinho nessa cadencia; o icone de captura na acao pede uma captura agora, fora do ciclo.
- APENAS LAB: gera cenario de teste, ESPERA ficar pronto e captura em seguida. Entra na fila; o agente executa no proximo check-in
- Abrir o relatorio deste agente
- Abrir relatorio, historico, pedir captura agora, cenario de teste (lab), reiniciar
- Achados da ultima captura, por severidade: Critical, High, Medium, Low
- Capturas anteriores deste agente e comparacao entre duas: mostra o que mudou de uma para a outra
- Critical: 0 achado(s) na ultima captura
- Endereco usado na rota ate o servidor
- Enderecos deste host. O primeiro e o usado na rota de saida ate o servidor
- Estado do AGENTE, nao do host: verde = falou com o servidor dentro do intervalo esperado; vermelho = passou de dois ciclos sem falar
- Fila de comandos: 0 pedido(s) aguardando este agente perguntar. Clique para ver, cancelar ou limpar. Nao confundir com a fila de ingestao (capturas), na tela Fila.
- Ha quanto tempo o AGENTE esta capturando (desde que subiu)
- Ha quanto tempo o HOST esta ligado (desde o boot)
- High: 0 achado(s) na ultima captura
- Low: 2 achado(s) na ultima captura
- Medium: 0 achado(s) na ultima captura
- Momento da ultima captura recebida, hora local e UTC
- Nome curto e UUID estavel da origem da captura
- Nome principal
- Nomes de dominio deste host. O principal em destaque; os demais sao aliases e reverso de DNS
- O AGENTE falou com o servidor dentro do intervalo esperado
- Outros enderecos deste host
- Outros nomes pelos quais este host e conhecido (aliases e DNS reverso)
- Reiniciar o agente (entra na fila)
- Solicitar captura agora. Entra na fila e o agente executa no proximo check-in (ate ~1 ciclo); a captura leva o tempo configurado (capture_duration)
- Ultima vez que este AGENTE falou com o servidor
- Uptime do host (desde o boot) e do agente (desde que subiu)
- chaos rodando por 300s; pronto para captura (log /tmp/si_chaos_1791578164-16768.log); captura de 15s entregue

---

## Linha do tempo: calendario de todos os hosts (`/timeline`)

### Tooltips (passar o mouse)

- Achados distintos do dia; clique para abrir a lista de eventos do dia
- Achados que apareceram pela primeira vez neste dia
- Alto: 13 achado(s)
- Baixo: 45 achado(s)
- Critico: 2 achado(s)
- Demais eventos: processos, conexoes, arquivos, persistencia, sessoes, comandos

### Balões de ajuda (ícone "?")

- Como ler o calendario Cada cor e uma severidade, com a letra e a quantidade: C critico, A alto, M medio, B baixo. Info fica de fora: e inventario e aparece em toda captura. A borda do dia (ou da hora) tem a cor da severidade mais alta presente. mudou : a captura tem achados Medio ou acima diferentes da captura anterior do mesmo host. fora do padrao : o total de achados Medio ou acima difere do val (...)

---

## Linha do tempo: lista de um dia (`/timeline?dia=2026-10-10`)

### Tooltips (passar o mouse)

- 4 achado(s) vistos pela primeira vez no dia
- 417 evento(s) nesta hora
- A mesma leitura apareceu 115 vezes nesta janela
- A seta em espiral abre este processo na arvore da captura de onde o evento saiu; o relogio indica que a hora ja foi corrigida pelo desvio do host
- Abrir este processo na arvore da captura de onde este evento saiu. Se ainda assim ele nao aparecer, a propria tela avisa.
- Account Manipulation: SSH Authorized Keys Tatica: Persistence Adicionar uma chave publica ao authorized_keys da acesso remoto silencioso e sem senha, que sobrevive a troca de senha.
- Alto: 2 achado(s) distintos nesta hora
- Avaliado: nenhum sinal de risco levantado neste processo
- Baixo: 17 achado(s) distintos nesta hora
- Boot or Logon Autostart Execution Tatica: Persistence, Privilege Escalation Mecanismo generico de autostart que roda o codigo do atacante como parte da inicializacao do sistema ou do usuario.
- Boot or Logon Autostart Execution: Kernel Modules and Extensions Tatica: Persistence, Privilege Escalation Um modulo de kernel malicioso carregado no boot da a forma mais privilegiada de persistencia e pode esconder outros artefatos.
- Clique para listar so esta hora
- Create or Modify System Process: Systemd Service Tatica: Persistence, Privilege Escalation Uma unit do systemd sobe o payload no boot, em geral como root, e pode reinicia-lo sozinho quando ele morre.
- Critical (score 1027): executa de diretorio gravavel + biblioteca de local nao confiavel + carregou modulo de kernel (exemplo: o texto lista os sinais presentes no processo)
- Critico: 2 achado(s) distintos nesta hora
- File and Directory Permissions Modification: Linux Tatica: Defense Evasion Mudar atributos do arquivo, como o flag imutavel, faz o artefato resistir a remocao e a inspecao; e tecnica comum de anti-forense e anti-remocao sobre o proprio arquivo.
- High (score 16777216): trocou a raiz do sistema de arquivos (exemplo: o texto lista os sinais presentes no processo)
- Hijack Execution Flow: Dynamic Linker Hijacking Tatica: Persistence, Privilege Escalation, Defense Evasion Precarregar uma biblioteca pelo ld.so.preload injeta codigo do atacante em todo processo dinamicamente ligado, o classico rootkit de userland.
- Info (score 128): processo defunto (exemplo: o texto lista os sinais presentes no processo)
- Instante corrigido pelo desvio de relogio do host, para ser comparavel entre maquinas
- Low (score 131072): apagou arquivo (exemplo: o texto lista os sinais presentes no processo)
- Natureza do evento; o icone repete o do filtro acima
- Nivel de risco e, ao lado, o numero cru do anomaly score. O numero e um campo de bits: cada bit e um sinal observado, nao uma magnitude. Veja o ? acima.
- Process Injection Tatica: Defense Evasion, Privilege Escalation Codigo do atacante roda DENTRO de um processo legitimo, herdando a identidade e os privilegios dele e sem deixar um processo separado para notar.
- Rootkit Tatica: Defense Evasion Codigo que esconde processos, arquivos ou conexoes das ferramentas que um administrador usaria, de modo que o sistema relata errado o proprio estado.
- Scheduled Task/Job Tatica: Execution, Persistence, Privilege Escalation Um mecanismo de agendamento relanca o payload sozinho, o que transforma uma execucao pontual em algo que volta.
- Tecnica MITRE ATT&CK associada, quando ha. Passe o mouse para o nome e a tatica.
- Valid Accounts Tatica: Defense Evasion, Persistence, Privilege Escalation, Initial Access Usa credenciais legitimas em vez de malware, e por isso a atividade passa por toda checagem que pergunta se o usuario tem permissao.
- achado
- achado: clique para ver so este tipo
- arquivo apagado: clique para ver so este tipo
- arquivo gravado: clique para ver so este tipo
- captura
- captura: clique para ver so este tipo
- comando executado: clique para ver so este tipo
- conexao de rede
- conexao de rede: clique para ver so este tipo
- persistencia
- persistencia: clique para ver so este tipo
- processo iniciou
- processo iniciou: clique para ver so este tipo
- processo terminou: clique para ver so este tipo
- sessao/autenticacao: clique para ver so este tipo

### Balões de ajuda (ícone "?")

- Horas do dia Cada coluna e uma hora: quantos eventos houve, a faixa dos achados distintos daquela hora (o mesmo achado do mesmo host conta uma vez) e quantos achados apareceram pela primeira vez no dia. Clique numa hora para ver so ela. Cada cor e uma severidade, com a letra e a quantidade: C critico, A alto, M medio, B baixo. Info fica de fora: e inventario e aparece em toda captura. A borda do d (...)
- Sinais do anomaly score (campo de bits) O numero ao lado do rotulo e um campo de bits: cada bit e um sinal observado, e o valor em si nao mede gravidade. O nivel exibido e o maior entre os sinais presentes, elevado um degrau quando dois ou mais sinais de peso coincidem no mesmo processo. High executa de diretorio gravavel : A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software instal (...)

---

## Capturas / Coletas: calendario de todos os hosts (`/calendario`)

### Tooltips (passar o mouse)

- Alto: 3 achado(s) na pior captura do dia
- Baixo: 21 achado(s) na pior captura do dia
- Capturas com achados Medio ou acima diferentes da anterior do mesmo host
- Capturas cujo total de achados Medio ou acima difere do mais comum do host
- Composicao da pior captura do dia; clique para listar as capturas
- Critico: 1 achado(s) na pior captura do dia
- Intervalos sem captura bem maiores que o tipico do host

### Balões de ajuda (ícone "?")

- Como ler o calendario Cada cor e uma severidade, com a letra e a quantidade: C critico, A alto, M medio, B baixo. Info fica de fora: e inventario e aparece em toda captura. A borda do dia (ou da hora) tem a cor da severidade mais alta presente. mudou : a captura tem achados Medio ou acima diferentes da captura anterior do mesmo host. fora do padrao : o total de achados Medio ou acima difere do val (...)

---

## Capturas / Coletas: lista de um dia (`/calendario?dia=2026-10-10`)

### Tooltips (passar o mouse)

- 15 captura(s) fora do padrao do host
- 2 captura(s) com achados Medio ou acima diferentes da anterior
- 2 captura(s) de cenario de teste
- Alto: 1 achado(s)
- Alto: 1 achado(s) na pior captura desta hora
- Alto: 1 achado(s) no maximo do grupo
- Alto: 3 achado(s) na pior captura do dia
- Baixo: 15 achado(s)
- Baixo: 2 achado(s) no maximo do grupo
- Baixo: 21 achado(s) na pior captura desta hora
- Baixo: 21 achado(s) na pior captura do dia
- Captura completa do ciclo do agente: eBPF, inventario e achados.
- Captura feita logo depois de o chaos_maker montar o cenario de teste. Os achados desta captura foram PLANTADOS de proposito no laboratorio.
- Capturas com achados Medio ou acima diferentes da anterior do mesmo host
- Capturas cujo total de achados Medio ou acima difere do mais comum do host
- Clique para listar so esta hora
- Coletado menos capturado: quanto a captura levou para chegar ao servidor
- Composicao da pior captura do dia; clique para listar as capturas
- Critico: 1 achado(s)
- Critico: 1 achado(s) na pior captura desta hora
- Critico: 1 achado(s) na pior captura do dia
- Intervalos sem captura bem maiores que o tipico do host

### Balões de ajuda (ícone "?")

- Como ler o calendario Cada cor e uma severidade, com a letra e a quantidade: C critico, A alto, M medio, B baixo. Info fica de fora: e inventario e aparece em toda captura. A borda do dia (ou da hora) tem a cor da severidade mais alta presente. mudou : a captura tem achados Medio ou acima diferentes da captura anterior do mesmo host. fora do padrao : o total de achados Medio ou acima difere do val (...)
- Horas do dia Cada coluna e uma hora: quantas capturas houve, a faixa da pior delas e as marcas (Δ mudaram, ≠ fora do padrao, cen cenario de teste). Clique numa hora para listar so ela. Cada cor e uma severidade, com a letra e a quantidade: C critico, A alto, M medio, B baixo. Info fica de fora: e inventario e aparece em toda captura. A borda do dia (ou da hora) tem a cor da severidade mais alta pr (...)
- Marcas mudou : a captura tem achados Medio ou acima diferentes da captura anterior do mesmo host. fora do padrao : o total de achados Medio ou acima difere do valor mais comum daquele host nas 24 horas anteriores (com pelo menos tres capturas para comparar). lacuna : o intervalo desde a captura anterior foi bem maior que o tipico do host (agente parado, host desligado ou entrega interrompida). Ach (...)

---

## Fila de ingestao (`/queue`)

### Tooltips (passar o mouse)

- Baixa: atende depois dos demais
- Capturas ja gravadas como evidencia
- Capturas que nao puderam ser gravadas. Diferente de zero aqui merece investigacao: e evidencia que chegou e nao ficou.
- Capturas recebidas e ainda nao gravadas
- Investigacao: atende este agente primeiro
- Padrao

### Balões de ajuda (ícone "?")

- O que esta fila faz Toda captura passa por aqui antes de virar evidencia guardada, venha da rede ou da coleta local. A fila existe para o servidor nao ser derrubado por todos os hosts reportando ao mesmo tempo. Numa investigacao, porem, um host importa mais que os outros. A prioridade coloca esse host na frente sem parar a coleta dos demais: numero MENOR e atendido primeiro , e o padrao e 50, o qu (...)

---

## Registro de comandos (`/log`)

### Tooltips (passar o mouse)

- APENAS LAB: executa o cenario de teste, que planta artefatos conhecidos para aferir a deteccao.
- Captura sob demanda: o agente captura agora, em vez de esperar o proximo ciclo.
- Capturas deste agente, para achar a que este comando produziu
- Eventos deste agente na janela que cobre este comando
- Hijack Execution Flow: Dynamic Linker Hijacking Tatica: Persistence, Privilege Escalation, Defense Evasion Precarregar uma biblioteca pelo ld.so.preload injeta codigo do atacante em todo processo dinamicamente ligado, o classico rootkit de userland.
- Relatorio mais recente deste agente

### Balões de ajuda (ícone "?")

- Como ler este registro PENDING o pedido esta na fila; o servidor NUNCA inicia conexao com o host inspecionado, quem busca e o agente. SENT foi entregue ao agente. Entregue nao e aceito: o desfecho so se conhece quando ele reporta. DONE o agente reportou conclusao. FAILED falhou, ou passou de 600s sem desfecho e foi encerrado como sem retorno. Espera = tempo ate o agente recolher o pedido, limitado (...)

---

## Capacidades dos hosts (`/capabilities`)

### Tooltips (passar o mouse)

- BTF no kernel permite o motor CO-RE
- Muda como conteiner e limite de recurso sao identificados
- Sem eBPF a captura se reduz ao que /proc mostra
- Sem privilegio o relatorio sai incompleto sem erro aparente

### Balões de ajuda (ícone "?")

- Duas perguntas diferentes Deteccao : quanto vale um relatorio produzido neste host. Sem eBPF a captura se reduz ao que /proc mostra; sem privilegio ela sai incompleta SEM erro aparente, que e o pior caso, porque o relatorio parece integro. Cenario de teste : o que a afericao pode cobrar deste host. Um agente com cenario limitado nao acusa menos por falha da ferramenta: ele nao tem como gerar o que (...)

---

## Historico do agente (`/history/7daf4613-bb13-46b2-b208-69b651fc1079`)

### Tooltips (passar o mouse)

- Abrir o relatorio da captura mais recente
- Baixar o relatorio desta captura como arquivo, para anexar. Vem sempre completo.
- Comparar esta captura com a imediatamente anterior (#191)
- Critical (score 15718897): atributo imutavel + assinatura de mineracao / uso de GPU + biblioteca de local nao confiavel + falha de rede + EDR/AV + processo defunto + concedeu execucao a regiao de memoria + uso de eBPF por terceiro + mudou de namespace + criou memoria de arquivo anonima + abriu porta de escuta + aceitou conexao de entrada + apagou arquivo + renomeou arquivo + consulta DNS observada (...)
- E a captura mais antiga guardada deste agente: nao ha anterior com que comparar
- High (score 460864): falha de rede + uso de eBPF por terceiro + abriu porta de escuta + apagou arquivo + renomeou arquivo (exemplo: o texto lista os sinais presentes no processo)
- Info (score 2097152): consulta DNS observada (exemplo: o texto lista os sinais presentes no processo)
- Low (score 131072): apagou arquivo (exemplo: o texto lista os sinais presentes no processo)
- Medium (score 137281): biblioteca de local nao confiavel + falha de rede + abriu porta de escuta + aceitou conexao de entrada + apagou arquivo (exemplo: o texto lista os sinais presentes no processo)
- Ver os eventos deste agente em ordem, junto com os dos demais hosts
- captura 1

### Balões de ajuda (ícone "?")

- Sinais do anomaly score (campo de bits) O numero ao lado do rotulo e um campo de bits: cada bit e um sinal observado, e o valor em si nao mede gravidade. O nivel exibido e o maior entre os sinais presentes, elevado um degrau quando dois ou mais sinais de peso coincidem no mesmo processo. High executa de diretorio gravavel : A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software instal (...)

---

## Relatorio do agente (`/agent/7daf4613-bb13-46b2-b208-69b651fc1079`)

### Tooltips (passar o mouse)

- A ferramenta olhou e nao havia valor. A ausencia aqui e uma observacao, e nao uma falha de captura.
- A linha literal encontrada no arquivo: a prova crua.
- APENAS LAB: cenario de teste por 300s, depois captura
- Abriu porta de escuta (bind)
- Accessing GPU Resources
- Aceitou conexao de entrada (inet_csk_accept)
- Acessou memoria de outro processo (ptrace/process_vm_readv)
- Active SSH Connection
- Active SSH Connection Sessao SSH ativa: de entrada (o processo sshd da sessao) ou de saida (o cliente ssh). O servico sshd que apenas escuta, o ssh-agent e o ssh-keygen nao acendem. Rotina de administracao remota; o valor forense esta em cruzar QUEM entrou (loginuid) e QUANDO com o log de autenticacao do host, nao no badge isolado.
- Aliases de /etc/hosts e DNS reverso por interface. O mesmo host aparece com nomes diferentes em logs de sistemas diferentes.
- Anomaly Score Rules
- Apagou arquivo (vfs_unlink)
- Apagou arquivo (vfs_unlink) vfs_unlink. Volume normal e alto (rm, gerenciador de pacote); o julgamento fino sobre padrao anti-forense fica para a regra que cruza com o restante do comportamento do processo.
- AppArmor Profile: Name (Mode)
- Baixar este relatorio como arquivo, para anexar. Vem sempre completo e identico ao que esta na tela, sem a barra de navegacao.
- Binario apagado do disco com o processo em execucao
- Calendario de achados deste host
- Calendario de capturas e coletas deste host
- Captura anterior, mais antiga que esta (completa)
- Captura completa do ciclo do agente: eBPF, inventario e achados.
- Capturas anteriores deste agente e comparacao entre duas
- Carregou kernel via kexec_load
- Carregou modulo de kernel (init_module/finit_module)
- Comentario/identidade de cada chave, para reconhecer o dono.
- Concedeu execucao a regiao de memoria (mprotect)
- Confianca (confirmado): fato verificado: o objeto foi lido ou existe
- Confianca (heuristico): regra local; admite falso positivo conhecido
- Confianca (provavel): forte indicio, coerente, mas nao confirmado
- Consulta DNS observada
- Contadores deste processo, sem os filhos.
- Contagem de itens inventariados nesta captura (baseline).
- Containerized Process
- Criou memoria de arquivo anonima (memfd_create)
- Crypto Mining Signature
- Current Disk I/O (Bytes/sec) - Hot Activity
- Custodia: o que foi preservado do artefato para a pericia. A aquisicao e DIRIGIDA (D-032): hash, metadado e um recorte pequeno, o suficiente para identificar e direcionar. A massa que PROVA e trabalho de analise aprofundada, fora do host.
- Este processo mais TODOS os descendentes. E este o numero que o badge da arvore exibe, somado.
- Fechar
- Filtra a aba Findings para os 1 achado(s) que citam esta tecnica
- Identificador do processo envolvido.
- Identificador estavel da origem da captura: hostname e endereco mudam, este nao.
- Immutable File Attribute
- Ir para a captura mais recente deste agente
- Kernel Limits (v1/v2)
- Legenda dos badges
- Leva ao processo na arvore (PID 27029). Se ele nao estiver nesta captura, a tela diz isso em vez de falhar em silencio.
- Limpa o filtro de severidade e volta a mostrar todos os achados desta captura
- Linha de comando do processo envolvido.
- Metadados do arquivo (dono, permissao, datas mtime/ctime/atime): permite datar o artefato e ver quem podia escrever.
- Momento em que o agente capturou estes dados. O relatorio descreve o host NAQUELE instante, e nao agora. Coletado pelo servidor em 2026-10-10 08:56:04 (atraso de 1s).
- Montou sistema de arquivos (mount)
- Mostrar ou ocultar System, Storage e Network, para dar espaco a arvore
- Mudanca de credencial (uid) via commit_creds
- Mudou de namespace (setns/unshare)
- Network Errors
- Network Receive: Current Delta / Total Session
- Network Transmit: Current Delta / Total Session
- New Processes
- Nome curto que o proprio host responde.
- Nome do destino em conexao TLS (SNI)
- Nome qualificado. Vazio significa que 'hostname -f' nao resolve neste host, o que e comum e legitimo.
- O alvo real que o mecanismo dispara: o que de fato roda.
- Objeto afetado: caminho de arquivo, unit, PID ou usuario
- Ordem sugerida para ler este relatorio
- PID 1
- Posicao desta captura na linha do tempo deste agente, da mais antiga para a mais recente.
- Process Frozen by EDR/AV (Wchan Wait)
- Process is running without mandatory access control enforcement.
- Proxima captura, mais recente que esta
- Qual coletor produziu este achado (ebpf, persistence, integrity, heuristic...)
- Quantas chaves SSH aceitam login para este usuario.
- Quantos achados citam esta tecnica
- Regioes de memoria gravaveis e executaveis ao mesmo tempo.
- Renomeou arquivo (vfs_rename)
- Reset Tree View
- Restart the agent (queued)
- Running via Sudo
- Save PDF
- Se o processo gera codigo por natureza (JIT), o que explica o W+X sem inocenta-lo.
- Security Inspectors - EDR/AV
- Severidade Low. O numero e um campo de bits, nao uma magnitude: cada bit e um sinal observado. Sinais presentes (score 131072): - apagou arquivo (+131072, Low): vfs_unlink. Volume normal e alto (rm, gerenciador de pacote); o julgamento fino sobre padrao anti-forense fica para a regra que cruza com o restante do comportamento do processo.
- Solicitar captura agora: entra na fila, o agente executa no proximo check-in (ate ~1 ciclo)
- Standard: Normal application. Inspector: Security tool monitoring other processes via Fanotify.
- T1014 - Rootkit Tatica: Defense Evasion Clique para ver na aba ATT&CK.
- T1055 - Process Injection Tatica: Defense Evasion, Privilege Escalation Clique para ver na aba ATT&CK.
- T1098.004 - Account Manipulation: SSH Authorized Keys Tatica: Persistence Clique para ver na aba ATT&CK.
- T1543.002 - Create or Modify System Process: Systemd Service Tatica: Persistence, Privilege Escalation Clique para ver na aba ATT&CK.
- T1547 - Boot or Logon Autostart Execution Tatica: Persistence, Privilege Escalation Clique para ver na aba ATT&CK.
- Tamanho total das regioes suspeitas, em KB.
- Top CPU Usage
- Top Disk I/O
- Top Memory (RSS)
- Top Network Activity
- Top Priority (Nice)
- Total Disk I/O during Session (Accumulated in Tree)
- Trocou a raiz do sistema de arquivos (pivot_root)
- Unsafe Path (/tmp, /dev/shm)
- Uso de eBPF por terceiro (bpf syscall)
- Usuario dono do mecanismo (ex.: dono do authorized_keys).
- Veio de pacote? verificado? Separa o que pertence ao sistema do que foi plantado (packaged:false = fora do gerenciador).
- Voltar para a tela Manager
- Zombie Process

### Balões de ajuda (ícone "?")

- × Badges da arvore de processos Rotulo tecnico (o que a sonda observou) e, logo abaixo em cinza, o que isso costuma significar para seguranca e pericia. ✨ NEW Processo novo nesta captura, ausente na anterior. Sozinho e neutro (todo host cria processos o tempo todo). O valor forense esta em CRUZAR com o resto da arvore: processo novo com caminho gravavel, ou novo direto sob PID 1 sem passar por um (...)
- × Sinais do anomaly score (campo de bits) +2 executa de diretorio gravavel High A linha de comando aponta para /tmp, /dev/shm ou /var/tmp. Software instalado nao roda de la; e o local escolhido justamente por ser gravavel por qualquer um. +8 binario apagado em execucao High O executavel sumiu do disco com o processo vivo. Apagar a amostra apos executar e tecnica corrente para impedir analise (ATT& (...)
- Como ler os achados Cada linha e um achado : o que foi encontrado, quao grave, QUEM encontrou (a fonte) e a evidencia bruta que sustenta a conclusao. Clique num achado para abrir a evidencia, a acao recomendada, a confianca e a custodia . Severidade e o que fazer: Critical artefato ativo de alto risco: conter agora (confirmar, preservar, isolar) High forte indicio: investigar hoje Medium sinal rel (...)
- O que e a matriz ATT&CK MITRE ATT&CK e um catalogo publico de tecnicas de ataque observadas em invasoes reais, organizadas por tatica (o objetivo do atacante naquele passo: executar, persistir, evadir, exfiltrar...). As tecnicas abaixo sao as que os achados desta captura citam, apresentadas na ordem do kill chain (das primeiras taticas as ultimas), para se ler como uma progressao e nao como etique (...)

### Ações clicáveis (função e rótulos)

- `alternarInventario()`: ▼ Ocultar inventario
- `event()`: +, •
- `filterFindings()`: 0 Critical, 0 Medium, 1 High, 2 Info, 5 Low, Ver todos os niveis
- `filterFindingsByTechnique()`: ◀ Ver achados
- `pivotToAttack()`: T1014, T1055, T1098.004, T1543.002, T1547
- `pivotToProcess()`: ▶ Ver processo
- `printStorage()`: Print
- `resetTree()`: ⟳
- `setFilter()`: ☢️, ⛏️, ✏️, ✨, ❌, 🌀, 🌐, 🐝, 🐧, 👂, 👻, 💊, 💣, 📥, 📦, 🔌, 🔐, 🔑, 🔒, 🕹️, 🗄️, 🗑️, 🚪, 🛡️, 🧊, 🧟, 🧠, 🧩, 🧹 CLEAR, 🫥
- `showTab()`: 1 Achados o que esta errado, 2 Processes quem executa, 3 ATT&CK que tecnica e, ATT&CK 5, Findings 6, Processes
- `sortView()`: ⚖️, 🌐, 💾, 🔥, 🧠
- `this()`: (icone), ×
- `toggleDet()`: + /usr/bin/dockerd --add-runtime oci=/usr/sbin/runc 1418 1h , + /usr/lib/systemd/systemd --switched-root --system --deseri, + /usr/lib/systemd/systemd --user 16659 42m root 0 0.0% 11.9, + /usr/lib/systemd/systemd --user 1900 1h 20m lightdm 0 0.0%, + /usr/sbin/lightdm 1560 1h 20m root 0 0.0% 8.7M - R:0W:0 0 , + bash -c P=25742; kill $P; for i in $(seq 1 30); do ps -p $, + kthreadd 2 1h 21m root 0 0.0% 0 - R:0W:0 0Σ 0 0Σ 0, + lightdm --session-child 17 20 1887 1h 20m root 0 0.0% 12.1, + sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 14, + sshd: root [priv] 26945 14s root 0 0.0% 10.9M R:241.0KW:0 , + sshd: root@notty 26965 14s root 0 0.0% 6.5M R:241.0KW:0 R:, |-- • (sd-pam) 16660 42m root 0 0.0% 5.7M - R:0W:0 0 0, |-- • (sd-pam) 1901 1h 20m lightdm 0 0.0% 5.7M - R:0W:0 0 0, |-- • /sbin/agetty -o -p -- \u --noclear - linux 1524 1h 20m, |-- • /sbin/auditd 931 1h 21m root -4 0.0% 3.6M - R:0W:0 0 0, |-- • /usr/bin/VBoxDRMClient 986 1h 21m root 0 0.0% 4.0M - R, |-- • /usr/bin/X :0 -seat seat0 -auth /run/lightdm/root/:0 -, |-- • /usr/bin/dbus-daemon --session --address=systemd: --no, |-- • /usr/bin/dbus-daemon --system --address=systemd: --nof, |-- • /usr/lib/accounts-daemon 1567 1h 20m root 0 0.0% 7.6M , |-- • /usr/lib/gvfs/gvfsd 1925 1h 20m lightdm 0 0.0% 11.1M -, |-- • /usr/lib/gvfs/gvfsd-fuse /run/user/464/gvfs -f 1931 1h, |-- • /usr/lib/polkit-1/polkitd --no-debug 982 1h 21m polkit, |-- • /usr/lib/systemd/systemd-journald 639 1h 21m root 0 0., |-- • /usr/lib/systemd/systemd-logind 1065 1h 21m root 0 0.0, |-- • /usr/lib/systemd/systemd-udevd 737 1h 21m root 0 0.0% , |-- • /usr/lib/wicked/bin/wickedd-auto4 --systemd --foregrou, |-- • /usr/lib/wicked/bin/wickedd-dhcp4 --systemd --foregrou, |-- • /usr/lib/wicked/bin/wickedd-dhcp6 --systemd --foregrou, |-- • /usr/sbin/ModemManager 1138 1h 21m root 0 0.0% 11.9M -, |-- • /usr/sbin/VBoxService --pidfile /var/run/vboxadd-servi, |-- • /usr/sbin/chronyd 1438 1h 20m chrony 0 0.0% 3.4M - R:0, |-- • /usr/sbin/cron -n 1919 1h 20m root 0 0.0% 2.6M - R:0W:, |-- • /usr/sbin/cupsd -l 1417 1h 20m root 0 0.0% 10.1M - R:0, |-- • /usr/sbin/haveged -w 1024 -v 0 -F 772 1h 21m root 0 0., |-- • /usr/sbin/irqbalance --foreground 977 1h 21m root 0 0., |-- • /usr/sbin/lightdm-gtk-greeter 1916 1h 20m lightdm 0 0., |-- • /usr/sbin/nscd 1038 1h 21m nscd 0 0.0% 4.6M - R:0W:0 0, |-- • /usr/sbin/rsyslogd -n -iNONE 1428 1h 20m root 0 0.0% 9, |-- • /usr/sbin/wickedd --systemd --foreground 1139 1h 21m r, |-- • /usr/sbin/wickedd-nanny --systemd --foreground 1144 1h, |-- • ata_sff 437 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • audit_prune_tree 1039 1h 21m root 0 0.0% 0 - R:0W:0 0 , |-- • avahi-daemon: running [openSUSE.local] 970 1h 21m avah, |-- • blkcg_punt_bio 52 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • bpfilter_umh 1657 1h 20m root 0 0.0% 1.1M - R:0W:0 0 0, |-- • charger_manager 145 1h 21m root -20 0.0% 0 - R:0W:0 0 , |-- • containerd --config /var/run/docker/containerd/contain, |-- • cpuhp/0 19 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • cpuhp/1 20 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • cpuhp/2 26 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • cpuhp/3 32 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • cryptd 398 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • devfreq_wq 56 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • edac-poller 55 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • ext4-rsv-conver 590 1h 21m root -20 0.0% 0 - R:0W:0 0 , |-- • idle_inject/0 18 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • idle_inject/1 21 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • idle_inject/2 27 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • idle_inject/3 33 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • inet_frag_wq 42 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • iprt-VBoxWQueue 411 1h 21m root -20 0.0% 0 - R:0W:0 0 , |-- • ipv6_addrconf 73 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • irq/18-vmwgfx 436 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • jbd2/dm-0-8 589 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • kaluad 412 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • kauditd 43 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • kblockd 51 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • kcompactd0 47 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • kdevtmpfs 41 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • kdmflush/254:0 568 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • khugepaged 49 1h 21m root 19 0.0% 0 - R:0W:0 0 0, |-- • khungtaskd 44 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • kintegrityd 50 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • kmpath_rdacd 416 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • ksmd 48 1h 21m root 5 0.0% 0 - R:0W:0 0 0, |-- • ksoftirqd/0 15 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • ksoftirqd/1 23 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • ksoftirqd/2 29 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • ksoftirqd/3 35 1h 21m root 0 0.0% 0 - R:0W:0 0Σ 0 0Σ 0, |-- • kstrp 79 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • kswapd0 59 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • kthrotld 67 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • kworker/0:0-ata_sff 24179 10m root 0 0.0% 0 - R:0W:0 0, |-- • kworker/0:1-events_freezable_power_ 23159 15m root 0 0, |-- • kworker/0:1H-kblockd 58 1h 21m root -20 0.0% 0 - R:0W:, |-- • kworker/0:2-ata_sff 22279 20m root 0 0.0% 0 - R:0W:0 0, |-- • kworker/0:2H-kblockd 775 1h 21m root -20 0.0% 0 - R:0W, |-- • kworker/0:3 26789 42s root 0 0.0% 0 - R:0W:0 0 0, |-- • kworker/1:0H-events_highpri 25 1h 21m root -20 0.0% 0 , |-- • kworker/1:1-events_power_efficient 11972 50m root 0 0., |-- • kworker/1:1H-kblockd 74 1h 21m root -20 0.0% 0 - R:0W:, |-- • kworker/1:2-events 12595 49m root 0 0.0% 0 - R:0W:0 0 , |-- • kworker/2:0-mm_percpu_wq 13437 49m root 0 0.0% 0 - R:0, |-- • kworker/2:0H-events_highpri 31 1h 21m root -20 0.0% 0 , |-- • kworker/2:1-kdmflush/254:0 25258 6m root 0 0.0% 0 - R:, |-- • kworker/2:1H-kblockd 156 1h 21m root -20 0.0% 0 - R:0W, |-- • kworker/3:0-mm_percpu_wq 19225 39m root 0 0.0% 0 - R:0, |-- • kworker/3:0H-events_highpri 37 1h 21m root -20 0.0% 0 , |-- • kworker/3:1-events 12167 50m root 0 0.0% 0 - R:0W:0 0 , |-- • kworker/3:1H-kblockd 185 1h 21m root -20 0.0% 0 - R:0W, |-- • kworker/u8:0-flush-254:0 25413 6m root 0 0.0% 0 - R:0W, |-- • kworker/u8:2-events_unbound 40 1h 21m root 0 0.0% 0 - , |-- • kworker/u8:4-writeback 459 1h 21m root 0 0.0% 0 - R:0W, |-- • kworker/u8:6-events_unbound 1648 1h 20m root 0 0.0% 0 , |-- • kworker/u9:0 81 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • lightdm --session-child 13 20 1960 1h 20m root 0 0.0% , |-- • migration/0 17 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • migration/1 22 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • migration/2 28 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • migration/3 34 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • mld 72 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • mm_percpu_wq 11 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • mpt/0 425 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • mpt_poll_0 422 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • netns 6 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • oom_reaper 45 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • python3 main.py --mode server --config /etc/sys-inspec, |-- • rcu_gp 3 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • rcu_par_gp 4 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • rcu_preempt 16 1h 21m root 0 0.5% 0 - R:0W:0 0 0, |-- • rcu_tasks_kthread 12 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • rcu_tasks_rude_kthread 13 1h 21m root 0 0.0% 0 - R:0W:, |-- • rcu_tasks_trace_kthread 14 1h 21m root 0 0.0% 0 - R:0W, |-- • scsi_eh_0 446 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • scsi_eh_1 449 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • scsi_eh_2 494 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • scsi_tmf_0 447 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • scsi_tmf_1 451 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • scsi_tmf_2 495 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • sleep 10 27031 2s root 0 0.0% 1.8M - R:0W:0 0 0, |-- • slub_flushwq 5 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • tpm_dev_wq 54 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • ttm 439 1h 21m root -20 0.0% 0 - R:0W:0 0 0, |-- • watchdogd 57 1h 21m root 0 0.0% 0 - R:0W:0 0 0, |-- • writeback 46 1h 21m root -20 0.0% 0 - R:0W:0 0 0
- `toggleDisk()`: +
- `toggleFinding()`: High Kernel tingido por modulo de procedencia irregular conf, Info Local systemd units inventoried confirmado persistence, Info Scheduled tasks inventoried confirmado persistence, Low Memoria gravavel e executavel em python3 (PID 27029) heu, Low SSH authorized keys present heuristico T1098.004 persist, Low systemd unit executes from an unsafe path provavel T1543, Low udev rule executes a program provavel T1547 persistence
- `toggleLegend()`: ?
- `window()`: 🖨️
