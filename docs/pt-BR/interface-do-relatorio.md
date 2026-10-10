# Interface do relatório e da tela Manager

> Como operar as duas telas da ferramenta, e por que cada controle existe.
>
> Este documento cobre o que a versão 1.1.0 mudou na interface. Ele não repete o
> que cada achado significa (isso está no próprio relatório, em tooltip) nem a
> arquitetura (ver `docs/pt-BR/`).

## 1. Tela Manager (os hosts)

É a primeira tela: uma linha por agente.

### 1.1 Identidade do host

As colunas **HOSTNAME / UUID**, **IP** e **FQDN** identificam a máquina. O UUID é
estável e sobrevive a mudança de nome ou de endereço, então é ele que amarra as
capturas de um mesmo host ao longo do tempo.

A partir da 1.1.0, **IP e FQDN mostram todos os valores**, e não apenas o
principal. O primeiro endereço é o usado na rota até o servidor, que é o que o
servidor de fato enxerga; os demais aparecem abaixo, menores. O mesmo vale para
os nomes: aliases de `/etc/hosts` e o reverso de DNS entram como linhas
adicionais.

**Por que isso importa:** o mesmo host aparece com nomes diferentes em sistemas
diferentes (inventário, chamado, firewall). Mostrar um nome só esconde metade do
que amarra a máquina ao relatório.

### 1.2 Severidade

Uma célula com os quatro contadores lado a lado: Critical, High, Medium e Low da
**última captura**. O zero continua visível, apenas apagado. Um contador que some
deixa o operador sem saber se é zero ou se a tela parou de reportar.

### 1.3 O bloco "Agente: presença e ritmo"

Quatro colunas sob um rótulo comum, porque respondem à mesma pergunta:

| Coluna | Responde |
|---|---|
| **Last Seen** | quando chegou a última captura, hora local e UTC |
| **Next / cadência** | quando a próxima é esperada, a partir do ciclo do agente |
| **Uptime** | há quanto tempo o host está ligado, e há quanto tempo o agente captura |
| **Status do agente** | se o agente falou com o servidor dentro do esperado, e há quanto tempo |

O status é **do agente**, não do host. Um host pode estar de pé com o agente
mudo, e essa é justamente a situação que interessa: por isso a coluna diz
"agente ativo" ou "agente mudo", e não apenas uma cor.

### 1.4 Coluna Action

Cinco ícones: abrir o relatório, capturas anteriores, pedir captura agora, cenário de
teste (apenas laboratório) e reiniciar o agente. Ao lado, o número da fila de
comandos daquele agente, clicável.

Abaixo dos ícones aparece o estado do último comando, em etapas.

### 1.5 Colunas ajustáveis

Todas as colunas têm uma **divisa arrastável** na borda direita do título. O
traço fica destacado ao passar o mouse, e o cursor muda para o de
redimensionamento.

### 1.6 Calendários: Linha do tempo e Capturas / Coletas

Dois botões da barra de navegação abrem calendários do mês, e os mesmos dois
botões existem dentro de cada host (na barra do relatório), já filtrados por ele.
Acima do mês, um seletor alterna entre todos os hosts e cada host.

Os dois usam as mesmas cores: a borda do dia tem a cor da severidade mais alta, e
a faixa mostra a composição por severidade (C crítico, A alto, M médio, B baixo).
Info fica de fora, porque é inventário e aparece em toda captura.

**Linha do tempo** abre no calendário de **achados e descobertas**. Em cada dia:
os achados distintos (o mesmo achado do mesmo host conta uma vez no dia), quantos
são novos (primeira vez que aquele host mostra aquele achado) e quantos outros
eventos houve. Clicar no dia abre a lista de eventos daquele dia, a mesma lista
de antes, com a leitura da sequência no topo; uma leitura repetida a cada captura
aparece uma vez, com "visto N vezes". A lista do dia tem no topo a mesma faixa de
24 horas do outro calendário, contando os achados distintos de cada hora; clicar
numa hora restringe a lista, e os filtros de tipo mantêm o dia e a hora. Os botões
de janela (15min, 1h, 6h, 24h) continuam levando à lista recente.

**Capturas / Coletas** conta as capturas por dia. Capturar é o agente obtendo os
dados do host; coletar é o servidor recebendo o que foi capturado, e a diferença
entre os dois instantes é o atraso da coleta. Marcas do dia: Δ para capturas cuja
composição mudou em relação à anterior do mesmo host, ≠ para capturas cujo total
foge do padrão do host (o valor mais comum nas 24 horas anteriores, com pelo
menos três capturas para comparar), e ⚠ para lacunas, intervalos sem
captura bem maiores que o típico. Na visão geral, o dia diz quantos hosts têm
algo a olhar. As três marcas olham só os achados Médio ou acima: o Baixo varia
com a atividade normal do host e, se contasse, quase toda captura sairia marcada.
Ele continua na faixa e, num grupo, aparece como intervalo ("Baixo de 4 a 23").
Cada pedaço da faixa e cada marca dizem por extenso o que contam ao passar o
mouse, e o "?" ao lado da legenda, das horas e da coluna Marcas explica a leitura.
Na lista, a coluna Marcas traz o detalhe: o que mudou ("Crítico 2→3"), qual é o
padrão do host e quanto durou a lacuna.

Ao clicar no dia, uma faixa de 24 horas mostra quantas capturas houve em cada
hora, com as mesmas cores; clicar numa hora restringe a lista. Na lista, capturas
iguais e seguidas aparecem numa linha só ("N capturas iguais", do primeiro ao
último horário), que abre sob demanda; uma captura que mudou ou que vem depois de
uma lacuna sempre começa um grupo novo. Cada captura leva ao relatório e à lista
de eventos dela.

## 2. Relatório (por agente)

### 2.1 Barra superior

Botão **Manager** (volta para os hosts), o carimbo de quando a captura foi feita e
a idade dela, a navegação entre capturas, o botão de baixar o relatório e os mesmos
comandos da tela anterior para aquele agente.

**Navegação entre capturas.** Quatro controles: captura anterior (mais antiga),
próxima (mais recente), ir para a mais recente, e a posição atual no formato
"captura N de M". A contagem é cronológica, da mais antiga para a mais recente,
que é como se lê uma linha do tempo; o banco devolve na ordem inversa.

Uma seta sem destino fica **visível e apagada**, e não some. O limite da coleção
é informação: uma seta que desaparece muda a largura da barra e deixa quem lê sem
saber se chegou ao fim ou se a tela quebrou. Com uma única captura não há setas,
mas a contagem continua sendo dita, porque "captura 1 de 1" também é resposta.

**Tipo da captura.** Ao lado da contagem, um selo diz que captura está na tela:
"completa" (ciclo normal do agente), "cenário de teste" (em amarelo) ou "ociosa"
(heartbeat do modo ocioso). A dica de cada seta diz o tipo da captura para onde
ela leva, para decidir antes de clicar. Uma captura é "cenário de teste" quando o
agente viu o `chaos_maker.sh` rodando durante ela, tenha o cenário sido disparado
pelo botão ou à mão: os achados dela foram plantados de propósito. Captura
gravada antes de o tipo existir aparece como "tipo não registrado", e não é
presumida completa.

**Baixar o relatório.** O ícone de disquete entrega o relatório como **arquivo**, com
nome no formato `sys-inspector_<host>_<AAAAMMDD-HHMMSS>.html`. O instante no nome
é o da **captura**, não o do download: quem recebe a peça precisa saber a que
momento ela se refere sem abrir o arquivo.

Três propriedades importam:

- **É sempre a versão completa.** Uma peça que mudasse de conteúdo conforme quem
  clicou não se anexa a processo nenhum.
- **É a mesma montagem que a tela.** Arquivo e página saem do mesmo código, para
  que a peça anexada seja a peça lida.
- **Não leva a barra de navegação.** Ela aponta para um servidor que quem lê o
  processo não alcança, e botão morto num documento pericial é pior que botão
  nenhum.

O download também está na tela de **Histórico**, em coluna própria, para baixar
qualquer captura sem precisar abri-la antes.

O relatório fica no **servidor**, e não no agente. Não é conveniência: o agente
escrever no host inspecionado contaminaria o alvo, o agente cifra com a chave
pública e não consegue ler o que coletou, e o agente não tem servidor web, só
chamadas de saída, de modo que um download abriria porta no processo mais
privilegiado entre os hosts.

### 2.2 Mostrar / ocultar inventário

Os três blocos do topo (System, Storage Topology, Network Topology) recolhem no
controle **MOSTRAR INVENTÁRIO / OCULTAR INVENTÁRIO**.

**Por que existe:** esses blocos ocupam metade da altura útil e quase nunca mudam
durante uma análise, enquanto a árvore de processos, que é onde se trabalha,
ficava espremida. O estado é lembrado pelo navegador, então quem trabalha na
árvore não precisa recolher o bloco a cada relatório que abre.

### 2.3 Abas

**Findings** (o que está errado), **Processes** (quem executa) e **ATT&CK** (que
técnica é). A faixa "COMO LER" sugere essa ordem.

Um achado que diz respeito a um processo traz o botão **Ver processo**, que pula
para ele na árvore e o destaca. Isso acontece em dois casos: quando o achado
**nomeia o PID** (memória gravável-e-executável, processo oculto, divergência de
threads) e quando o **caminho denunciado** está sendo executado por algum
processo capturado.

Se o processo já não estiver na captura, a tela **diz isso** e sugere procurar no
histórico do agente, em vez de simplesmente não reagir. Ausência é resposta.

Um achado que não é sobre processo (um módulo de kernel, um arquivo, um padrão
de todos os hosts) continua **sem** o botão, e essa ausência também informa: não há
processo a que ir.

### 2.4 Árvore de processos

- **Rolagem própria**: a árvore rola dentro da própria caixa, nos dois eixos, e o
  cabeçalho das colunas acompanha. A página em si não rola.
- **Colunas ajustáveis**: mesma divisa arrastável da tela Manager.
- **COMMAND TREE quebra em até três linhas**, para o argumento do fim da linha de
  comando não ficar escondido atrás de reticências. É frequentemente ali que está
  o caminho de onde o binário foi lançado.
- **ALERTS usa duas linhas** quando há muitos sinais.

### 2.5 Painel de detalhe do processo

Clicar numa linha abre o detalhe. **Todos os blocos aparecem sempre**, mesmo sem
dado:

| Bloco | Quando vazio, diz |
|---|---|
| Executable Provenance | "sem binário em disco (processo de kernel, ou caminho ilegível)" |
| Process Ancestry | "sem ancestral capturado nesta janela" |
| Probe Signals | cada campo com um travessão, ou "não capturado" |
| Security Forensics | "nenhum motivo de segurança disparou para este processo" |

**Por que a ferramenta insiste nisso (decisão D-020):** um campo omitido faz o
leitor deduzir, e as duas deduções possíveis levam a lugares opostos: "o host não
tinha" contra "a ferramenta não olhou". A segunda invalida qualquer conclusão
tirada da ausência. Por isso todo campo aparece, em um de três estados:

- **um valor**: a captura olhou e havia;
- **um travessão** (`—`): olhou e não havia. A ausência aqui é observação, não
  falha;
- **"não capturado"**: esta captura não produziu o campo, o que costuma acontecer
  com relatório gerado por agente anterior à versão que passou a capturar aquilo.
  Nada se pode concluir dessa ausência.

### 2.6 Filtros e badges

**O badge de falha de rede conta a subárvore.** O número ao lado do ❌ soma
retransmissões TCP e pacotes descartados **deste processo e de todos os
descendentes dele**, inclusive os ramos que ainda não foram expandidos. Por isso
o badge de um pai pode ser maior que a soma dos filhos visíveis na tela.

O painel de detalhe mostra as duas leituras lado a lado, "Deste processo" e "Com
os descendentes", e declara qual é o total que o badge exibe. Sem esses rótulos,
um pai com badge 7 e detalhe 0 parecia erro de contagem, quando era apenas o pai
não ter descarte próprio.

Cada sinal detectado vira um badge com ícone próprio na árvore, e a barra de
FILTROS tem um botão por sinal. **Cada sinal tem um ícone exclusivo** e isso é
verificado por teste: dois sinais com o mesmo desenho são um sinal só aos olhos
de quem lê, e num relatório forense dois fatos diferentes não podem ter a mesma
aparência.

**Filtro sem resultado responde.** Um filtro que não casa com nenhum processo
escreve na tela quantos processos foram examinados e que a ausência é a resposta,
em vez de apenas esvaziar a árvore. Da tela, "nenhum resultado" e "quebrado"
eram indistinguíveis, e foi essa ambiguidade que fez um filtro correto ser
reportado como defeito.

O aviso fica no fluxo do documento e permanece até o filtro mudar, porque
descreve o **estado atual** da tela e não um evento passageiro.

## 3. Limitações conhecidas da interface

Registradas para que a ausência não seja lida como esquecimento.

**Resolvidas na 1.2.0.** As quatro limitações listadas aqui até a 1.1.0 deixaram
de existir: o relatório voltou a ter download, o botão **Ver processo** passou a
aparecer em todo achado que diz respeito a um processo, a navegação entre
capturas entrou na barra do relatório, e filtro sem resultado passou a avisar. O
registro fica aqui porque ele dizia a verdade sobre a versão anterior, e um
histórico de limitações apagado não serve a quem lê um relatório antigo.

**Em aberto:**

- a comparação entre duas capturas mostra os processos que **apareceram** e não
  os que **desapareceram**, que são frequentemente os mais interessantes;
- a **custódia da captura inteira** não aparece no relatório. O relatório mostra a
  custódia por achado, o que foi preservado daquele objeto, mas o registro da
  captura, com digest, elo com a captura anterior, assinatura e a impressão
  digital da chave que assinou, vive só no banco. Quem lê a peça não o vê.
