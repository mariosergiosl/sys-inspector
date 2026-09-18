# Interface do laudo e da tela Manager

> Como operar as duas telas da ferramenta, e por que cada controle existe.
>
> Este documento cobre o que a versão 1.1.0 mudou na interface. Ele não repete o
> que cada achado significa (isso está no próprio laudo, em tooltip) nem a
> arquitetura (ver `docs/pt-BR/`).

## 1. Tela Manager (a frota)

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
que amarra a máquina ao laudo.

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
| **Uptime** | há quanto tempo o host está ligado, e há quanto tempo o agente coleta |
| **Status do agente** | se o agente falou com o servidor dentro do esperado, e há quanto tempo |

O status é **do agente**, não do host. Um host pode estar de pé com o agente
mudo, e essa é justamente a situação que interessa: por isso a coluna diz
"agente ativo" ou "agente mudo", e não apenas uma cor.

### 1.4 Coluna Action

Cinco ícones: abrir o laudo, capturas anteriores, pedir captura agora, cenário de
teste (apenas laboratório) e reiniciar o agente. Ao lado, o número da fila de
comandos daquele agente, clicável.

Abaixo dos ícones aparece o estado do último comando, em etapas.

### 1.5 Colunas ajustáveis

Todas as colunas têm uma **divisa arrastável** na borda direita do título. O
traço fica destacado ao passar o mouse, e o cursor muda para o de
redimensionamento.

## 2. Laudo (por agente)

### 2.1 Barra superior

Botão **Manager** (volta para a frota), o carimbo de quando a captura foi feita e
a idade dela, e os mesmos comandos da tela anterior para aquele agente.

### 2.2 Mostrar / ocultar inventário

Os três blocos do topo (System, Storage Topology, Network Topology) recolhem no
controle **MOSTRAR INVENTÁRIO / OCULTAR INVENTÁRIO**.

**Por que existe:** esses blocos ocupam metade da altura útil e quase nunca mudam
durante uma análise, enquanto a árvore de processos, que é onde se trabalha,
ficava espremida. O estado é lembrado pelo navegador, então quem trabalha na
árvore não precisa recolher o bloco a cada laudo que abre.

### 2.3 Abas

**Findings** (o que está errado), **Processes** (quem executa) e **ATT&CK** (que
técnica é). A faixa "COMO LER" sugere essa ordem.

Um achado cujo caminho está sendo executado agora traz o botão **Ver processo**,
que pula para ele na árvore e o destaca.

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
| Probe Signals | cada campo com um travessão, ou "não coletado" |
| Security Forensics | "nenhum motivo de segurança disparou para este processo" |

**Por que a ferramenta insiste nisso (decisão D-020):** um campo omitido faz o
leitor deduzir, e as duas deduções possíveis levam a lugares opostos: "o host não
tinha" contra "a ferramenta não olhou". A segunda invalida qualquer conclusão
tirada da ausência. Por isso todo campo aparece, em um de três estados:

- **um valor**: a coleta olhou e havia;
- **um travessão** (`—`): olhou e não havia. A ausência aqui é observação, não
  falha;
- **"não coletado"**: esta captura não produziu o campo, o que costuma acontecer
  com laudo gerado por agente anterior à versão que passou a coletar aquilo.
  Nada se pode concluir dessa ausência.

### 2.6 Filtros e badges

Cada sinal detectado vira um badge com ícone próprio na árvore, e a barra de
FILTROS tem um botão por sinal. **Cada sinal tem um ícone exclusivo** e isso é
verificado por teste: dois sinais com o mesmo desenho são um sinal só aos olhos
de quem lê, e num laudo forense dois fatos diferentes não podem ter a mesma
aparência.

**Limitação conhecida:** um filtro que não casa com nenhum processo apenas
esvazia a árvore, sem dizer que não houve resultado. Da tela, "nenhum resultado"
e "quebrado" são indistinguíveis. Está registrado como pendência.

## 3. Limitações conhecidas da interface

Registradas para que a ausência não seja lida como esquecimento:

- o laudo existe como página servida, **não como arquivo para download**;
- o botão **Ver processo** aparece apenas nos achados cujo caminho está sendo
  executado no momento da captura, e não em todos os que citam um processo;
- não há navegação entre capturas dentro do laudo (anterior, próxima, mais
  recente): isso hoje se faz pela tela de Histórico;
- filtro sem resultado não avisa.
