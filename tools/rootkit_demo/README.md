# Artefato de teste do coletor de rootkit (C-037)

Módulo de kernel didático que existe por um motivo só: provar que a camada **S5**
do coletor `src/collectors/rootkit.py` acende quando deve.

## Por que ele precisa existir

O coletor de rootkit tem cinco camadas. Quatro delas são exercitadas por
artefatos de espaço de usuário no `chaos_maker.sh`:

| Camada | O que pergunta | Como o cenário prova |
|---|---|---|
| S1 | algum módulo foi carregado fora do boot? | `modprobe` de um módulo in-tree assinado, e `rmmod` na limpeza |
| S2 | algum módulo carregado não pertence a pacote? | `.ko` plantado fora do RPM |
| S3 | há sequestro por `ld.so.preload`? | biblioteca isolada, no padrão já estabelecido no projeto |
| S4 | o kernel está tingido? | leitura; provocar exigiria justamente este módulo |
| **S5** | **as listas de módulos divergem?** | **este arquivo** |

A S5 é a única que aponta um módulo **ativamente escondido**, e é a única que não
tem como ser produzida de fora: retirar um módulo da lista do kernel é código
rodando **dentro** do kernel. Não existe script capaz de causar essa divergência.

Como a regra do projeto (D-025) é que o cenário de teste reproduza a situação que
o detector foi programado para pegar, a única forma de cumpri-la nesta camada é
escrever o módulo.

## O que ele faz, e só isso

Remove a própria entrada da lista encadeada de módulos do kernel, espera
`hide_seconds`, e se recoloca.

O efeito observável é exatamente o que o detector procura: some de `lsmod` e de
`/proc/modules`, e **continua** em `/sys/module/sysinspector_demo_hide` com
`initstate=live`. Duas fontes do mesmo fato, discordando.

## O que ele deliberadamente não faz

Isto é um alvo de tiro, não uma arma. Ele não intercepta syscall, não altera
tabela nenhuma do kernel, não esconde processo, arquivo, porta, conexão ou
usuário, não concede privilégio a ninguém, não tem gatilho nem escuta rede, e não
persiste (não se instala em lugar nenhum e não sobrevive ao reboot).

Ele também **não** esconde o próprio objeto em `/sys/module`, o que um rootkit de
verdade faria em seguida. Isso é de propósito: é esse rastro que o torna
detectável, e é por ele que o módulo consegue voltar.

## O que ele custa

**O kernel fica tingido até o próximo boot**, com os bits `O` (fora da árvore) e
`E` (não assinado). Isso é irreversível sem reiniciar, e faz a camada S4 do
próprio coletor acusar o host pelo resto da sessão. Em VM de teste isso é
aceitável, e até útil (prova a S4 de quebra). Em qualquer outro host, não.

**Risco técnico, dito de frente:** a manipulação da lista é feita sem tomar
`module_mutex`, que o kernel não exporta para módulos. Se outro módulo for
carregado ou descarregado no mesmo instante, a lista pode corromper e derrubar o
kernel. Numa VM ociosa a chance é remota; num host com carga, não se carrega isto.

Por isso o `chaos_maker.sh` exige a opção `--rootkit`, e **nunca** inclui este
artefato em `--all`.

## Como usar

Exige `gcc` e os headers do kernel em execução (`kernel-devel`). A compilação é um
passo manual e deliberado: nenhum pacote do projeto compila ou instala isto.

```bash
cd tools/rootkit_demo && make
```

```bash
sudo insmod sysinspector_demo_hide.ko hide_seconds=90
```

Enquanto escondido, `rmmod` **não** o encontra, porque `rmmod` procura na mesma
lista da qual ele saiu. Ele reaparece sozinho ao fim de `hide_seconds`, e só então
pode ser removido:

```bash
sudo rmmod sysinspector_demo_hide
```

Acompanhe pelo log do kernel:

```bash
sudo dmesg | grep sysinspector_demo_hide
```

## Como conferir que o detector acendeu

Com o módulo escondido, rode uma captura e procure na aba Findings por um achado
**Critical** com título `Modulo de kernel ausente da lista de modulos:
sysinspector_demo_hide`, fonte `heuristic`, técnica `T1014`, e o bloco
"Encaminhamento a bancada" preenchido.

Conferência rápida, fora da ferramenta:

```bash
lsmod | grep sysinspector_demo_hide
```

```bash
ls -d /sys/module/sysinspector_demo_hide
```

O primeiro comando não devolve nada e o segundo devolve o diretório. Essa é a
divergência inteira.
