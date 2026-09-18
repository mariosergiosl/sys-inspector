# sys-inspector - Inspetor de Sistema e Ferramenta de Auditoria baseada em eBPF

**Language / Idioma:** [English](README.md) | Português

[![OBS Build Status](https://build.opensuse.org/projects/home:mariosergiosl:sys-inspector/packages/sys-inspector/badge.svg)](https://build.opensuse.org/package/show/home:mariosergiosl:sys-inspector/sys-inspector)
[![PyPI version](https://img.shields.io/pypi/v/sys-inspector.svg)](https://pypi.org/project/sys-inspector/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-green.svg?logo=linux&logoColor=white)](https://www.kernel.org/)
[![GitHub Release](https://img.shields.io/github/v/release/mariosergiosl/sys-inspector)](https://github.com/mariosergiosl/sys-inspector/releases)

O **Sys-Inspector** é uma ferramenta avançada de observabilidade e forense movida por **eBPF** (Extended Berkeley Packet Filter).

Diferente das ferramentas tradicionais que consultam o `/proc` periodicamente, o Sys-Inspector se conecta diretamente ao Kernel do Linux para capturar eventos (execução de processos, I/O de arquivos, conexões de rede) em tempo real.

## Funcionalidades (v1.2.0)

* **Novo na v1.2.0 - O laudo como peça:** Baixa como arquivo nomeado pelo host e pelo instante da COLETA, sempre completo, montado pelo mesmo código que desenha a tela, e sem a barra de navegação, porque botão morto num documento pericial é pior que botão nenhum. A própria barra passou a andar entre as capturas (anterior, próxima, mais recente, "captura N de M"), e uma seta sem destino fica visível e apagada em vez de sumir: o limite da coleção é informação.
* **Novo na v1.2.0 - Ausência responde, na tela:** Um filtro que não casa nada diz quantos processos examinou, em vez de apenas esvaziar a árvore, e o salto para o processo passou a aparecer em todo achado que diz respeito a um, e não só naqueles cujo caminho denunciado por acaso está rodando. Quando o processo já saiu da captura, a tela diz isso.
* **Novo na v1.1.0 - Aquisição dirigida e encaminhamento:** Um arquivo ou região de memória suspeita é hasheada, recortada e, quando cabe no orçamento de bytes declarado, copiada - sempre registrando o ESCOPO do hash, para que um hash parcial nunca seja lido como identificação do objeto inteiro. Todo achado pode ainda dizer qual análise de bancada conclui o que ele não conclui, por quê e sobre qual objeto: a ferramenta coleta o suficiente para identificar e direcionar, nunca a massa que prova, e isso só é honesto quando ela diz quem termina o serviço.
* **Novo na v1.1.0 - Caça a rootkit e fuga de contêiner:** Cruza as três listas de módulos do kernel com o taint, julga cada biblioteca do `/etc/ld.so.preload` pela procedência de pacote, e acompanha `mount` e `pivot_root` - o passo que transforma isolamento quebrado em acesso ao host. O SNI do TLS completa o "com quem" onde o DNS não alcança (cache, IP fixo, DoH).
* **Novo na v1.1.0 - Um caminho de execução só:** Agente e servidor, nada além. Para uma máquina, instale os dois no mesmo host. HTTPS é o único transporte; o caminho em texto claro foi removido do código, e não desligado.
* **Novo na v1.1.0 - Um laudo feito para a árvore:** O bloco de inventário recolhe para dar a tela à árvore de processos, as colunas se redimensionam arrastando a divisa no cabeçalho, e a árvore rola nos dois eixos com o cabeçalho fixo. Todo bloco de detalhe está sempre presente, em um de três estados: um valor, "olhou e não havia", ou "não coletado por esta captura".

* **Novo na v1.0.0 - Contrato de resposta do achado:** Todo achado declara sua **confiança** (confirmado / provável / heurístico), para uma heurística nunca aparecer como fato, e sua **custódia** (o que foi preservado do artefato). O laudo se lê como uma investigação: faixa "como ler" (Findings -> Processes -> ATT&CK), legenda de severidade com a ação do operador, tooltips em cada campo da evidência e pivôs clicáveis nos dois sentidos entre um achado e sua técnica ATT&CK.
* **Novo na v1.0.0 - Frota distribuída:** Agentes em modelo pull encaminham capturas cifradas a um servidor central (outbox store-and-forward, fila de ingestão priorizada, fila de comandos auditada, capacidades por agente, HTTPS). A Manager mostra o progresso de cada comando como um stepper ao vivo.
* **Novo na v1.0.0 - Detecção de runtime e anti-forense:** Processos ocultos, divergência de contagem de threads, memória W+X, binário substituído no disco, bibliotecas não confiáveis e arquivos imutáveis em diretórios graváveis.
* **Achados forenses (Findings):** Todo coletor emite achados normalizados numa escala única de severidade (Info a Crítico), cada um informando a fonte que o produziu, a técnica MITRE ATT&CK, a evidência bruta e a ação recomendada.
* **Enumeração de persistência:** Responde à primeira pergunta diante de suspeita de comprometimento, como um invasor sobreviveria a um reboot: units systemd, tarefas cron/at, scripts de inicialização e de perfil, `/etc/ld.so.preload`, autoload de módulos de kernel, regras udev, pilhas PAM e `authorized_keys` por usuário. Itens de baseline permanecem informativos; a severidade só sobe diante de indicadores reais, como execução a partir de diretórios graváveis por usuário, arquivos graváveis por todos, nomes ocultos ou alteração recente.

* **Painel Fleet View:** Monitora vários nós da infraestrutura a partir de uma interface web centralizada.
* **Time Machine Forense:** Pausa a execução ao vivo e volta no tempo para inspecionar snapshots históricos armazenados em SQLite.
* **Visibilidade em Nível de Kernel:** Usa kprobes/tracepoints do eBPF para monitoramento sem pontos cegos.
* **Forense Profunda:**
  * **Hashes MD5 em tempo real:** Calcula o hash dos binários executados na hora.
  * **Consciência de Contexto:** Detecta IPs de origem SSH, usuários Sudo e sessões Tmux.
  * **Propagação Recursiva de Alertas:** Anomalias em processos filhos (libs inseguras, erros de rede) sobem como aviso até o processo pai na árvore.
* **Topologia e Infraestrutura:**
  * **Topologia de Armazenamento:** Visão hierárquica de Discos -> Partições -> LVM -> Pontos de Montagem, com HCTL.
  * **Topologia de Rede:** Autodetecção de Gateway, servidores DNS e interfaces.
* **Relatórios Corporativos:**
  * Gera **Dashboards HTML** interativos e autocontidos.
  * **Suporte a Logo:** Embute o logo da sua organização automaticamente.
  * **Badges Visuais:** Identificação instantânea de `[SSH]`, `[SUDO]`, `[UNSAFE]`, `[NET ERR]`.
  * **Barra com Estado Ativo:** A barra do relatório destaca a ordenação e o filtro aplicados no momento.
* **Segurança do Dashboard (opcional):**
  * **Autenticação HTTP Basic:** Credenciais com hash PBKDF2, funcionando em HTTP e HTTPS.
  * **HTTPS com certificado autoassinado automático:** Sem PKI manual; certificados próprios são respeitados.
  * Ambos desligados por padrão (veja a seção "Segurança do Dashboard" abaixo).

## Requisitos

* Kernel Linux 4.15+ (5.x+ recomendado para suporte a BTF).
* Privilégios de root (`sudo`).
* Python 3.6+.
* BCC Tools (`python3-bcc`).
* `iproute2` (para o comando `tc`, necessário apenas para o Chaos Maker).
* Bibliotecas Python adicionais: `flask`, `cryptography`, `pyyaml`.

## Instalação (PyPI)

Funciona em qualquer distribuição Linux com Python 3.6+.

```bash
    pip install sys-inspector
```

## Instalação (RPM / openSUSE)

Você pode instalar o **Sys-Inspector** diretamente via `zypper` usando o repositório do openSUSE Build Service.

1. **Adicione o repositório:**

```bash
    zypper addrepo https://download.opensuse.org/repositories/home:mariosergiosl:sys-inspector/15.6/home:mariosergiosl:sys-inspector.repo
```

2. **Atualize e aceite a chave GPG:**
Durante a atualização, será solicitada a confiança na chave GPG do repositório.

**Fingerprint:** 7CF0 5795 053C F397 8E00 948E 9F8D 1AC9 E2BE EABC

```bash
    zypper refresh
    # Digite 'a' para confiar sempre quando solicitado.
```

3. **Instale o pacote:**

```bash
    zypper install sys-inspector
```

4. **Execute:**
Uma vez instalado, o comando fica disponível globalmente:

```bash
    sys-inspector
```

## Uso

O Sys-Inspector é orquestrado pelo ponto de entrada `main.py` (ou globalmente como `sys-inspector`). Ele suporta vários modos de execução.

A ferramenta tem um caminho só: um **agente** que coleta e um **servidor** que
recebe e renderiza. Para uma máquina só, instale os dois no mesmo host.

### 1. Servidor (dashboard)

Recebe as capturas dos agentes e serve o dashboard da frota.

```bash
    sudo sys-inspector --mode server
    # Acesse o dashboard em https://localhost:8080
    # TLS vem ligado; um par autoassinado e gerado na primeira subida,
    # entao o navegador avisa do emissor desconhecido.
```

### 2. Agente (coletor)

Coleta, cifra, guarda e entrega ao servidor configurado em `daemon.server_ip`.

```bash
    sudo sys-inspector --mode daemon
```

### 3. Execução pontual (sem servidor)

Um único ciclo de captura, guardado localmente. É a forma mais curta de
experimentar a ferramenta: sem troca de chaves, sem token, sem segundo processo.

```bash
    sudo sys-inspector --mode daemon --once
```

### 4. Logo Personalizado

Para incluir o logo da sua empresa no cabeçalho do relatório, basta colocar um arquivo PNG no caminho:

```bash
    /etc/sys-inspector/logo.png
```

A aplicação detecta, redimensiona (altura máxima de 40px), codifica em Base64 e embute no HTML automaticamente.

## Segurança do Dashboard (Autenticação e HTTPS)

Ambos são **opcionais e desligados por padrão**, então instalações existentes não são afetadas. Configure na seção `network` do `conf/config.yaml` (ou `/etc/sys-inspector/config.yaml`).

### Autenticação HTTP Basic

1. Gere o hash da senha (rode na máquina que serve o dashboard, para o hash bater com a versão do `werkzeug` dela):

```bash
    python3 tools/gen_password.py
```

2. Cole o resultado no `config.yaml` e habilite:

```yaml
    network:
      auth:
        enabled: true
        username: "admin"
        password_hash: "pbkdf2:sha256:..."
```

A autenticação funciona em HTTP e HTTPS. Se habilitada sem hash, o servidor falha fechado e rejeita todas as requisições.

### HTTPS (TLS)

Habilite o TLS no `config.yaml`. Se o certificado/chave abaixo faltarem, um par autoassinado é gerado automaticamente na primeira execução (o navegador avisará sobre o emissor desconhecido, o que é esperado):

```yaml
    network:
      tls_enabled: true
      ssl_cert: "/etc/sys-inspector/server_cert.pem"
      ssl_key: "/etc/sys-inspector/server_key.pem"
```

Para usar sua própria PKI, coloque o certificado e a chave nos caminhos configurados e eles serão usados no lugar de gerar um novo.

Veja [docs/pt-BR/seguranca_dashboard.md](docs/pt-BR/seguranca_dashboard.md) para detalhes.

## Chaos Engineering (Ferramenta de Teste)

Incluído em `tools/chaos_maker.sh` há uma ferramenta de teste de estresse feita para validar as capacidades de detecção do inspetor.

**AVISO: NÃO EXECUTE EM SISTEMAS DE PRODUÇÃO.**
Este script usa `tc` (Traffic Control) para degradar propositalmente a qualidade da rede (perda de pacotes/latência) e consome recursos de CPU/Disco.

### Capacidades

* **Degradação de Rede:** Injeta latência e perda de pacotes para disparar alertas `[NET ERR]` no relatório.
* **Anomalias de Processo:** Esconde processos em `/dev/shm` para disparar alertas `[WARN]`.
* **Carga de Bibliotecas Inseguras:** Força o carregamento de bibliotecas de `/tmp` para disparar alertas `[UNSAFE]`.
* **Estresse de Disco:** Gera alto throughput de I/O para testar a contabilização.

### Como Executar

```bash
    sudo ./tools/chaos_maker.sh
```

Para parar: pressione Ctrl+C. O script captura o sinal e limpa automaticamente as regras de rede (tc qdisc del) e os arquivos temporários.

### Estrutura do Projeto

```bash
    ├── conf/                  # Configuração e Chaves Criptográficas
    ├── data/                  # Persistência SQLite e IDs de Agente
    ├── docs/                  # Documentação narrativa (docs/en, docs/pt-BR)
    ├── report/                # Saída de Relatórios HTML
    ├── scripts/               # Auxiliares de desenvolvimento (formatação, venv, testes)
    ├── src/
    │   ├── collectors/        # Engine eBPF e Construtores da Árvore de Processos
    │   ├── controllers/       # Modos de Execução (Daemon, Web, Snapshot)
    │   ├── core/              # Lógica de Banco de Dados e Criptografia
    │   ├── exporters/         # HTML e Web Assets
    │   ├── probes/            # Código-fonte C do eBPF
    │   ├── storage/           # Interface e handlers de armazenamento
    │   └── utils/             # Carregadores de configuração
    ├── tests/                 # Suíte de testes automatizados (pytest)
    ├── tools/                 # Ferramentas operacionais (chaos_maker, setup_env, geração de chaves/senha)
    └── main.py                # Ponto de Entrada Unificado
```

## Licença

O Sys-Inspector é software livre distribuído sob a **GNU Affero General Public
License v3.0 only (AGPL-3.0-only)**. O texto completo está em [LICENSE.md](LICENSE.md).

A AGPL foi escolhida porque o Sys-Inspector pode ser operado como serviço de rede
(servidor multiagente e painel web). Quem executar uma versão modificada e
disponibilizá-la a usuários pela rede precisa oferecer a esses usuários o código
correspondente da versão modificada.

A licença cobre apenas o código-fonte. **"Sys-Inspector" e seu logotipo são
marcas** e não são licenciados junto com o código; veja [TRADEMARK.md](TRADEMARK.md)
e [NOTICE](NOTICE).
