# Estratégia de Migração: Memusage para Sys-Inspector

**Data:** 2025-11-28
**Versão:** 1.0
**Contexto:** Evolução arquitetural de monitoramento User Space para Kernel Space.

## 1. Visão Geral Executiva

O projeto `sys-inspector` representa a reengenharia completa do legado `memusage`. O objetivo é transicionar de um modelo de **monitoramento passivo (polling)** para um modelo de **observabilidade ativa (event-driven)** utilizando eBPF (Extended Berkeley Packet Filter).

Esta mudança visa eliminar as limitações de granularidade e performance inerentes à leitura repetitiva do sistema de arquivos `/proc`, permitindo a captura de eventos de curta duração e telemetria de I/O em tempo real.

## 2. Matriz de Migração (De-Para)

A tabela abaixo mapeia as características fundamentais do projeto legado e sua contraparte na nova arquitetura.

| Característica | Memusage (Legado) | Sys-Inspector (Novo) | Justificativa Técnica |
| :--- | :--- | :--- | :--- |
| **Fonte de Dados** | Leitura de `/proc` via `psutil`. | Instrumentação do Kernel via `eBPF/BCC`. | `/proc` oferece apenas o estado atual (snapshot). eBPF captura eventos no momento exato em que ocorrem (ex: `execve`, `vfs_read`). |
| **Mecanismo** | Polling (Amostragem em Loop). | Event-Driven (Interrupções/Hooks). | O polling consome CPU desnecessária e perde processos que iniciam e terminam entre os ciclos de leitura. |
| **Privilégios** | Usuário comum (User Space). | **Root (sudo)** obrigatório. | A syscall `bpf()` exige a capability `CAP_SYS_ADMIN` para carregar bytecode seguro no Kernel. |
| **Estrutura** | Script Monolítico (`memusage.py`). | Pacote Python Modular (`src/`). | Separação de responsabilidades (Loader BPF vs Formatação) e facilidade para testes unitários. |
| **Deploy** | Script standalone. | Pacote RPM via Open Build Service. | Padronização de distribuição Linux Enterprise. |
| **Ambiente Dev** | Local (Qualquer Linux com Python). | Híbrido (Host Win + Guest Linux). | Necessário para compilação JIT do código C e headers do Kernel específicos. |

## 3. Decisões de Design e Restrições

### 3.1. Restrições de Codificação
* **Codificação:** Estritamente **US-ASCII**. É vetado o uso de acentos ou caracteres especiais em comentários, strings ou variáveis para garantir compatibilidade universal de build.
* **Padrão:** PEP 8 rigoroso para Python.
* **Headers:** Blocos de comentários padronizados obrigatórios para arquivos bash e python.

### 3.2. Estratégia de Empacotamento (OBS/RPM)
Diferente do legado, o `sys-inspector` adota o layout de diretório `src/`.
* **Motivo:** Evita "importação acidental" do diretório local durante testes.
* **Spec File:** O arquivo `.spec` deverá declarar dependências de compilação nativas:
    * `python3-bcc` (Runtime e Bindings).
    * `clang` / `llvm` (Compilador BPF JIT).
    * `kernel-default-devel` (Headers do Kernel, devem coincidir com `uname -r`).

### 3.3. Supressão de Linters
No projeto legado, diversas regras do Pylint (`R0914`, `R0915`) foram suprimidas devido à complexidade ciclomática da função principal. No novo projeto, a modularização deve eliminar a necessidade dessas supressões. O código deve ser limpo e segmentado.

## 4. Análise de Funcionalidades Críticas

### 4.1. Monitoramento de Processos
* **Legado:** Iterava sobre `psutil.process_iter()`.
* **Novo:** Hook na syscall `execve` (entrada) e `exit_group` (saída).
* **Ganho:** Detecção de processos "efêmeros" (que duram milissegundos) e árvore genealógica precisa (PPID) garantida pelo Kernel.

### 4.2. Monitoramento de I/O e Arquivos Abertos
* **Legado:** Snapshot de `/proc/[pid]/fd`. Ineficiente para cargas intensas.
* **Novo:** Tracepoints em `vfs_read`, `vfs_write` e `vfs_open`.
* **Ganho:** Capacidade de ver *qual* arquivo está gerando I/O no momento exato da escrita, permitindo correlacionar processos a picos de disco instantaneamente.

## 5. Próximos Passos (Roadmap)

1.  **Validação de Ambiente:** Execução de trace simples (`execve`). **(Concluído)**
2.  **Modularização:** Separar o código C (BPF) da lógica Python.
3.  **Implementação de I/O:** Criar hooks para monitoramento de arquivos abertos (foco do Lab original).
4.  **Integração OBS:** Gerar o primeiro RPM experimental.