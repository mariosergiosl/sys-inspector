# Guia de Implementação do Ambiente de Desenvolvimento eBPF

## 1. Desenho da Arquitetura Híbrida

O ambiente foi desenhado para contornar limitações de I/O em pastas compartilhadas (NTFS/vboxsf) mantendo a performance de execução Linux (Ext4).

```text
[ HOST: Windows 11 ]                                  [ GUEST: OpenSUSE 15.6 ]
.                                                     .
.   VSCode (Editor)                                   .   Kernel 6.4.x (eBPF)
.   `-- Remote SSH Plugin ------------------------->  .   `-- SSH Server (Root)
.                                                     .
.   Pasta do Projeto (NTFS)                           .   Mount Point (/opt/host)
.   C:\...\GitHub\sys-inspector <== Shared Folder ==  .   /opt/host/Syncfolder
.                                                     .   `-- Código Fonte (Leitura/Escrita)
.                                                     .
.                                                     .   Sistema de Arquivos Nativo (Ext4)
.                                                     .   /root/venvs/sys-inspector
.                                                         `-- Binários Python e Libs (Execução)
```

## 2. Passo a Passo da Instalação (Do Zero)

### FASE 1: Configuração do VirtualBox

1.  **Criação da VM:**
    * **OS:** Linux / openSUSE (64-bit).
    * **Memória:** Mínimo 4GB (Recomendado 8GB para compilação LLVM).
    * **Processador:** Mínimo 2 vCPUs.

2.  **Rede (Crucial):**
    * Alterar de "NAT" para **Bridged Adapter** (Placa em Modo Bridge).
    * Isso permite que a VM receba um IP da sua rede local (ex: `192.168.1.x`) acessível pelo Windows.

3.  **Pastas Compartilhadas:**
    * Caminho do Host: Pasta onde estão seus projetos (ex: `C:\Users\Mario\GitHub`).
    * Caminho do Guest (Mount Point): `/opt/host`.
    * Opções: [x] Auto-mount, [x] Make Permanent.

### FASE 2: Instalação do Sistema Operacional (Guest)

1.  **Boot:** Iniciar com a ISO do OpenSUSE Leap 15.6.
2.  **Particionamento (Ponto Crítico de Falha Anterior):**
    * Selecionar **Expert Partitioner**.
    * Para a partição raiz (`/`), alterar o sistema de arquivos padrão (Btrfs) para **Ext4**.
    * *Motivo:* Evitar o preenchimento do disco por snapshots do Snapper em discos pequenos (<40GB).
3.  **Seleção de Software:**
    * Padrão: "Server" ou "Transactional Server" (sem interface) ou "Desktop with XFCE" (leve).
    * Adicional: Marcar o padrão "Base Development".
4.  **Finalização:** Criar usuário `root` e concluir instalação.

### FASE 3: Configuração do Sistema (Pós-Instalação)

Acesse o terminal da VM (console do VirtualBox) como `root`.

1.  **Configuração de Rede (IP Estático):**
    * Executar `yast lan`.
    * Definir IP Estático (ex: `192.168.1.26`).
    * Definir Gateway (`192.168.1.1`) e DNS (`8.8.8.8`).

2.  **Habilitar SSH para Root:**
    * Editar `/etc/ssh/sshd_config`.
    * Definir `PermitRootLogin yes`.
    * Reiniciar serviço: `systemctl restart sshd`.

3.  **Preparação da Pasta Compartilhada:**
    * Adicionar usuário ao grupo vboxsf: `usermod -aG vboxsf root`.
    * Verificar montagem: `ls -lh /opt/host`.

### FASE 4: Toolchain e Dependências (Guest)

Executar os seguintes comandos para instalar compiladores e headers do Kernel.

```bash
# 1. Atualizar repositórios
zypper refresh

# 2. Instalar ferramentas base
zypper install -y git clang llvm make gcc python3 python3-pip python3-devel

# 3. Instalar BCC (BPF Compiler Collection)
zypper install -y python3-bcc bcc-tools

# 4. Instalar Headers do Kernel (Sincronização Obrigatória)
zypper install -y kernel-devel kernel-default-devel
```

**Verificação:**
O comando `uname -r` deve retornar versão idêntica ao pacote `rpm -q kernel-default-devel`. Se diferir, execute `reboot`.

### FASE 5: Configuração do Host (Windows)

1.  **Limpeza de Chaves SSH (PowerShell):**
    Se reinstalou a VM mantendo o IP, limpe a chave antiga:
    ```powershell
    ssh-keygen -R 192.168.1.26
    ```

2.  **Teste de Conexão (MobaXterm ou Terminal):**
    ```powershell
    ssh root@192.168.1.26
    # Aceite o fingerprint digitando 'yes'
    ```

### FASE 6: Configuração do Ambiente de Projeto (Híbrido)

Esta etapa resolve o problema de links simbólicos na pasta compartilhada.

1.  **Navegar até o projeto (Guest):**
    ```bash
    cd /opt/host/Syncfolder/.../sys-inspector
    ```

2.  **Criar Ambiente Virtual Desacoplado:**
    Não crie o venv na pasta atual. Crie no disco local.
    ```bash
    mkdir -p /root/venvs
    # --system-site-packages é vital para herdar o módulo 'bcc' instalado via zypper
    python3 -m venv /root/venvs/sys-inspector --system-site-packages
    ```

3.  **Instalar Ferramentas de Qualidade:**
    ```bash
    source /root/venvs/sys-inspector/bin/activate
    pip install black pylint
    ```

### FASE 7: Configuração do VSCode (Remote SSH)

1.  **Conectar:** Usar "Remote-SSH: Connect to Host..." -> `root@192.168.1.26`.
2.  **Instalar Extensões no Remoto:**
    * Abrir painel de extensões (`Ctrl+Shift+X`).
    * Instalar "Python" (Microsoft) no alvo SSH.
3.  **Configurar Intérprete Python (Manual):**
    * O VSCode não achará o venv automaticamente pois está fora da pasta do projeto.
    * `F1` -> `Python: Select Interpreter` -> `Enter interpreter path...`.
    * Caminho: `/root/venvs/sys-inspector/bin/python`.
4.  **Desativar Criação Automática:**
    * Se o VSCode oferecer criar um venv na pasta do projeto, recuse. Isso falhará devido ao sistema de arquivos `vboxsf`.

---

## 3. Comandos de Manutenção Diária

### Iniciar Sessão de Desenvolvimento
1.  Abrir VSCode.
2.  Conectar via SSH.
3.  Abrir Terminal Integrado (`Ctrl + '`).
4.  O ambiente `(sys-inspector)` deve carregar automaticamente.
5.  Se não carregar: `source /root/venvs/sys-inspector/bin/activate`.

### Executar Scripts eBPF
Sempre execute como root (sudo implícito no login SSH) e usando o Python do venv:

```bash
# Método Recomendado (com venv ativo)
python src/main.py

# Método Explicito
/root/venvs/sys-inspector/bin/python src/main.py
```