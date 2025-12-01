Configuração do Ambiente de Desenvolvimento eBPF (Híbrido)

1. Visão Geral da Arquitetura

O projeto utiliza uma arquitetura híbrida para mitigar as limitações de sistemas de arquivos virtualizados enquanto mantém a conveniência das ferramentas de desenvolvimento do host.

Host (Edição): Windows 11 com VSCode.

Guest (Execução/Compilação): VM OpenSUSE Leap 15.6 (Headless/Server) no VirtualBox.

Sincronização: Pasta compartilhada (VirtualBox Shared Folders) montada em /opt/host.

Execução Segura: Ambiente virtual Python (venv) desacoplado, residindo no sistema de arquivos nativo da VM (Ext4) para suportar symlinks e sockets.

2. Componentes e Configuração

2.1. Host (Windows 11)

Editor: Visual Studio Code.

Terminal: PowerShell / MobaXterm.

Virtualização: Oracle VirtualBox 7.x.

Chaves SSH: Geradas nativamente (ssh-keygen) e limpas via ssh-keygen -R [IP] quando necessário.

2.2. Guest (OpenSUSE Leap 15.6)

IP: Estático (192.168.1.26).

Kernel: Versão 6.4.x (Atualizado via repositório Kernel:stable ou Backports para suporte eBPF moderno).

Montagem Compartilhada:

Origem: Pasta local do Windows.

Destino: /opt/host/Syncfolder.

Driver: vboxsf.

2.3. Toolchain eBPF/BCC

Instalada via Zypper e verificada para garantir paridade exata entre Kernel e Headers:

bcc-tools

python3-bcc

llvm / clang

kernel-default-devel (Versão deve casar exatamente com uname -r).

3. Estrutura de Diretórios Crítica

Devido à incapacidade do driver vboxsf de criar links simbólicos (necessários para venv Python), adotou-se a seguinte separação:

Finalidade

Caminho na VM

Sistema de Arquivos

Código Fonte

/opt/host/Syncfolder/.../sys-inspector

vboxsf (NTFS/Win)

Ambiente Virtual

/root/venvs/sys-inspector

ext4 (Linux Nativo)

4. Configuração do VSCode (Remote SSH)

4.1. Conexão

Utiliza o plugin Remote - SSH.

Usuário: root (Necessário para operações eBPF/BCC que exigem privilégios privilegiados de kernel).

4.2. Extensões no Remoto

As seguintes extensões devem ser instaladas no contexto SSH (dentro da VM):

Python (Microsoft): Para IntelliSense e Debugging.

Pylint / Black: Para linting e formatação (PEP 8).

4.3. Definição do Intérprete Python

O VSCode não detecta automaticamente o venv deslocado. A configuração é manual:

Command Palette (Ctrl+Shift+P).

Python: Select Interpreter.

Enter interpreter path....

Caminho: /root/venvs/sys-inspector/bin/python.

5. Scripts de Automação

O projeto contém scripts em scripts/ para replicar o ambiente:

install_deps.sh: Atualiza o Zypper, instala compiladores (LLVM/Clang), ferramentas BCC e verifica a versão dos headers do kernel.

setup_venv.sh: Cria o diretório /root/venvs/sys-inspector (Ext4), inicializa o ambiente virtual com --system-site-packages (para acesso ao BCC global) e instala dependências de desenvolvimento (black, pylint).

6. Procedimento de Execução

Como o código utiliza eBPF, a execução exige privilégios de root. O VSCode terminal já loga como root, mas o binário python correto deve ser invocado explicitamente se não estiver com o ambiente ativado.

Comando Padrão:

# Ativar ambiente (recomendado)
source /root/venvs/sys-inspector/bin/activate
python src/main.py

# Ou execução direta
sudo /root/venvs/sys-inspector/bin/python src/main.py


7. Troubleshooting Comum

Erro Operation not permitted ao criar venv: Ocorre se tentar criar .venv dentro da pasta do projeto. Solução: Use o script setup_venv.sh que aponta para /root/venvs.

Erro de Importação BCC: Ocorre se o venv for criado sem a flag --system-site-packages.

Falha de Compilação eBPF: Geralmente indica incompatibilidade entre uname -r e o pacote kernel-default-devel. Executar zypper install -f kernel-default-devel e reiniciar.

## 8. Instalação de Ferramentas de Qualidade (QA)

Para garantir que o código siga os padrões PEP 8 (exigido pelo Flake8), é necessário instalar as ferramentas de linting no ambiente virtual.

O script `scripts/setup_venv.sh` já foi atualizado para fazer isso automaticamente, mas você pode instalar manualmente:

```bash
source /root/venvs/sys-inspector/bin/activate
pip install flake8 pylint
``` 

9. Fluxo de Desenvolvimento e Teste (Cheat Sheet)
9.1. Retomando o Trabalho (Após Reboot)
Como o código está na pasta compartilhada (Windows) e o Venv no Linux (Ext4):

Bash

# 1. Vá para a pasta do projeto
cd /opt/host/Syncfolder/Trabalho/GitHub/mariosergiosl/sys-inspector

# 2. Ative o Ambiente Virtual
source /root/venvs/sys-inspector/bin/activate

# 3. Execute o inspetor (requer sudo)
sudo python3 src/inspector.py --html relatorio_teste.html --duration 10
9.2. Verificação de Qualidade (Linting)
Antes de fazer commit, verifique se o código está limpo:

Bash

# Execute da raiz do projeto
./scripts/run_python_test.bash
9.3. Gerando Anomalias para Teste
Para validar se o inspetor detecta malwares e uso indevido:

Bash

# Inicia o script malicioso em background
./scripts/gerar_anomalia.sh

# (Gere o relatório enquanto ele roda...)

# Para matar o processo malicioso (que ignora Ctrl+C):
sudo pkill -9 -f ".kworker_fake"