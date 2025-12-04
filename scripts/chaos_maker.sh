#!/bin/bash
# ==============================================================================
# FILE: scripts/chaos_maker.sh
# DESCRIPTION: Gera carga de CPU, I/O de Disco e DEGRADAÇÃO DE REDE.
#              Usa 'tc' (Traffic Control) para simular perda de pacotes.
#
# WARNING: Roda apenas em VM de teste! Afeta a rede toda da VM.
#
# Para testar a nova funcionalidade de rede (Retransmissão/Drops), 
# precisamos de algo que simule uma rede ruim.
# No Linux, usamos o tc (Traffic Control) com o módulo netem (Network Emulator). 
# Ele permite injetar latência e perda de pacotes na interface 
# de rede intencionalmente.
# ==============================================================================

# Config
TARGET_URL="http://google.com" # Algo externo para testar TCP
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
TEMP_FILE="/tmp/.chaos_data"
FAKE_LIB="/tmp/libfake.so"

# Função de Limpeza (Trap) - Roda quando você dá Ctrl+C
cleanup() {
    echo ""
    echo ">>> PARANDO O CAOS..."
    
    # 1. Matar processos filhos
    pkill -P $$ 
    # Matar processos python soltos criados por nós
    pkill -f ".unsafe_proc.py"
    
    # 2. Limpar regras de rede (Restaura a internet normal)
    if [ -n "$IFACE" ]; then
        echo ">>> Restaurando interface $IFACE..."
        tc qdisc del dev $IFACE root netem 2>/dev/null
    fi
    
    # 3. Limpar arquivos
    rm -f $TEMP_FILE $FAKE_LIB /tmp/.unsafe_proc.py
    
    echo ">>> Sistema limpo. Tchau!"
    exit 0
}

# Captura Ctrl+C e chama cleanup
trap cleanup SIGINT SIGTERM

echo ">>> INICIANDO O GERADOR DE CAOS (PID $$)"
echo ">>> Interface de Rede Alvo: $IFACE"

# ------------------------------------------------------------------------------
# 1. DEGRADAÇÃO DE REDE (Simula CrowdStrike/Firewall ruim)
# ------------------------------------------------------------------------------
echo ">>> [NET] Injetando 20% de perda de pacotes e 100ms de delay..."
# Adiciona regra: 100ms delay, 20% packet loss, 5% corrupt
tc qdisc add dev $IFACE root netem delay 100ms loss 20% corrupt 5% 2>/dev/null || \
tc qdisc change dev $IFACE root netem delay 100ms loss 20% corrupt 5%

# Gerador de Tráfego (Loop de Download falho)
echo ">>> [NET] Iniciando tráfego HTTP (wget loop)..."
(while true; do 
    wget -q --timeout=2 --tries=1 -O /dev/null $TARGET_URL
    sleep 0.5
done) &

# ------------------------------------------------------------------------------
# 2. ESTRESSE DE DISCO (I/O)
# ------------------------------------------------------------------------------
echo ">>> [DISK] Iniciando escrita em disco ($TEMP_FILE)..."
(while true; do
    # Escreve 100MB, sincroniza e apaga
    dd if=/dev/zero of=$TEMP_FILE bs=1M count=100 status=none
    sync
    rm $TEMP_FILE
    sleep 1
done) &

# ------------------------------------------------------------------------------
# 3. ANOMALIA DE PROCESSO (Hidden & Fileless)
# ------------------------------------------------------------------------------
echo ">>> [PROC] Criando processo suspeito em /dev/shm..."
cp /bin/sleep /dev/shm/.hidden_miner
/dev/shm/.hidden_miner 1000 &

# ------------------------------------------------------------------------------
# 4. ANOMALIA DE BIBLIOTECA (Unsafe Lib Load) - NOVO v0.26
# ------------------------------------------------------------------------------
echo ">>> [LIB] Criando processo com Lib Insegura (/tmp)..."
# Copia uma lib inofensiva do sistema para /tmp para simular um payload
cp /lib64/libz.so.1 $FAKE_LIB 2>/dev/null || cp /usr/lib64/libz.so.1 $FAKE_LIB

# Cria um script python que carrega essa lib explicitamente
cat << 'EOF' > /tmp/.unsafe_proc.py
import time
import ctypes
import os
print(f"PID Malicioso (Lib): {os.getpid()}")
try:
    # Carrega a lib do /tmp (Isso deve disparar o alerta [UNSAFE] no inspector)
    ctypes.CDLL("/tmp/libfake.so")
except Exception as e:
    print(f"Erro ao carregar lib: {e}")
while True: time.sleep(1)
EOF

python3 /tmp/.unsafe_proc.py &

echo "----------------------------------------------------------------"
echo " CAOS RODANDO! O sistema agora está lento e instável."
echo " Execute o sys-inspector em outro terminal para ver:"
echo " 1. [NET ERR] Retransmissões TCP (Devido aos 20% de perda)"
echo " 2. [WARN] Processo oculto em /dev/shm"
echo " 3. [UNSAFE] Biblioteca carregada de /tmp em .unsafe_proc.py"
echo " 4. Alto I/O de escrita"
echo "----------------------------------------------------------------"
echo " PRESSIONE CTRL+C PARA PARAR E LIMPAR TUDO"
echo "----------------------------------------------------------------"

# Mantém o script rodando
while true; do sleep 1; done