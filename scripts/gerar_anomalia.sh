#!/bin/bash

# 1. Criar o código Python "Malicioso"
cat << 'EOF' > /tmp/bad_actor.py
import time
import os
import sys
import urllib.request
import ctypes
import random

# Nome do processo para parecer legítimo (mas rodando do lugar errado)
# No Linux, mudar o nome do processo em Python é chato, vamos confiar no nome do arquivo.

print(f"Processo INICIADO. PID: {os.getpid()}")

# Carregar uma lib explicitamente (Simula injeção ou dependência)
try:
    libc = ctypes.CDLL("libc.so.6")
    print("Lib carregada: libc.so.6")
except:
    pass

while True:
    try:
        # --- 1. ATIVIDADE DE REDE ---
        # Tenta conectar em algo para gerar tráfego TCP
        print("Conectando rede...")
        with urllib.request.urlopen("http://google.com", timeout=1) as response:
            _ = response.read(1024)

        # --- 2. ATIVIDADE DE DISCO ---
        # Escreve lixo num arquivo oculto
        print("Escrevendo em disco...")
        with open("/tmp/.data_exfiltration", "a") as f:
            f.write(f"DADOS ROUBADOS: {random.getrandbits(128)}\n" * 50)
            
        # --- 3. SLEEP ---
        # Dorme pouco para aparecer bastante no top/inspector
        time.sleep(0.5)
        
    except Exception as e:
        print(e)
        time.sleep(1)
EOF

# 2. Preparar o cenário "Feio"

# Move para /dev/shm (memória compartilhada, local comum de malware para evitar disco)
# Ou /tmp com nome oculto
TARGET_PATH="/tmp/.kworker_fake"

cp /tmp/bad_actor.py $TARGET_PATH

# Define variáveis suspeitas
export LD_LIBRARY_PATH=/tmp:/var/tmp
export MY_MALICIOUS_VAR="payload_v1"

# Executa em background
python3 $TARGET_PATH &
PID=$!

# 3. A cereja do bolo: Deletar o executável enquanto roda
# Isso faz o /proc/PID/exe apontar para "... (deleted)"
sleep 1
rm $TARGET_PATH
rm /tmp/bad_actor.py

echo "--------------------------------------------------"
echo "ANOMALIA RODANDO!"
echo "PID: $PID"
echo "Comportamentos esperados no Relatório:"
echo "1. [WARN] Path in TMP (/tmp/.kworker_fake)"
echo "2. [WARN] Binary Deleted (arquivo removido)"
echo "3. [WARN] Suspicious Env (LD_LIBRARY_PATH)"
echo "4. [WARN] Hidden File (ponto no inicio)"
echo "5. Rede: Conexões IPv4 para o Google"
echo "6. Disco: Escrita pesada em /tmp/.data_exfiltration"
echo "--------------------------------------------------"
echo "Para matar depois: kill -9 $PID"