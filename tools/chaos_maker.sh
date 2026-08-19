#!/bin/bash
# ======================================================================================
# FILE: scripts/chaos_maker.sh
# USAGE: ./scripts/chaos_maker.sh [OPTIONS]
# DESCRIPTION: Advanced Chaos Generator for Sys-Inspector Validation.
#              Simulates Network degradation, Disk I/O, Process anomalies,
#              Security Inspection (Fanotify), Real Containers (Podman),
#              GPU/Crypto-mining signatures, and Process Priority (Nice).
#
#              WARNING: Run only on a test VM! Affects the entire VM network.
#
# OPTIONS:
#   --net        Enable Network degradation (Loss/Delay + TCP/UDP Flood + DNS Noise)
#   --firewall   Enable Firewall Drops (Simulates EDR blocking traffic)
#   --disk       Enable Disk I/O stress & Immutable file simulation
#   --proc       Enable Process anomalies (Zombie/Hidden/Unsafe Libs/Nice/Deleted)
#   --fanotify   Enable Fanotify Inspection Simulation (EDR Simulation)
#   --container  Enable Container Simulation (Podman/Docker or Unshare fallback)
#   --gpu        Enable Fake GPU/Crypto-mining Simulation (Memory Signature)
#   --probes     Enable the 13 new eBPF probe signals (F-201, 2026-08-17/18):
#                cred_change, kmod_load, new_listener, accepted_conn,
#                mem_access, memfd_create, exec_mem_grant, bpf_use,
#                file_deleted, file_renamed, ns_change, kexec_load, dns_query
#   --all        Enable ALL tests (Default if no option is provided)
#   --duration   Duration in seconds before auto-stop (Default: 40)
#   --help       Show this message
#
# PARAMETERS: None
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 1.0.1
# ======================================================================================

# --------------------------------------------------------------------------------------
# CONFIGURATION & CONSTANTS
# --------------------------------------------------------------------------------------
TEMP_DIR="/tmp/chaos_artifacts"
FAKE_LIB="${TEMP_DIR}/libnvidia-ml.so"
FAKE_DEV="${TEMP_DIR}/fake_dev_nvidia0"
# [FIXED] Use /dev/shm for realistic shared memory/driver simulation
FAKE_GPU_HANDLE="/dev/shm/fake_dev_nvidia" 
LOG_FILE="${TEMP_DIR}/chaos.log"
TARGET_URL="http://google.com"

# Colors for Output (ANSI - US-ASCII)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GREY='\033[0;90m'
NC='\033[0m'

# Default Settings
DURATION=120
ENABLE_NET=false
ENABLE_FW=false
ENABLE_DISK=false
ENABLE_PROC=false
ENABLE_FANO=false
ENABLE_CONT=false
ENABLE_GPU=false
ENABLE_PROBES=false
ALL_MODE=false

# --------------------------------------------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------------------------------------------

# NAME: log_msg
# DESCRIPTION: standardized logging with timestamp
# PARAMETER: $1 = Level (INFO, WARN, ERROR), $2 = Message
log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp=$(date +'%H:%M:%S')
    local color="$NC"
    
    case "$level" in
        INFO) color="$GREEN" ;;
        WARN) color="$YELLOW" ;;
        ERR)  color="$RED" ;;
        TYPE) color="$CYAN" ;;
    esac

    echo -e "${GREY}[$timestamp]${NC} ${color}[$level]${NC} $msg"
}

# NAME: usage
# DESCRIPTION: Prints the help message extracted from the file header.
# PARAMETER: None
usage() {
    grep "^# OPTIONS:" "$0" -A 11 | sed 's/^#//'
    exit 0
}

# NAME: check_root
# DESCRIPTION: Verifies if the script is running with root privileges.
# PARAMETER: None
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_msg "ERR" "Root privileges required (sudo)."
        exit 1
    fi
}

# NAME: cleanup
# DESCRIPTION: Restores system state, kills child processes and removes artifacts.
# PARAMETER: None
cleanup() {
    echo ""
    log_msg "WARN" "Stopping Chaos & Cleaning up artifacts..."

    # 1. Kill direct child processes first
    pkill -P $$ 2>/dev/null

    # 2. Kill the Fake EDR and Victim FIRST (Release Kernel Hooks)
    #    If we don't kill the EDR first, the victim might stay frozen forever.
    pkill -f "fake_edr_agent" 2>/dev/null
    pkill -f "victim_loader" 2>/dev/null
    
    # 2.1 Kill C binary helpers specifically
    pkill -f "edr_blocker" 2>/dev/null

    # 2.2 Kill specific python patterns (cleaner targeting)
    pkill -f "artifact_net.py"
    pkill -f "artifact_gpu.py"
    pkill -f "artifact_io.py"
    pkill -f "artifact_unsafe.py"
    pkill -f "artifact_zombie.py"
    pkill -f "kryptominer"
    pkill -f "nice_test_low"
    pkill -f "sudo_simulator"
    pkill -f "artifact_fw.py"
    pkill -f "artifact_fano.py"
    pkill -f "probe_cred_change.py"
    pkill -f "probe_kmod_load.py"
    pkill -f "probe_listener.py"
    pkill -f "probe_mem_access.py"
    pkill -f "probe_memfd_create.py"
    pkill -f "probe_exec_mem_grant.py"
    pkill -f "probe_bpf_use.py"
    pkill -f "probe_file_ops.py"
    pkill -f "probe_kexec_load.py"
    # probe_ns_change nao e python: e o "unshare --fork --pid -- sleep 2"
    # em loop; pkill -P $$ (item 1) ja mata o subshell que o gera, e cada
    # "sleep 2" some sozinho pelo --fork --pid ao perder o pai unshare.

    # 3. Restore Network Rules
    if [ "$ENABLE_NET" = "true" ]; then
        IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
        [ -z "$IFACE" ] && IFACE="lo"
        if command -v tc >/dev/null 2>&1; then
            tc qdisc del dev "$IFACE" root 2>/dev/null
        fi
    fi
    
    # 4. Remove Firewall Rules
    if command -v iptables >/dev/null 2>&1; then
        iptables -D OUTPUT -p tcp --dport 8888 -j DROP 2>/dev/null
    fi
    
    # 5. Stop Containers
    if command -v podman &> /dev/null; then
        podman rm -f sys-inspector-test-chaos 2>/dev/null
    elif command -v docker &> /dev/null; then
        docker rm -f sys-inspector-test-chaos 2>/dev/null
    fi
    
    # 6. Remove Artifacts (Handle chattr removal if exists)
    if [ -f "${TEMP_DIR}/immutable.dat" ]; then
        # Check if chattr exists before running
        if command -v chattr >/dev/null 2>&1; then
            chattr -i "${TEMP_DIR}/immutable.dat" 2>/dev/null
        fi
    fi
    
    # Clean fake handles
    if [ -f "$FAKE_GPU_HANDLE" ]; then
        rm -f "$FAKE_GPU_HANDLE"
    fi

    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi

    log_msg "INFO" "System Restored. Exiting."
    exit 0
}

# --------------------------------------------------------------------------------------
# MAIN EXECUTION & ARGUMENT PARSING
# --------------------------------------------------------------------------------------

trap cleanup SIGINT SIGTERM
check_root

# Argument Parsing
if [[ $# -eq 0 ]]; then
    ALL_MODE=true
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --net) ENABLE_NET=true ;;
        --firewall) ENABLE_FW=true ;;
        --disk) ENABLE_DISK=true ;;
        --proc) ENABLE_PROC=true ;;
        --fanotify) ENABLE_FANO=true ;;
        --container) ENABLE_CONT=true ;;
        --gpu) ENABLE_GPU=true ;;
        --probes) ENABLE_PROBES=true ;;
        --all) ALL_MODE=true ;;
        --duration) shift; DURATION="$1" ;;
        --help) usage ;;
        *) log_msg "ERR" "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ "$ALL_MODE" = "true" ]; then
    ENABLE_NET=true; ENABLE_FW=true; ENABLE_DISK=true; ENABLE_PROC=true
    ENABLE_FANO=true; ENABLE_CONT=true; ENABLE_GPU=true; ENABLE_PROBES=true
fi

#--- Trava de gateway --------------------------------------------------
# O caos de rede e de firewall e transitorio, mas no host que roteia o lab
# ele derruba TODOS os outros agentes ao mesmo tempo, e o operador perde
# justamente a frota que iria observar. Quem dispara pelo botao da tela nao
# tem como saber em qual host esta clicando.
#
# A trava vive AQUI, no script canonico, e nao apenas no wrapper: os dois
# chamadores (wrapper e daemon) herdam a mesma regra, em vez de cada um
# reimplementar a sua e divergirem em silencio.
#
# Ela so age quando o host de fato POSSUI o IP de gateway do lab; nos demais
# hosts a chamada segue igual.
LAB_GATEWAY_IP="${LAB_GATEWAY_IP:-192.168.56.200}"
if [ "${SAFE_ON_GATEWAY:-0}" = "1" ] \
   && ip -o addr 2>/dev/null | grep -q "${LAB_GATEWAY_IP}"; then
    ENABLE_NET=false
    ENABLE_FW=false
    echo "--- SAFE_ON_GATEWAY: este host possui ${LAB_GATEWAY_IP}; rede e firewall DESLIGADOS ---"
fi

# Visual Header
echo -e "${CYAN}
   _____ _    _  ___   ____  _____ 
  / ____| |  | |/ _ \ / __ \| ____|
 | |    | |__| | |_| | |  | | |__  
 | |    |  __  |  _  | |  | |___ \ 
 | |____| |  | | | | | |__| |___) |
  \_____|_|  |_|_| |_|\____/|____/ 
   Sys-Inspector Chaos Generator
              v1.0.1
${NC}"

log_msg "INFO" "Preparing Environment in ${TEMP_DIR}..."
log_msg "INFO" "Test Duration: ${DURATION}s"
mkdir -p "$TEMP_DIR"
chmod 777 "$TEMP_DIR"

# --------------------------------------------------------------------------------------
# MODULE 1: NETWORK DEGRADATION (TCP/UDP + DNS Noise)
# --------------------------------------------------------------------------------------
if [ "$ENABLE_NET" = "true" ]; then
    IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    [ -z "$IFACE" ] && IFACE="lo"
    
    log_msg "TYPE" "[NET] Network Fault Injection ($IFACE)"
    if command -v tc >/dev/null 2>&1; then
        log_msg "INFO" "   -> Injecting 100ms Delay & 5% Packet Loss..."
        tc qdisc add dev "$IFACE" root netem delay 100ms loss 5% 2>/dev/null || \
        tc qdisc change dev "$IFACE" root netem delay 100ms loss 5%
    else
        log_msg "WARN" "   -> 'tc' command not found. Packet loss simulation skipped."
    fi

    log_msg "INFO" "   -> Spawning Traffic Generators (TCP/UDP/DNS)..."
    
    # TCP Generator (Aggregation Test)
    (while true; do 
        wget -q --timeout=1 --tries=1 -O /dev/null "$TARGET_URL"
        sleep 0.8
    done) &
    PID_TCP=$!
    echo "      * TCP Gen PID: $PID_TCP (Target: $TARGET_URL)"

    # UDP + DNS Flood Script
    cat << 'EOF' > "${TEMP_DIR}/artifact_net.py"
import socket, time, threading, random
def flood_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try: s.sendto(b"X"*512, ("127.0.0.1", 9999))
        except: pass
        time.sleep(0.02)

def dns_noise():
    # Simulates DGA (Domain Generation Algorithm) queries
    domains = ["google.com", "fail.net", "bot.c2", "update.linux"]
    while True:
        try: 
            target = random.choice(domains)
            socket.gethostbyname(target)
        except: pass
        time.sleep(2)

t1 = threading.Thread(target=flood_udp); t1.daemon=True; t1.start()
t2 = threading.Thread(target=dns_noise); t2.daemon=True; t2.start()
while True: time.sleep(1)
EOF
    python3 "${TEMP_DIR}/artifact_net.py" &
    PID_NET=$!
    echo "      * UDP/DNS Gen PID: $PID_NET"
else
    log_msg "TYPE" "[NET] SKIPPED"
fi

# --------------------------------------------------------------------------------------
# MODULE 2: FIREWALL DROPS
# --------------------------------------------------------------------------------------
if [ "$ENABLE_FW" = "true" ]; then
    log_msg "TYPE" "[FW] Firewall Drop Simulation"
    if command -v iptables >/dev/null 2>&1; then
        log_msg "INFO" "   -> Adding IPTables DROP rule for port 8888..."
        iptables -A OUTPUT -p tcp --dport 8888 -j DROP
        
        cat << 'EOF' > "${TEMP_DIR}/artifact_fw.py"
import socket, time
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 8888))
    except: pass
    time.sleep(0.2)
EOF
        python3 "${TEMP_DIR}/artifact_fw.py" &
        PID_FW=$!
        echo "      * Connector PID: $PID_FW (Tries 8.8.8.8:8888)"
    else
        log_msg "WARN" "   -> 'iptables' not found. Drop simulation skipped."
    fi
else
    log_msg "TYPE" "[FW] SKIPPED"
fi

# --------------------------------------------------------------------------------------
# MODULE 3: DISK I/O STRESS
# --------------------------------------------------------------------------------------
if [ "$ENABLE_DISK" = "true" ]; then
    log_msg "TYPE" "[DISK] I/O Stress & File Anomalies"
    
    # 1. Immutable File
    touch "${TEMP_DIR}/immutable.dat"
    if command -v chattr &>/dev/null; then
        chattr +i "${TEMP_DIR}/immutable.dat" 2>/dev/null
        echo "      * Created Immutable File: ${TEMP_DIR}/immutable.dat"
    fi

    # 2. IO Writer
    cat << 'EOF' > "${TEMP_DIR}/artifact_io.py"
import time, os
while True:
    try:
        with open("/tmp/chaos_artifacts/io_test.dat", "wb") as f:
            f.write(os.urandom(1024*1024*5)) # 5MB
            f.flush()
            os.fsync(f.fileno())
    except: pass
    time.sleep(0.5)
EOF
    python3 "${TEMP_DIR}/artifact_io.py" &
    PID_IO=$!
    echo "      * I/O Stress PID: $PID_IO"
else
    log_msg "TYPE" "[DISK] SKIPPED"
fi

# --------------------------------------------------------------------------------------
# MODULE 4: PROCESS ANOMALIES
# --------------------------------------------------------------------------------------
if [ "$ENABLE_PROC" = "true" ]; then
    log_msg "TYPE" "[PROC] Process & Forensics Anomalies"
    
    # 1. Unsafe Lib Load (Check if gcc exists first)
    if command -v gcc >/dev/null 2>&1; then
        echo 'int harmless(){return 0;}' > "${TEMP_DIR}/libunsafe.c"
        gcc -shared -o "${TEMP_DIR}/libunsafe.so" -fPIC "${TEMP_DIR}/libunsafe.c" 2>/dev/null
        
        cat << EOF > "${TEMP_DIR}/artifact_unsafe.py"
import time, ctypes
try: ctypes.CDLL("${TEMP_DIR}/libunsafe.so")
except: pass
while True: time.sleep(1)
EOF
        python3 "${TEMP_DIR}/artifact_unsafe.py" &
        echo "      * Unsafe Lib Loader PID: $!"
    else
        log_msg "WARN" "   -> GCC not found. Skipping Unsafe Lib compilation."
    fi

    # 2. Nice Priority
    cp "$(which python3)" "${TEMP_DIR}/nice_test_low"
    nice -n -5 "${TEMP_DIR}/nice_test_low" -c "import time; time.sleep(100)" &
    echo "      * Nice (-5) PID: $! (Exec: nice_test_low)"
    
    # 3. Deleted Binary
    cp "$(which sleep)" "${TEMP_DIR}/deleted_sleep"
    "${TEMP_DIR}/deleted_sleep" 100 &
    PID_DEL=$!
    sleep 0.2
    rm -f "${TEMP_DIR}/deleted_sleep"
    echo "      * Deleted Binary PID: $PID_DEL (deleted_sleep)"

    # 4. Zombie Process (Persistent)
    cat << 'EOF' > "${TEMP_DIR}/artifact_zombie.py"
import os, time, sys
try:
    pid = os.fork()
    if pid > 0:
        # Parent sleeps and does NOT wait for child -> Child becomes zombie
        # We rename the process to make it obvious
        with open(f"/proc/{os.getpid()}/comm", "w") as f:
            f.write("zombie_maker")
        time.sleep(100)
    else:
        # Child exits immediately
        sys.exit(0)
except OSError:
    pass
EOF
    python3 "${TEMP_DIR}/artifact_zombie.py" &
    echo "      * Zombie Maker PID: $!"

    # 5. SUDO Simulator
    # Runs a dummy process to test SUDO badge detection
    if command -v sudo >/dev/null 2>&1; then
        sudo -n sleep 1000 2>/dev/null &
        echo "      * SUDO Simulator spawned (if allowed)"
    else
        # Fallback if sudo fails (for non-root dev envs)
        (exec -a "sudo_sim" sleep 1000) &
    fi

else
    log_msg "TYPE" "[PROC] SKIPPED"
fi

# --------------------------------------------------------------------------------------
# MODULE 5: FANOTIFY SIMULATION
# --------------------------------------------------------------------------------------
if [ "$ENABLE_FANO" = "true" ]; then
    log_msg "TYPE" "[EDR] Fanotify Inspection Simulation"
    # [NEW] Use ctypes to call libc.fanotify_init to create a REAL handle
    cat << 'EOF' > "${TEMP_DIR}/artifact_fano.py"
import time, ctypes, os
try:
    libc = ctypes.CDLL(None)
    # fanotify_init(FAN_CLASS_NOTIF, 0) -> return valid FD or -1
    # 0 = FAN_CLASS_NOTIF (default)
    fd = libc.fanotify_init(0, 0)
except:
    pass
while True: time.sleep(1)
EOF
    python3 "${TEMP_DIR}/artifact_fano.py" &
    echo "      * Mock Inspector PID: $! (Holds REAL fanotify handle)"
else
    log_msg "TYPE" "[EDR] SKIPPED"
fi

# --------------------------------------------------------------------------------------
# MODULE 5.1: REAL FANOTIFY BLOCKER (EDR FREEZE SIMULATION) (FAKE EDR & VICTIM)
# --------------------------------------------------------------------------------------
if [ "$ENABLE_FANO" = "true" ]; then
    log_msg "TYPE" "[EDR] Real Fanotify Blocking Simulation (C-Based)"

    # 1. Create the specific malware file to be blocked
    touch "${TEMP_DIR}/malware.sample"

    # 2. Generate C Code for the "Fake EDR Agent"
    cat << 'EOF' > "${TEMP_DIR}/fake_edr.c"
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fanotify.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    char *path = argv[1];

    // Initialize Fanotify (CLASS_CONTENT = can pause execution)
    int fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY);
    if (fd < 0) { perror("fanotify_init"); return 1; }

    // Mark ONLY the specific file inode passed as argument
    if (fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, path) < 0) {
        perror("fanotify_mark");
        return 1;
    }

    printf("EDR_LISTENING\n");
    fflush(stdout);

    char buf[4096];
    while (1) {
        // Read events
        ssize_t len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN) break;

        struct fanotify_event_metadata *metadata;
        metadata = (struct fanotify_event_metadata *)buf;

        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->mask & FAN_OPEN_PERM) {
                // EDR LOGIC: We hold the process here!
                sleep(30); 

                // Decision: ALLOW
                struct fanotify_response response;
                response.fd = metadata->fd;
                response.response = FAN_ALLOW;
                write(fd, &response, sizeof(response));
                
                close(metadata->fd);
            }
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
    return 0;
}
EOF

    # 3. Compile and Run the EDR
    if command -v gcc &>/dev/null; then
        gcc "${TEMP_DIR}/fake_edr.c" -o "${TEMP_DIR}/fake_edr_agent" 2>/dev/null
        
        # Start the EDR blocker in background
        "${TEMP_DIR}/fake_edr_agent" "${TEMP_DIR}/malware.sample" &
        EDR_PID=$!
        
        # Wait for EDR to initialize hook
        sleep 1
        
        # 4. Create and Launch the Victim
        cp "$(which cat)" "${TEMP_DIR}/victim_loader"
        
        log_msg "INFO" "   -> Launching Victim (victim_loader) against protected file..."
        "${TEMP_DIR}/victim_loader" "${TEMP_DIR}/malware.sample" >/dev/null &
        VICTIM_PID=$!

        echo "      * Fake EDR Agent PID: $EDR_PID (Status: Blocking ${TEMP_DIR}/malware.sample)"
        echo "      * Victim PID: $VICTIM_PID (Status: Frozen by Fanotify)"
    else
        log_msg "WARN" "GCC not found. Skipping Real Fanotify compilation."
    fi
else
    log_msg "TYPE" "[EDR] SKIPPED"
fi

# --------------------------------------------------------------------------------------
# MODULE 6: GPU/MINING SIMULATION
# --------------------------------------------------------------------------------------
if [ "$ENABLE_GPU" = "true" ]; then
    log_msg "TYPE" "[GPU] Crypto-Miner Signature Simulation"
    
    # 1. Create fake device in shared memory (Host accessible)
    touch "$FAKE_GPU_HANDLE"
    
    # 2. Create Hybrid Miner Script
    cat <<EOF > "${TEMP_DIR}/kryptominer"
import time, os, math

# BEHAVIOR 1: Open GPU Handle (Simulate Driver Access)
try:
    fd = open('${FAKE_GPU_HANDLE}', 'w')
except:
    pass

# BEHAVIOR 2: Burn CPU (Simulate Mining Work)
while True:
    # Math loop to register user CPU time
    val = 0
    for i in range(1000, 5000):
        val += math.sqrt(i)
    time.sleep(0.05)
EOF
    
    # 3. Execution
    chmod +x "${TEMP_DIR}/kryptominer"
    python3 "${TEMP_DIR}/kryptominer" &
    echo "      * Miner PID: $! (Name: kryptominer)"
else
    log_msg "TYPE" "[GPU] SKIPPED"
fi

# --------------------------------------------------------------------------------------
# MODULE 7.5: PROBE SIGNALS (F-201, 2026-08-17/18)
# --------------------------------------------------------------------------------------
# Aciona os 13 sinais novos de risk.py que ainda nao tinham artefato dedicado
# (F-201, Lote 1). dns_query ja e exercitado pelo MODULE 1 (dns_noise dentro
# de artifact_net.py); nao repetido aqui.
#
# SEGURANCA: init_module, kexec_load e bpf() usam kprobe na ENTRADA da
# funcao do kernel -- disparam ANTES de qualquer validacao/efeito. Chamar a
# syscall com argumentos deliberadamente vazios/invalidos aciona a sonda e
# falha de forma inofensiva antes de fazer qualquer coisa real:
#   - init_module(NULL, 0, "")  -> EFAULT imediato, nenhum modulo carrega.
#   - kexec_load(0, 0, NULL, 0) -> nr_segments=0 e o proprio teste de
#     capacidade que kexec-tools usa para saber se a syscall existe; sem
#     segmento nenhum, nao ha kernel novo para trocar.
#   - bpf(9999, NULL, 0)        -> cmd invalido, -EINVAL imediato.
# As demais (memfd_create, mprotect+EXEC, ptrace attach/detach, bind/accept,
# setns/unshare, unlink/rename, sudo -u) sao operacoes REAIS e seguras: so
# nao tem efeito nocivo porque nao fazem nada alem de exercitar a sonda
# (memoria alocada e liberada, arquivo de teste, socket local, etc.).
if [ "$ENABLE_PROBES" = "true" ]; then
    log_msg "TYPE" "[PROBES] F-201: 13 sinais novos do anomaly score"

    # [2026-08-18, achado do Mario] Ate aqui os 12 sinais rodavam em UM
    # processo so (threads dentro do mesmo artifact_probes.py). Funciona,
    # mas concentra tudo numa unica linha da arvore: um bug de atribuicao
    # por processo (ex.: tag vazando para o PID errado) fica mascarado,
    # porque o mesmo PID "deveria mesmo" ter todos os badges. Cada sonda
    # agora e um SCRIPT E UM PROCESSO proprios, para cada sinal aparecer
    # isolado na arvore -- do jeito que um analista precisa ver para
    # confiar que o badge esta preso ao processo certo.
    #
    # probe_lib.py e importado por cada um (evita repetir 8x o mesmo
    # boilerplate de ctypes/numeros de syscall); ainda assim cada
    # probe_*.py roda como PROCESSO TOP-LEVEL proprio (python3 "$f" &), nao
    # como thread dentro de um processo maior.
    cat << 'EOF' > "${TEMP_DIR}/probe_lib.py"
import ctypes
import time

libc = ctypes.CDLL(None, use_errno=True)

# Numeros de syscall x86_64. Sem dependencia de versao de libc porque nem
# toda glibc antiga expoe wrapper para as mais novas (memfd_create, bpf).
SYS_INIT_MODULE = 175
SYS_BPF = 321
SYS_KEXEC_LOAD = 246
SYS_MEMFD_CREATE = 319

PTRACE_ATTACH = 16
PTRACE_DETACH = 17


def loop(segundos, funcao):
    """Roda 'funcao' em loop nesta sonda, sem derrubar o processo se falhar."""
    while True:
        try:
            funcao()
        except Exception:
            pass
        time.sleep(segundos)
EOF

    # 1. cred_change: commit_creds, root trocando de uid via sudo.
    cat << 'EOF' > "${TEMP_DIR}/probe_cred_change.py"
import subprocess
import sys
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import loop


def toca():
    subprocess.Popen(["sudo", "-n", "-u", "nobody", "sleep", "2"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


loop(3, toca)
EOF

    # 2. kmod_load: init_module(NULL, 0, "") -> EFAULT imediato, nenhum
    #    modulo real carrega (kprobe na entrada da funcao ja disparou).
    cat << 'EOF' > "${TEMP_DIR}/probe_kmod_load.py"
import ctypes
import sys
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import libc, loop, SYS_INIT_MODULE


def toca():
    libc.syscall(SYS_INIT_MODULE, None, ctypes.c_ulong(0), b"")


loop(4, toca)
EOF

    # 3. new_listener + accepted_conn: bind/listen e um cliente LOCAL se
    #    conectando (mesmo fluxo, faz sentido no mesmo processo -- e uma
    #    coisa so: "este host abriu e aceitou uma conexao").
    cat << 'EOF' > "${TEMP_DIR}/probe_listener.py"
import socket
import sys
import threading
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import loop


def toca():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    porta = srv.getsockname()[1]
    srv.listen(1)

    def conecta():
        try:
            c = socket.create_connection(("127.0.0.1", porta), timeout=2)
            c.close()
        except Exception:
            pass

    threading.Thread(target=conecta, daemon=True).start()
    try:
        srv.settimeout(2)
        conn, _ = srv.accept()
        conn.close()
    except Exception:
        pass
    srv.close()


loop(3, toca)
EOF

    # 4. mem_access: ptrace attach/detach num filho PROPRIO deste script
    #    (nunca em outro processo do host).
    cat << 'EOF' > "${TEMP_DIR}/probe_mem_access.py"
import subprocess
import sys
import time
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import libc, loop, PTRACE_ATTACH, PTRACE_DETACH


def toca():
    filho = subprocess.Popen(["sleep", "5"])
    time.sleep(0.2)
    try:
        libc.ptrace(PTRACE_ATTACH, filho.pid, None, None)
        time.sleep(0.1)
        libc.ptrace(PTRACE_DETACH, filho.pid, None, None)
    except Exception:
        pass
    filho.wait()


loop(4, toca)
EOF

    # 5. memfd_create: aloca e libera, sem execucao a partir dai.
    cat << 'EOF' > "${TEMP_DIR}/probe_memfd_create.py"
import os
import sys
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import libc, loop, SYS_MEMFD_CREATE


def toca():
    fd = libc.syscall(SYS_MEMFD_CREATE, b"chaos_probe_memfd", 0)
    if fd >= 0:
        os.close(fd)


loop(2, toca)
EOF

    # 6. exec_mem_grant: mprotect concedendo PROT_EXEC a uma pagina anonima
    #    recem-alocada. So a PERMISSAO muda; nada e escrito nem executado.
    cat << 'EOF' > "${TEMP_DIR}/probe_exec_mem_grant.py"
import ctypes
import sys
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import libc, loop


def toca():
    tamanho = 4096
    PROT_READ, PROT_WRITE, PROT_EXEC = 0x1, 0x2, 0x4
    MAP_PRIVATE, MAP_ANONYMOUS = 0x02, 0x20
    libc.mmap.restype = ctypes.c_void_p
    endereco = libc.mmap(None, tamanho, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    if endereco and endereco != -1:
        libc.mprotect(ctypes.c_void_p(endereco), tamanho,
                      PROT_READ | PROT_WRITE | PROT_EXEC)
        libc.munmap(ctypes.c_void_p(endereco), tamanho)


loop(2, toca)
EOF

    # 7. bpf_use: bpf() com comando invalido -> -EINVAL imediato, nenhum
    #    programa eBPF de fato carrega.
    cat << 'EOF' > "${TEMP_DIR}/probe_bpf_use.py"
import ctypes
import sys
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import libc, loop, SYS_BPF


def toca():
    libc.syscall(SYS_BPF, ctypes.c_int(9999), None, ctypes.c_ulong(0))


loop(3, toca)
EOF

    # 8. file_deleted + file_renamed: mesmo arquivo, os dois lados de UMA
    #    operacao de anti-forense tipica (renomeia, depois apaga).
    cat << 'EOF' > "${TEMP_DIR}/probe_file_ops.py"
import os
import sys
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import loop


def toca():
    base = "/tmp/chaos_artifacts/probe_file_%d" % os.getpid()
    with open(base, "w") as f:
        f.write("chaos")
    os.rename(base, base + "_renamed")   # vfs_rename
    os.unlink(base + "_renamed")         # vfs_unlink


loop(2, toca)
EOF

    # 9. kexec_load: kexec_load(0, 0, NULL, 0), o proprio teste de
    #    capacidade que kexec-tools usa. Sem segmento nenhum, nao ha
    #    kernel novo para trocar.
    cat << 'EOF' > "${TEMP_DIR}/probe_kexec_load.py"
import ctypes
import sys
sys.path.insert(0, "/tmp/chaos_artifacts")
from probe_lib import libc, loop, SYS_KEXEC_LOAD


def toca():
    libc.syscall(SYS_KEXEC_LOAD, ctypes.c_ulong(0), ctypes.c_ulong(0),
                None, ctypes.c_ulong(0))


loop(6, toca)
EOF

    for f in probe_cred_change probe_kmod_load probe_listener \
             probe_mem_access probe_memfd_create probe_exec_mem_grant \
             probe_bpf_use probe_file_ops probe_kexec_load; do
        python3 "${TEMP_DIR}/${f}.py" &
        echo "      * ${f} PID: $!"
    done

    # 10. ns_change: setns/unshare. Comando de linha proprio (nao precisa
    #     de python), mesma tecnica do fallback de container (MODULE 7),
    #     aqui como PROCESSO PROPRIO para nao depender de podman/docker
    #     ausentes nem se misturar com o cenario de container.
    (while true; do
        unshare --fork --pid -- sleep 2 2>/dev/null
        sleep 3
    done) &
    echo "      * probe_ns_change PID: $!"

    echo "      * (dns_query ja coberto pelo MODULE 1 / dns_noise)"
else
    log_msg "TYPE" "[PROBES] SKIPPED"
fi

# --------------------------------------------------------------------------------------
# MODULE 7: CONTAINER
# --------------------------------------------------------------------------------------
if [ "$ENABLE_CONT" = "true" ]; then
    if command -v podman &> /dev/null; then
        log_msg "TYPE" "[CONT] Launching Podman Container (Alpine)"
        podman run -d --rm --name sys-inspector-test-chaos alpine top >/dev/null 2>&1
        echo "      * Container Name: sys-inspector-test-chaos"
    elif command -v docker &> /dev/null; then
        log_msg "TYPE" "[CONT] Launching Docker Container (Alpine)"
        docker run -d --rm --name sys-inspector-test-chaos alpine top >/dev/null 2>&1
        echo "      * Container Name: sys-inspector-test-chaos"
    else
        log_msg "WARN" "[CONT] No container engine. Using unshare fallback."
        unshare --fork --pid --mount-proc /bin/bash -c "sleep 9999" &
    fi
else
    log_msg "TYPE" "[CONT] SKIPPED"
fi

echo "================================================================================"
echo " >>> SYSTEM READY FOR COLLECTION (Start sys-inspector now) <<<"
echo "================================================================================"

# --------------------------------------------------------------------------------------
# COUNTDOWN TIMER LOOP
# --------------------------------------------------------------------------------------
REMAINING=$DURATION
while [ "$REMAINING" -gt 0 ]; do
    if (( REMAINING % 5 == 0 )) || (( REMAINING <= 5 )); then
        echo -ne "   ... Auto-stop in ${REMAINING}s\r"
    fi
    sleep 1
    ((REMAINING--))
done
echo "" # Newline after counter

cleanup