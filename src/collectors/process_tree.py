# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/collectors/process_tree.py
# DESCRIPTION: Manages the process tree data structure.
#              Handles Aggregation (Delta & Totals), Badge Inheritance,
#              Security Anomaly Scoring (Bitmask), and Static Analysis.
#
#              UPDATED v0.70:
#              - FEAT: Added 'Duration' (Uptime - Starttime) calculation.
#              - FEAT: Added 'Started ON' absolute timestamp.
#              - FEAT: Horizontal EDR Detection (Wchan check) -> Badge 🧊
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# ==============================================================================

import os
import pwd
import grp
import hashlib
import glob
import re
import time
# import sys
import subprocess
import shutil
from datetime import datetime, timedelta

# ------------------------------------------------------------------------------
# CONSTANTS: BITMASK SCORING
# ------------------------------------------------------------------------------
SCORE_UNSAFE_LIB = 1
SCORE_MALWARE = 2
SCORE_NET_TOOL = 4
SCORE_DELETED = 8
SCORE_INSPECTOR = 16
SCORE_GPU = 32
SCORE_NET_ISSUE = 64
SCORE_ZOMBIE = 128
SCORE_IMMUTABLE = 256

# Diretorios de onde um binario legitimo normalmente NAO e executado.
UNSAFE_EXEC_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")


def unsafe_path_in_cmdline(cmdline):
    """
    Procura um caminho de execucao suspeito em QUALQUER argumento da linha de
    comando, devolvendo o primeiro encontrado.

    Olhar so para o inicio da linha, ou so para /proc/PID/exe, deixa passar a
    evasao mais simples que existe: executar o payload por um interpretador.
    Em "/bin/bash /dev/shm/miner.sh" o executavel e o bash e a linha comeca com
    /bin/bash, mas o codigo que roda esta em /dev/shm.
    """
    if not cmdline:
        return None
    for token in str(cmdline).split():
        # Remove aspas e redirecionamentos coladas no argumento.
        arg = token.strip("'\"")
        if arg.startswith(UNSAFE_EXEC_PREFIXES):
            return arg
    return None


# Get System Clock Ticks (usually 100) for uptime calc
try:
    CLK_TCK = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
except:
    CLK_TCK = 100


# ------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------------------
def get_username(uid):
    """Resolves UID to Username."""
    try:
        if uid == 4294967295 or uid == -1: return "unset"
        return pwd.getpwuid(uid).pw_name
    except:
        return str(uid)


def calculate_md5(filepath):
    """Calculates MD5 hash of a file."""
    if not os.path.exists(filepath): return "N/A"
    try:
        hasher = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return "ACCESS_DENIED"


def _get_container_info(pid):
    """Parses cgroup to find Docker/K8s/Podman IDs."""
    c_id, c_type = None, "host"
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            for line in f:
                if "docker" in line:
                    parts = line.split("docker")[-1]
                    c_id = ''.join(filter(str.isalnum, parts))[:12]
                    c_type = "docker"
                    break
                elif "kubepods" in line:
                    c_type = "k8s"
                    if "pod" in line:
                        parts = line.split("pod")[-1]
                        c_id = ''.join(filter(str.isalnum, parts))[:12]
                        break
                elif "libpod" in line:
                    c_type = "podman"
                    parts = line.split("libpod-")[-1]
                    c_id = ''.join(filter(str.isalnum, parts))[:12]
                    break
    except: pass
    return c_id, c_type


def _get_raw_cgroups(pid):
    """Reads all cgroup entries for detail display."""
    cgroups = []
    try:
        with open(f"/proc/{pid}/cgroup", "r") as f:
            for line in f:
                cgroups.append(line.strip())
    except: pass
    return cgroups


def _read_maps(pid):
    """Scans /proc/PID/maps to find loaded libraries."""
    libs = set()
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) > 5:
                    path = parts[5]
                    if path.startswith("/") and not path.startswith(("/dev", "[", "/sys", "/proc")):
                        libs.add(path)
    except: pass
    return list(libs)


def _read_security_context(pid):
    """Reads SELinux/AppArmor context."""
    try:
        with open(f"/proc/{pid}/attr/current", "r") as f:
            return f.read().strip().replace('\x00', '')
    except:
        return "unconfined"


def _check_fanotify(pid):
    """Parses /proc/PID/fdinfo to find Fanotify flags."""
    try:
        fd_dir = f"/proc/{pid}/fdinfo"
        if not os.path.exists(fd_dir): return False

        inspector_details = {"found": False, "mode": "Unknown", "flags": ""}

        for fd_file in os.listdir(fd_dir):
            try:
                with open(os.path.join(fd_dir, fd_file), "r") as f:
                    content = f.read()
                    if "fanotify" in content:
                        inspector_details["found"] = True
                        match = re.search(r"fanotify flags:([0-9a-fA-F]+)", content)
                        if match:
                            hex_flags = int(match.group(1), 16)
                            inspector_details["flags"] = hex(hex_flags)
                            if hex_flags == 0:
                                inspector_details["mode"] = "ASYNC (Log Only)"
                            else:
                                inspector_details["mode"] = "SYNC (Blocking Inspection)"
                        return inspector_details
            except: continue
    except: pass
    return False


def _check_wchan(pid):
    """
    [v0.70 NEW] Checks /proc/pid/wchan for EDR/AV latency.
    Returns: True if blocked by security tool.
    """
    try:
        with open(f"/proc/{pid}/wchan", "r") as f:
            wchan = f.read().strip()
            # Signatures of AV scanning/interception
            if any(x in wchan for x in ["fanotify", "fsnotify", "av_scan", "sophos", "falcon"]):
                return True, wchan
    except:
        pass
    return False, ""


def _scan_open_fds(pid):
    """
    Scans /proc/PID/fd to get currently open files.
    [FIX] Removed incorrect logic that skipped normal configuration files.
    """
    files = set()
    try:
        fd_dir = f"/proc/{pid}/fd"
        if not os.path.exists(fd_dir): return files
        for fd in os.listdir(fd_dir):
            try:
                path = os.readlink(os.path.join(fd_dir, fd))

                if path.startswith("/"):
                    pass

                # Special handling for abstract sockets/pipes often appearing with type prefixes
                if path.startswith(("socket:", "pipe:", "anon_inode:")):
                    files.add(path)
                    continue

                if path == "/dev/null":
                    files.add(path)
                    continue

                files.add(path)
            except: pass
    except: pass
    return files


def _check_immutable_path(path):
    """Checks if a directory has immutable (i) or append-only (a) attributes."""
    if not shutil.which("lsattr"): return False
    try:
        cmd = ["lsattr", "-d", path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        out, _ = proc.communicate(timeout=0.5)
        if out:
            attrs = out.split()[0]
            if 'i' in attrs or 'a' in attrs:
                return attrs
    except: pass
    return False


def _immutable_files_in(dirs, cap=20, max_scan=50000, budget_s=2.5):
    """
    Arquivos imutaveis (i) ou append-only (a) DENTRO dos diretorios gravaveis.

    A checagem anterior olhava so o atributo do PROPRIO diretorio (`lsattr -d`),
    e por isso nao via o caso mais comum e mais relevante: um ARQUIVO tornado
    imutavel dentro de um diretorio gravavel. E tecnica corrente de anti-remocao
    -- o artefato nao pode ser apagado pelos meios normais nem por root sem antes
    remover o atributo. Foi o que o cenario de teste plantava
    (`/tmp/chaos_artifacts/immutable.dat`) e que passava despercebido.

    RECENTES PRIMEIRO: um artefato de anti-remocao acabou de ser criado, entao a
    travessia visita cada diretorio em ordem de modificacao decrescente. Assim o
    arquivo recem-marcado e checado no comeco, e a deteccao nao depende de quantos
    arquivos ANTIGOS enchem o /tmp nem da ordem arbitraria do os.walk. Foi a falha
    que a certificacao do chaos pegou: com ~17 mil arquivos em /tmp o artefato
    (planto ha segundos) ficava para o fim da varredura e o orcamento de tempo se
    esgotava antes de alcanca-lo, num host, enquanto noutro com /tmp enxuto era
    detectado. Ordenando por recencia, o artefato aparece primeiro nos dois.
    """
    if not shutil.which("lsattr"):
        return []

    deadline = time.time() + budget_s
    achados = []
    escaneados = [0]

    def _checar(caminho):
        """
        lsattr num UNICO arquivo, com timeout proprio.

        Por arquivo, e nao em lote, de proposito. Um lsattr sobre um arquivo sob
        I/O pesado (medido: o io_test.dat de 5MB reescrito com fsync em loop faz
        o lsattr do lote levar ~50s) BLOQUEIA. Em lote, esse unico arquivo lento
        estoura o timeout e leva junto o RESULTADO do artefato que estava no
        mesmo lote. Isolado, o arquivo lento custa so o proprio timeout e nao
        contamina o achado. Foi a causa raiz que a certificacao do chaos revelou.
        """
        proc = None
        try:
            proc = subprocess.Popen(
                ["lsattr", "-d", caminho],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                universal_newlines=True)
            out, _ = proc.communicate(timeout=1)
        except Exception:
            if proc:
                try: proc.kill()
                except Exception: pass
            return
        for line in (out or "").splitlines():
            partes = line.split(None, 1)
            if len(partes) != 2:
                continue
            attrs, achado = partes[0], partes[1]
            if 'i' in attrs or 'a' in attrs:
                achados.append("%s (%s)" % (achado, attrs))

    def _mtime(entrada):
        try:
            return entrada.stat(follow_symlinks=False).st_mtime
        except OSError:
            return 0

    def _varrer(raiz):
        """
        Travessia recursiva. Subdiretorios sao visitados por RECENCIA (o artefato
        recem-plantado primeiro), para a deteccao nao depender de quantos
        arquivos velhos enchem o /tmp. Arquivos sao checados um a um.

        So arquivos REGULARES entram: imutabilidade nao se aplica a socket ou
        FIFO, e o lsattr sobre socket BLOQUEIA ate o timeout.
        """
        if time.time() > deadline or escaneados[0] >= max_scan:
            return True
        try:
            entradas = list(os.scandir(raiz))
        except OSError:
            return False

        subdirs = []
        for e in entradas:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    subdirs.append(e)
                    continue
                if not e.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            _checar(e.path)
            escaneados[0] += 1
            if len(achados) >= cap or time.time() > deadline \
                    or escaneados[0] >= max_scan:
                return True

        subdirs.sort(key=_mtime, reverse=True)
        for sd in subdirs:
            if _varrer(sd.path):
                return True
        return False

    for d in dirs:
        if not os.path.isdir(d):
            continue
        if _varrer(d):
            break

    return achados[:cap]


def _get_udp_stats():
    """Reads global UDP OutDatagrams from /proc/net/snmp."""
    try:
        with open("/proc/net/snmp", "r") as f:
            for line in f:
                if line.startswith("Udp:"):
                    parts = line.split()
                    if parts[1].isdigit():
                        return int(parts[4])
    except: pass
    return 0


def _format_duration(seconds):
    """Formats seconds into 14D 6h 35m."""
    d = datetime(1, 1, 1) + timedelta(seconds=seconds)
    days = d.day - 1
    hours = d.hour
    mins = d.minute

    parts = []
    if days > 0: parts.append(f"{days}D")
    if hours > 0: parts.append(f"{hours}h")
    if mins > 0: parts.append(f"{mins}m")
    if not parts: return f"{d.second}s"
    return " ".join(parts)


# ------------------------------------------------------------------------------
# CORE CLASSES
# ------------------------------------------------------------------------------
class ProcessNode:
    """Represents a single process in the tree."""
    def __init__(self, pid, ppid, cmd, uid, prio=120, loginuid=None):
        self.pid = pid
        self.ppid = ppid
        self.cmd = cmd
        self.uid = uid
        if prio == 0: prio = 120
        self.prio = prio
        self.nice = prio - 120

        self.username = get_username(uid)
        self.loginuid = loginuid
        self.loginuser = get_username(loginuid) if loginuid is not None else None

        self.state = "R"

        # Resources
        self.vsz = 0
        self.rss = 0
        self.cpu_usage_pct = 0.0
        self.cpu_start_ticks = 0
        self.start_time = 0

        # [v0.70] Time Metrics
        self.duration_str = ""
        self.start_ts_abs = ""

        # Extended Context
        self.gpu_usage = False
        self.container_id = None
        self.container_type = "host"
        self.cgroups = []
        self.is_inspector = False
        self.inspector_data = None
        self.is_inspected = False
        self.security_context = "N/A"

        # Metrics (Own)
        self.read_bytes_delta = 0
        self.write_bytes_delta = 0
        self.net_tx_bytes = 0
        self.net_rx_bytes = 0
        self.tcp_retrans = 0
        self.tcp_drops = 0
        self.network_drops_details = []

        self.io_latency_tot = 0
        self.io_ops_count = 0

        # Tree Metrics (Accumulated)
        self.tree_read = 0
        self.tree_write = 0
        self.tree_read_delta = 0
        self.tree_write_delta = 0
        self.tree_net_tx = 0
        self.tree_net_rx = 0
        self.tree_io_latency = 0
        self.tree_tcp_drops = 0
        self.tree_tcp_retrans = 0

        # Alerting
        self.tree_has_alert = False
        self.tree_max_score = 0
        self.anomaly_score = 0
        self.context_tags = []
        self.md5 = "Calculating..."

        # Proveniencia do executavel (/proc/PID/exe): caminho real, se foi
        # apagado do disco ainda em execucao, se roda apenas em memoria
        # (memfd) e os MAC times do binario, para a analise temporal.
        self.exe_path = ""
        self.exe_deleted = False
        self.exe_memfd = False
        self.exe_size = 0
        self.exe_mtime = 0
        self.exe_ctime = 0
        self.exe_atime = 0

        self.libs = []
        self.open_files = set()
        self.file_metadata = {}  # [NEW] Stores permissions/owner
        self.connections = set()
        self.is_new = False

        # Sinais das sondas de ciclo de vida, credencial, modulo e escuta.
        # Declarados AQUI, e nao criados sob demanda no tratador de evento,
        # porque to_json serializa vars(node): um campo que so passa a existir
        # quando o evento ocorre sai do JSON nas capturas em que nao ocorreu, e
        # a tela nao consegue distinguir "nao aconteceu" de "nao foi coletado".
        # E a regra D-020 aplicada na origem do dado.
        self.exited = False
        self.exit_code = 0
        self.cred_changes = []          # ex.: "1000->0"
        self.loginuid_at_change = None  # quem entrou, no momento da troca
        self.kernel_module_loads = 0
        self.module_args = []
        self.listening = []             # portas em que passou a escutar
        self.accepted = []              # conexoes aceitas (alguem entrou)
        self.mem_access = []            # ptrace/process_vm_readv em outro pid
        self.memfd_created = 0          # execucao fileless
        self.memfd_names = []
        self.exec_mem_grants = 0        # mprotect concedendo execucao
        self.bpf_calls = 0              # uso de eBPF por terceiros
        self.files_deleted = 0          # anti-forense
        self.files_renamed = 0
        self.ns_changes = 0             # setns/unshare (fuga de conteiner)
        self.kexec_calls = 0            # troca de kernel

        self.detection_reasons = []

    def update_static_info(self):
        """Enriches process data with static information."""
        cid, ctype = _get_container_info(self.pid)
        if cid:
            self.container_id = cid
            self.container_type = ctype
            if "CONTAINER" not in self.context_tags: self.context_tags.append("CONTAINER")

        self.cgroups = _get_raw_cgroups(self.pid)
        self.security_context = _read_security_context(self.pid)

        # [FIX] Scan FDs correctly now
        static_files = _scan_open_fds(self.pid)
        self.open_files.update(static_files)

        # Capture Metadata (Owner/Perms) for open files
        for f in self.open_files:
            if f.startswith("/"):
                try:
                    st = os.stat(f)
                    mode = oct(st.st_mode & 0o777)[2:]
                    u_name = get_username(st.st_uid)
                    try:
                        g_name = grp.getgrgid(st.st_gid).gr_name
                    except:
                        g_name = str(st.st_gid)

                    self.file_metadata[f] = f"{u_name}:{g_name} {mode}"
                except:
                    self.file_metadata[f] = ""  # Failed to stat (e.g. permission denied)

            if "/dev/nvidia" in f or "/dev/kfd" in f or "fake_dev_nvidia" in f:
                self.gpu_usage = True
                self.detection_reasons.append(f"GPU Hardware Access: {f} [+{SCORE_GPU}]")
                if "GPU" not in self.context_tags: self.context_tags.append("GPU")

        self.libs = _read_maps(self.pid)
        for lib in self.libs:
            if lib.startswith(("/tmp", "/dev/shm", "/var/tmp")):
                self.detection_reasons.append(f"Unsafe Library Path: {lib} [+{SCORE_UNSAFE_LIB}]")
                if "UNSAFE" not in self.context_tags: self.context_tags.append("UNSAFE")

            if not self.gpu_usage and ("libnvidia" in lib or "libcuda" in lib):
                self.gpu_usage = True
                self.detection_reasons.append(f"GPU Library Loaded: {os.path.basename(lib)} [+{SCORE_GPU}]")
                if "MINER" not in self.context_tags: self.context_tags.append("MINER")

        # Case-insensitive checks
        miner_names = ["xmrig", "minerd", "kryptominer", "ethminer", "chaos_miner"]
        cmd_lower = self.cmd.lower()
        if any(m in cmd_lower for m in miner_names):
            self.gpu_usage = True
            self.detection_reasons.append(f"Heuristic Name Match: '{self.cmd}' [+{SCORE_GPU}]")
            if "MINER" not in self.context_tags: self.context_tags.append("MINER")

        fano_res = _check_fanotify(self.pid)
        if fano_res and fano_res["found"]:
            self.is_inspector = True
            self.inspector_data = fano_res
            if "EDR/AV" not in self.context_tags: self.context_tags.append("EDR/AV")

        # [v0.70] EDR Horizontal Detection (Wchan check)
        if self.state in ['S', 'D']:
            is_frozen, reason = _check_wchan(self.pid)
            if is_frozen:
                self.context_tags.append("EDR-WAIT")
                self.context_tags.append("🧊")  # ICE CUBE
                self.detection_reasons.append(f"Latency: Waiting for {reason}")

        if "sshd" in cmd_lower or "ssh" in cmd_lower:
            if "SSH" not in self.context_tags: self.context_tags.append("SSH")
        if "sudo" in cmd_lower:
            if "SUDO" not in self.context_tags: self.context_tags.append("SUDO")

        self._collect_exe_provenance()

    def _collect_exe_provenance(self):
        """
        Coleta a proveniencia do executavel a partir de /proc/PID/exe.

        O kernel acrescenta o sufixo " (deleted)" ao alvo do link quando o
        binario e apagado enquanto ainda executa, e usa "/memfd:" quando o
        codigo roda apenas em memoria. As duas situacoes sao classicas de
        anti-forense e de malware fileless: o artefato some do disco, mas o
        processo continua vivo. Nao basta olhar a linha de comando, que nao
        carrega essa informacao.

        Guarda tambem os MAC times e o tamanho do binario, que sustentam a
        analise temporal (quando o arquivo foi criado/alterado/acessado).
        """
        try:
            link = os.readlink(f"/proc/{self.pid}/exe")
        except Exception:
            self.md5 = "N/A"
            return

        exe = link
        if link.endswith(" (deleted)"):
            self.exe_deleted = True
            exe = link[:-len(" (deleted)")]
        if exe.startswith("/memfd:"):
            self.exe_memfd = True

        self.exe_path = exe

        if self.exe_deleted:
            self.detection_reasons.append(
                f"Executable deleted from disk while running: {exe} [+{SCORE_DELETED}]")
            if "DELETED" not in self.context_tags:
                self.context_tags.append("DELETED")

        if self.exe_memfd:
            self.detection_reasons.append(
                f"Fileless execution from memory: {exe} [+{SCORE_MALWARE}]")
            if "DELETED" not in self.context_tags:
                self.context_tags.append("DELETED")

        # O executavel pode ser um interpretador legitimo (/bin/bash) rodando
        # um payload que esta num diretorio inseguro; por isso a linha de
        # comando inteira tambem e inspecionada.
        unsafe = None
        if exe.startswith(("/tmp", "/dev/shm", "/var/tmp")):
            unsafe = exe
        else:
            unsafe = unsafe_path_in_cmdline(self.cmd)
        if unsafe:
            self.detection_reasons.append(
                f"Executed from unsafe path: {unsafe} [+{SCORE_MALWARE}]")
            if "UNSAFE" not in self.context_tags:
                self.context_tags.append("UNSAFE")

        try:
            if os.path.exists(exe):
                self.md5 = calculate_md5(exe)
                st = os.stat(exe)
                self.exe_size = st.st_size
                self.exe_mtime = st.st_mtime
                self.exe_ctime = st.st_ctime
                self.exe_atime = st.st_atime
            else:
                # Binario ausente do disco (apagado ou apenas em memoria).
                self.md5 = "N/A (not on disk)"
        except Exception:
            self.md5 = "N/A"


class ProcessTree:
    """Manages the hierarchy of processes."""
    def __init__(self):
        self.nodes = {}
        self.prev_udp_out = 0
        self.first_scan = True

        # Get System Boot Time for absolute timestamps
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                self.boot_time = datetime.now() - timedelta(seconds=uptime_seconds)
        except:
            self.boot_time = datetime.now()

    def reset(self):
        """
        Esvazia a arvore para que a proxima captura represente uma janela.

        Sem isto, um agente de longa duracao acumula indefinidamente processos
        que ja morreram: cada ciclo varre /proc de novo e apenas ACRESCENTA ao
        que ja estava la. As consequencias sao todas ruins e nenhuma e obvia.

        A pior delas e forense: o laudo passa a afirmar que um processo existe
        quando ele terminou horas antes, e a comparacao entre capturas nunca
        registra desaparecimento, escondendo justamente o artefato que se apagou
        depois de agir. Junto vem o crescimento sem limite do relatorio e da
        memoria do agente.

        O tempo de inicializacao e preservado: ele descreve o host, nao a
        captura, e recalcula-lo a cada ciclo so introduziria imprecisao.
        """
        self.nodes = {}
        self.prev_udp_out = 0
        self.first_scan = True

    def add_or_update(self, pid, ppid, cmd, uid, prio, loginuid=None, state="R", duration_str="", start_ts_abs=""):
        if pid == 0: return None

        if pid not in self.nodes:
            node = ProcessNode(pid, ppid, cmd, uid, prio, loginuid)
            try: node.start_time = os.path.getctime(f"/proc/{pid}")
            except: node.start_time = time.time()
            node.state = state
            node.duration_str = duration_str
            node.start_ts_abs = start_ts_abs
            node.update_static_info()
            self.nodes[pid] = node
        else:
            node = self.nodes[pid]
            # [FIX] Robust Command Logic
            if node.cmd == "?" or node.cmd == "":
                node.cmd = cmd
            elif len(cmd) > len(node.cmd):
                node.cmd = cmd

            node.state = state
            # Update dynamic metrics
            if duration_str: node.duration_str = duration_str
            if start_ts_abs: node.start_ts_abs = start_ts_abs

            if loginuid is not None:
                node.loginuid = loginuid
                node.loginuser = get_username(loginuid)

            cmd_lower = cmd.lower()
            if ("sshd" in cmd_lower or "ssh" in cmd_lower) and "SSH" not in node.context_tags:
                node.context_tags.append("SSH")
            if "sudo" in cmd_lower and "SUDO" not in node.context_tags:
                node.context_tags.append("SUDO")

        return self.nodes[pid]

    def get(self, pid):
        return self.nodes.get(pid)

    def scan_proc_fs(self):
        print("[*] Scanning /proc...")
        my_pid = os.getpid()
        count = 0

        self._check_global_anomalies()

        # Pre-read system uptime for calculations
        try:
            with open('/proc/uptime', 'r') as uf:
                sys_uptime = float(uf.readline().split()[0])
        except: sys_uptime = 0

        for path in glob.glob('/proc/[0-9]*'):
            try:
                pid_str = os.path.basename(path)
                if not pid_str.isdigit(): continue
                pid = int(pid_str)
                if pid == my_pid: continue

                info = {}
                try:
                    with open(os.path.join(path, 'status'), 'r') as f:
                        s = f.read()
                    info = {l.split(':')[0]: l.split(':', 1)[1].strip() for l in s.splitlines() if ':' in l}
                except: continue

                prio_val = 120  # Default
                duration_str = ""
                start_ts_abs = ""

                try:
                    with open(os.path.join(path, 'stat'), 'r') as f:
                        stat_content = f.read().strip()
                        last_paren_idx = stat_content.rfind(')')
                        if last_paren_idx != -1:
                            rest = stat_content[last_paren_idx + 1:].strip().split()
                            if len(rest) >= 20:  # Ensure we have starttime field
                                nice_val = int(rest[16])
                                prio_val = 120 + nice_val

                                # [v0.70] Duration Calc
                                starttime_jiffies = int(rest[19])
                                starttime_sec = starttime_jiffies / CLK_TCK
                                duration_sec = sys_uptime - starttime_sec
                                duration_str = _format_duration(duration_sec)

                                abs_start = self.boot_time + timedelta(seconds=starttime_sec)
                                start_ts_abs = abs_start.strftime("%a, %d %b %Y at %H:%M")

                except: pass

                name = info.get('Name', '?')
                ppid = int(info.get('PPid', 0))
                uid_str = info.get('Uid', '0').split()[0]
                uid = int(uid_str) if uid_str.isdigit() else 0
                state_raw = info.get('State', 'R')
                state = state_raw.split()[0]

                luid = None
                try:
                    luid_path = os.path.join(path, 'loginuid')
                    if os.path.exists(luid_path):
                        with open(luid_path, 'r') as f:
                            val = f.read().strip()
                            if val: luid = int(val)
                except: luid = None

                try:
                    with open(os.path.join(path, 'cmdline'), 'rb') as f:
                        raw = f.read()
                        if raw:
                            full_cmd = raw.replace(b'\0', b' ').decode('utf-8', 'ignore').strip()
                            if full_cmd: name = full_cmd
                except: pass

                self.add_or_update(pid, ppid, name, uid, prio_val, luid, state, duration_str, start_ts_abs)
                count += 1

                if 'VmRSS' in info:
                    node = self.nodes.get(pid)
                    if node:
                        try: node.rss = int(info['VmRSS'].replace('kB', '')) * 1024
                        except: pass
            except Exception: continue
        print(f"[+] Static Scan Complete. Found {count} processes.")

    def _check_global_anomalies(self):
        """Runs global environment checks (Network & File System)."""
        curr_udp = _get_udp_stats()
        if not self.first_scan and curr_udp > 0:
            delta = curr_udp - self.prev_udp_out
            if delta > 2000:
                pass
        self.prev_udp_out = curr_udp
        self.first_scan = False

        bad_dirs = []
        watch_dirs = ["/tmp", "/dev/shm", "/var/tmp"]
        for d in watch_dirs:
            attrs = _check_immutable_path(d)
            if attrs:
                bad_dirs.append(f"{d} ({attrs})")

        # Alem do atributo do PROPRIO diretorio, os ARQUIVOS imutaveis dentro
        # dele: e o caso comum de anti-remocao, e era o que passava despercebido.
        bad_dirs.extend(_immutable_files_in(watch_dirs))

        self.immutable_alert = bad_dirs if bad_dirs else []

    def aggregate_stats(self):
        """Bubble up stats AND BADGES using Recursive DFS."""

        # [FIX item1] Identify kernel threads: PID 2 (kthreadd) and its whole
        # subtree. TCP drop/retransmit events fired in softirq context get
        # charged to the running kernel thread (ksoftirqd, kthreadd), not to the
        # socket owner. Those are false-positive NET ERR alerts, so kernel
        # threads are excluded from NET ERR (badge, score and tree aggregation).
        # User processes always descend from PID 1, so this set is exact.
        kthread_children = {}
        for _pid, _n in self.nodes.items():
            kthread_children.setdefault(int(_n.ppid), []).append(_pid)
        self.kernel_pids = set()
        if 2 in self.nodes:
            _stack = [2]
            while _stack:
                _kp = _stack.pop()
                if _kp in self.kernel_pids:
                    continue
                self.kernel_pids.add(_kp)
                _stack.extend(kthread_children.get(_kp, []))

        for n in self.nodes.values():
            n.anomaly_score = 0

            if "UNSAFE" in n.context_tags: n.anomaly_score += SCORE_UNSAFE_LIB
            if "MINER" in n.context_tags or "GPU" in n.context_tags:
                n.anomaly_score |= SCORE_GPU
            if "EDR/AV" in n.context_tags: n.anomaly_score += SCORE_INSPECTOR
            if "NET_TOOL" in n.context_tags: n.anomaly_score += SCORE_NET_TOOL
            if "DELETED" in n.context_tags: n.anomaly_score += SCORE_DELETED
            if unsafe_path_in_cmdline(n.cmd): n.anomaly_score += SCORE_MALWARE

            if n.pid not in self.kernel_pids and (n.tcp_retrans > 0 or n.tcp_drops > 0):
                n.tags_accumulated = set(n.context_tags)
                n.tags_accumulated.add("NET ERR")
                n.anomaly_score += SCORE_NET_ISSUE
            else:
                n.tags_accumulated = set(n.context_tags)
                # [FIX item1] Drop any pre-existing NET ERR tag on kernel threads
                # (set upstream by the collector) so it does not linger in the
                # filter or bubble up to kthreadd.
                if n.pid in self.kernel_pids:
                    n.tags_accumulated.discard("NET ERR")

            if n.state == 'Z' or "<defunct>" in n.cmd:
                n.anomaly_score |= SCORE_ZOMBIE
                if "ZOMBIE" not in n.tags_accumulated: n.tags_accumulated.add("ZOMBIE")
                n.detection_reasons.append(f"Process is ZOMBIE/DEFUNCT. Parent: {n.ppid}")

            # [v0.70] EDR Horizontal (Propagate)
            if "EDR-WAIT" in n.context_tags:
                n.tags_accumulated.add("EDR-WAIT")
                n.tags_accumulated.add("🧊")

            n.tree_has_alert = (n.anomaly_score > 0)
            n.tree_max_score = n.anomaly_score

        children_map = {}
        for pid, node in self.nodes.items():
            if node.ppid not in children_map: children_map[node.ppid] = []
            children_map[node.ppid].append(pid)

        all_pids = set(self.nodes.keys())
        roots = [pid for pid in all_pids if self.nodes[pid].ppid not in all_pids]

        for root_pid in roots:
            if root_pid != 1 and root_pid != 2:
                if 1 in self.nodes:
                    if 1 not in children_map: children_map[1] = []
                    if root_pid not in children_map[1]:
                        children_map[1].append(root_pid)

        visited = set()

        def accumulate_recursive(pid):
            if pid in visited: return self.nodes[pid]
            visited.add(pid)
            node = self.nodes[pid]

            node.tree_read = node.read_bytes_delta
            node.tree_write = node.write_bytes_delta
            node.tree_read_delta = node.read_bytes_delta
            node.tree_write_delta = node.write_bytes_delta
            node.tree_net_tx = node.net_tx_bytes
            node.tree_net_rx = node.net_rx_bytes
            node.tree_io_latency = node.io_latency_tot
            # [FIX item1] Kernel threads do not own sockets; drop their softirq-
            # attributed TCP counters so they neither alert nor bubble up.
            if node.pid in self.kernel_pids:
                node.tree_tcp_drops = 0
                node.tree_tcp_retrans = 0
            else:
                node.tree_tcp_drops = node.tcp_drops
                node.tree_tcp_retrans = node.tcp_retrans

            if pid == 1 and hasattr(self, 'immutable_alert') and self.immutable_alert:
                for alert in self.immutable_alert:
                    node.detection_reasons.append(f"Filesystem Anomaly: {alert} [+{SCORE_IMMUTABLE}]")
                    node.anomaly_score |= SCORE_IMMUTABLE
                    node.tags_accumulated.add("UNSAFE")

            if pid in children_map:
                for child_pid in children_map[pid]:
                    if child_pid in self.nodes:
                        child = accumulate_recursive(child_pid)

                        node.tree_read += child.tree_read
                        node.tree_write += child.tree_write
                        node.tree_read_delta += child.tree_read_delta
                        node.tree_write_delta += child.tree_write_delta
                        node.tree_net_tx += child.tree_net_tx
                        node.tree_net_rx += child.tree_net_rx
                        node.tree_io_latency += child.tree_io_latency
                        node.tree_tcp_drops += child.tree_tcp_drops
                        node.tree_tcp_retrans += child.tree_tcp_retrans

                        if child.state == 'Z':
                            node.anomaly_score |= SCORE_ZOMBIE
                            if "ZOMBIE_PARENT" not in node.tags_accumulated:
                                node.tags_accumulated.add("WARN")

                        if child.tree_max_score > node.tree_max_score:
                            node.tree_max_score = child.tree_max_score
                        if child.tree_has_alert:
                            node.tree_has_alert = True

                        whitelist = ["SSH", "SUDO", "UNSAFE", "MINER", "EDR/AV", "CONTAINER", "GPU", "NET ERR", "NEW", "WARN", "ZOMBIE", "EDR-WAIT", "🧊"]
                        for tag in child.tags_accumulated:
                            if tag in whitelist or "WARN" in tag:
                                node.tags_accumulated.add(tag)
            return node

        if 1 in self.nodes: accumulate_recursive(1)
        if 2 in self.nodes: accumulate_recursive(2)
        for r in roots:
            accumulate_recursive(r)

        for n in self.nodes.values():
            n.context_tags = list(n.tags_accumulated)

    def to_json(self):
        serialized_nodes = {}
        for pid, node in self.nodes.items():
            d = vars(node).copy()
            if 'tags_accumulated' in d: del d['tags_accumulated']
            if isinstance(d.get('open_files'), set): d['open_files'] = list(d['open_files'])
            if isinstance(d.get('connections'), set): d['connections'] = list(d['connections'])
            if 'network_drops_details' not in d: d['network_drops_details'] = []
            if 'detection_reasons' not in d: d['detection_reasons'] = []
            if 'cgroups' not in d: d['cgroups'] = []
            serialized_nodes[pid] = d
        return serialized_nodes
