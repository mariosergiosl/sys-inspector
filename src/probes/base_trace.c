/*
 * ========================================================================================
 * FILE: src/probes/base_trace.c
 * DESCRIPTION: eBPF C source code for Deep System Observability.
 * Monitors Syscalls, I/O Latency, Network Buffers, and Security Inspection.
 *
 * FEATURES:
 * - Process Execution (execve) & File Access (openat)
 * - Disk I/O Latency Calculation (vfs_read/write entry vs return)
 * - Network Interface Buffer Analysis (net_dev_xmit/netif_receive_skb)
 * - TCP Health (Retransmits & Drops via kfree_skb)
 * - Horizontal Inspection Detection (fanotify hooks)
 * - [NEW v0.50.41] Detailed Packet Drop Analysis (L3/L4 extraction)
 * - [NEW v0.50.41] User Provenance Tracking (loginuid/AUID for sudo/ssh tracking)
 *
 * OPTIONS:
 *
 * PARAMETERS:
 *
 * AUTHOR: Mario Luz (Refactoring Sys-Inspector Project)
 * CHANGELOG:
 * VERSION: v0.90.14
# ==============================================================================
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/mm_types.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
// [PATCH] Include Version to handle Kernel 6.x logic
#include <linux/version.h>
// Credenciais: necessario para ler o novo conjunto em commit_creds.
#include <linux/cred.h>

// [PATCH] Compatibility Macro for Memory Reads (SLES 12/15 vs SLES 16)
// Kernel 5.8+ enforces strict separation between user/kernel memory reads.
// [CORRIGIDO] O tamanho vem do DESTINO APONTADO, nao do ponteiro.
//
// A versao anterior era `sizeof(dst)`, e como todo chamador passa `&campo`, o
// que se media era o tamanho do PONTEIRO: oito bytes, sempre, qualquer que fosse
// o destino. As consequencias nao eram cosmeticas:
//
//   - `struct iphdr` (20 bytes) recebia 8. Os campos protocol, saddr e daddr
//     ficam nos bytes 9 a 19, entao NUNCA eram lidos do pacote: o evento de
//     descarte reportava endereco de origem e destino vindos de lixo da pilha,
//     e o filtro `iph.protocol == 6 || == 17` decidia sobre lixo.
//   - campos de 2 bytes recebiam 8, escrevendo 6 alem do destino.
//   - campos de 4 bytes vinham passando por acidente, porque o campo seguinte
//     era reescrito logo depois. Acidente nao e contrato.
//
// `sizeof(*(dst))` resolve os dois casos sem tocar em nenhum chamador: para
// `&escalar` da o tamanho do escalar, e para `&vetor` da o tamanho do vetor.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    #define SAFE_KREAD(dst, src) bpf_probe_read_kernel(dst, sizeof(*(dst)), src)
#else
    #define SAFE_KREAD(dst, src) bpf_probe_read(dst, sizeof(*(dst)), src)
#endif

// Variante com tamanho EXPLICITO, para quando o destino nao carrega o proprio
// tamanho no tipo, ou quando se quer ler deliberadamente menos do que o campo
// comporta. Continua disponivel; com a macro acima corrigida deixou de ser
// obrigatoria para o caso comum.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    #define SAFE_KREAD_N(dst, n, src) bpf_probe_read_kernel(dst, n, src)
#else
    #define SAFE_KREAD_N(dst, n, src) bpf_probe_read(dst, n, src)
#endif

// Placeholder for the Python Agent PID (replaced at runtime by loader.py)
#define FILTER_PID 00000

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Structure sent to Python User Space via perf_submit
struct event_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 loginuid;      // [NEW] Audit UID (The original user before sudo/su)
    char comm[TASK_COMM_LEN];
    char filename[256];
    char type_id;      // 'E'=Exec, 'O'=Open, 'N'=Net, 'R'=Read, 'W'=Write, 'D'=Drop
    
    // Network Details (Connect & Drops)
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    // Familia do endereco: 4 ou 6. Zero significa "evento que nao e de rede".
    // Sem este campo nao ha como distinguir um destino IPv4 de um IPv6 truncado
    // nos 4 primeiros bytes, e a conexao IPv6 apareceria como um IPv4 inventado.
    u8  ip_ver;
    u8  daddr6[16];    // destino IPv6, em ordem de rede

    // Credenciais resultantes (type_id 'S'). Guardadas ao lado do loginuid que
    // populate_basic_info ja coleta: o par (quem entrou, o que virou) e o que
    // permite dizer se houve escalada, e nao apenas que o processo e root.
    u32 new_uid;
    u32 new_euid;
    u32 exit_code;     // type_id 'X'
    u32 proto;         // [NEW] Protocol (TCP=6/UDP=17) for drops
    u64 net_len;       // Packet length
    
    // Memory & I/O Details
    u64 mem_vsz;
    u64 mem_peak_rss;
    u64 io_bytes;
    u64 io_latency_ns; // Time spent waiting for disk (Delta)
    
    // Security / Inspection Details
    u32 inspector_pid; // Who is inspecting this process?
    int prio;
};

// ============================================================================
// BPF MAPS (Storage)
// ============================================================================

// Event Buffer (High bandwidth events)
BPF_PERF_OUTPUT(events);

// 1. Latency Tracking Maps (Temporary storage for start times)
// Key: PID, Value: Timestamp (ns)
BPF_HASH(io_start, u32, u64);

// 2. Traffic Aggregation Maps (To avoid spamming perf buffer for every byte)
// Key: PID, Value: Bytes
BPF_HASH(net_bytes_sent, u32, u64);
BPF_HASH(net_bytes_recv, u32, u64);

// 3. Health Counters
// Key: PID, Value: Count
BPF_HASH(tcp_retrans_map, u32, u64);
BPF_HASH(tcp_drop_map, u32, u64);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static int populate_basic_info(struct event_data_t *data) {
    u64 id = bpf_get_current_pid_tgid();
    data->pid = id >> 32;

    // Ignore the agent's own traffic/actions to avoid feedback loops
    if (data->pid == FILTER_PID) return 1;

    data->uid = bpf_get_current_uid_gid();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->ppid = task->real_parent->tgid;
    data->prio = task->prio;
    
    // [NEW] Capture LoginUID (Audit ID) - Tracks original user across sudo/screen
    // Logic for newer kernels (OpenSUSE 15.6 uses kernel 6.4+)
    // If this fails on older kernels, BCC usually zeros it out or we can add #ifdefs later.
    data->loginuid = task->loginuid.val;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    if (task->mm) {
        data->mem_vsz = task->mm->total_vm << 12; // Pages to Bytes
        data->mem_peak_rss = task->mm->hiwater_rss << 12;
    }
    return 0;
}

// ============================================================================
// PROBES: PROCESS & FILE SYSTEM
// ============================================================================

// 1. EXECVE: New Process Creation
int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;

    data.type_id = 'E';
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 2. OPENAT: File Opening
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;

    data.type_id = 'O';
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// ============================================================================
// PROBES: DISK I/O LATENCY (The "Hot" Metric)
// ============================================================================

// Entry Probe: Record start timestamp
int kprobe__vfs_read(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;
    
    u64 ts = bpf_ktime_get_ns();
    io_start.update(&pid, &ts);
    return 0;
}

// Return Probe: Calculate Delta (Latency) and Bytes
int kretprobe__vfs_read(struct pt_regs *ctx) {
    struct event_data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    // Calculate Latency
    u64 *tsp = io_start.lookup(&pid);
    if (tsp) {
        u64 delta = bpf_ktime_get_ns() - *tsp;
        // Optimization: Only report if latency > 1ms (1,000,000ns) or large read
        // to reduce noise, unless it's critical.
        data.io_latency_ns = delta;
        io_start.delete(&pid);
    }

    ssize_t ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        if (populate_basic_info(&data)) return 0;
        data.type_id = 'R';
        data.io_bytes = ret;
        
        // Submit if we have significant data
        if (data.io_bytes > 0) events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Entry Probe: Record start timestamp for Write
int kprobe__vfs_write(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;
    
    u64 ts = bpf_ktime_get_ns();
    io_start.update(&pid, &ts);
    return 0;
}

// Return Probe: Write Latency
int kretprobe__vfs_write(struct pt_regs *ctx) {
    struct event_data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u64 *tsp = io_start.lookup(&pid);
    if (tsp) {
        data.io_latency_ns = bpf_ktime_get_ns() - *tsp;
        io_start.delete(&pid);
    }

    ssize_t ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        if (populate_basic_info(&data)) return 0;
        data.type_id = 'W';
        data.io_bytes = ret;
        if (data.io_bytes > 0) events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// ============================================================================
// PROBES: NETWORK BUFFER & TRAFFIC (Driver Level)
// ============================================================================

// 1. TCP Connect (New Connections)
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;

    data.type_id = 'N';
    data.ip_ver = 4;
    struct sockaddr_in *daddr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);

    // [PATCH] Using SAFE_KREAD for Kernel 6.x compatibility
    SAFE_KREAD_N(&data.daddr, sizeof(data.daddr), &daddr->sin_addr.s_addr);
    SAFE_KREAD_N(&data.dport, sizeof(data.dport), &daddr->sin_port);

    // Get Source Info from Socket
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.sport = sk->__sk_common.skc_num;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 1b. TCP Connect sobre IPv6.
//
// Sem esta sonda, TODA conexao IPv6 e invisivel para a ferramenta: o host podia
// falar com qualquer destino v6 e a arvore de processos nao registrava conexao
// nenhuma. Nao e um detalhe de cobertura, e um ponto cego inteiro, e em rede
// moderna o v6 costuma ser o caminho preferido quando existe.
//
// O simetrico do v4: o destino vem do sockaddr passado na chamada, e a porta de
// origem do proprio socket.
int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;

    data.type_id = 'N';
    data.ip_ver = 6;

    struct sockaddr_in6 *daddr = (struct sockaddr_in6 *)PT_REGS_PARM2(ctx);

    // 16 bytes com tamanho explicito: aqui a macro que infere sizeof do ponteiro
    // leria 8 e o endereco chegaria pela metade, silenciosamente.
    SAFE_KREAD_N(&data.daddr6, sizeof(data.daddr6),
                 &daddr->sin6_addr.in6_u.u6_addr8);
    SAFE_KREAD_N(&data.dport, sizeof(data.dport), &daddr->sin6_port);

    data.sport = sk->__sk_common.skc_num;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// ============================================================================
// PROBES: CICLO DE VIDA, CREDENCIAIS, MODULO DE KERNEL E ESCUTA
// ============================================================================

// Fim de processo.
//
// Sem isto o agente so descobre que um processo sumiu comparando duas capturas,
// e nunca sabe QUANDO ele terminou. E o que faltava para existir o evento
// process.end e, com ele, a linha do tempo deixar de ter apenas nascimentos.
TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;

    data.type_id = 'X';

    struct task_struct *tarefa = (struct task_struct *)bpf_get_current_task();
    SAFE_KREAD_N(&data.exit_code, sizeof(data.exit_code), &tarefa->exit_code);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Mudanca de credencial.
//
// UMA sonda em commit_creds cobre a CLASSE inteira, porque toda troca de
// credencial do kernel passa por aqui: setuid, setresuid, capset, e tambem a
// credencial forjada por um exploit de kernel. Tres sondas de syscall cobririam
// apenas as trocas pedidas pelas vias normais, que sao justamente as que um
// exploit NAO usa; a ficha AM-001 descreve um caminho cujo passo final e
// exatamente uma chamada a commit_creds com credencial fabricada.
//
// Aqui so se COLETA o par (credencial que entrou, credencial que saiu). Julgar
// se houve escalada e trabalho da regra, que precisa do loginuid e da arvore
// para nao acusar todo sudo legitimo.
int kprobe__commit_creds(struct pt_regs *ctx, struct cred *new_cred) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;

    data.type_id = 'S';
    SAFE_KREAD_N(&data.new_uid, sizeof(data.new_uid), &new_cred->uid.val);
    SAFE_KREAD_N(&data.new_euid, sizeof(data.new_euid), &new_cred->euid.val);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Carga de modulo de kernel: o caminho classico de rootkit.
//
// Hoje a ferramenta nao ve nenhuma. O coletor de persistencia le a configuracao
// de autoload em disco, que mostra o que foi CONFIGURADO para carregar, nunca o
// que esta sendo carregado agora. Um modulo inserido a mao nao deixa rastro
// naquele caminho.
int syscall__init_module(struct pt_regs *ctx) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'M';
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__finit_module(struct pt_regs *ctx, int fd, const char __user *args_u) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'M';
    // O nome do modulo nao vem no argumento; o que existe e o descritor do
    // arquivo. Guarda-se os parametros, que costumam identificar a carga.
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args_u);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// bind(): o momento em que um socket passa a escutar.
//
// Um backdoor que abre porta era completamente invisivel: existe sonda de
// conexao de SAIDA (tcp_connect) e nenhuma de ENTRADA. Guarda-se a familia e a
// porta; o julgamento de "esta porta deveria existir?" e da regra, nao daqui.
int syscall__bind(struct pt_regs *ctx, int fd, struct sockaddr *endereco) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;

    data.type_id = 'L';

    u16 familia = 0;
    SAFE_KREAD_N(&familia, sizeof(familia), &endereco->sa_family);

    if (familia == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)endereco;
        data.ip_ver = 4;
        SAFE_KREAD_N(&data.dport, sizeof(data.dport), &v4->sin_port);
        SAFE_KREAD_N(&data.daddr, sizeof(data.daddr), &v4->sin_addr.s_addr);
    } else if (familia == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)endereco;
        data.ip_ver = 6;
        SAFE_KREAD_N(&data.dport, sizeof(data.dport), &v6->sin6_port);
        SAFE_KREAD_N(&data.daddr6, sizeof(data.daddr6),
                     &v6->sin6_addr.in6_u.u6_addr8);
    } else {
        // AF_UNIX e demais familias: registra o bind sem endereco de rede.
        data.ip_ver = 0;
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 2. Interface Buffer TX (Queuing) - Replaces simple tcp_sendmsg for lower level view
TRACEPOINT_PROBE(net, net_dev_xmit) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u64 len = args->len;
    u64 zero = 0, *val;
    
    // Aggregate Total Bytes Sent
    val = net_bytes_sent.lookup_or_try_init(&pid, &zero);
    if (val) { (*val) += len; }

    return 0;
}

// 3. Interface Buffer RX - Replaces tcp_cleanup_rbuf
TRACEPOINT_PROBE(net, netif_receive_skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u64 len = args->len;
    u64 zero = 0, *val;

    // Aggregate Total Bytes Received
    val = net_bytes_recv.lookup_or_try_init(&pid, &zero);
    if (val) { (*val) += len; }

    return 0;
}

// 4. TCP Retransmissions (Congestion/Packet Loss)
TRACEPOINT_PROBE(tcp, tcp_retransmit_skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u64 zero = 0, *val;
    val = tcp_retrans_map.lookup_or_try_init(&pid, &zero);
    if (val) (*val)++;
    
    return 0;
}

// 5. Packet Drops (Detailed Analysis) [UPDATED v0.50.41]
// We now parse the SKB to see WHAT is being dropped (Source/Dest IP)
TRACEPOINT_PROBE(skb, kfree_skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Always count drops in the aggregated map for stats
    u64 zero = 0, *val;
    val = tcp_drop_map.lookup_or_try_init(&pid, &zero);
    if (val) (*val)++;

    // If it's the agent itself, don't analyze headers
    if (pid == FILTER_PID) return 0;

    // [NEW] Deep Drop Analysis
    // We attempt to read the IP header from the sk_buff
    // Note: 'args->skbaddr' is the pointer to struct sk_buff
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    
    // Only proceed if we can read the network header
    unsigned char *head;
    u16 network_header;
    
    // [PATCH] Using SAFE_KREAD for Kernel 6.x compatibility (Reading sk_buff struct)
    SAFE_KREAD(&head, &skb->head);
    SAFE_KREAD(&network_header, &skb->network_header);

    // Assume IPv4 for now (version check usually needed but kept simple for perf)
    struct iphdr iph;
    
    // [PATCH] Using SAFE_KREAD for Kernel 6.x compatibility (Reading packet data via ptr)
    SAFE_KREAD(&iph, head + network_header);

    // If protocol is TCP (6) or UDP (17), capture it
    if (iph.protocol == 6 || iph.protocol == 17) {
        struct event_data_t data = {};
        
        // We use PID 0 if the drop happens in SoftIRQ context (Driver level)
        // But we still want to report the packet details.
        data.pid = pid;
        data.uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        
        data.type_id = 'D'; // Drop Event
        data.saddr = iph.saddr;
        data.daddr = iph.daddr;
        data.proto = iph.protocol;
        data.net_len = skb->len;
        
        // Extract Ports (Offset depends on IHL)
        // IP Header Length is in 32-bit words
        u8 ihl = iph.ihl * 4;
        
        // Read Transport Header (TCP/UDP ports are at the start)
        struct tcphdr tcph;
        // [PATCH] Using SAFE_KREAD for Kernel 6.x compatibility
        SAFE_KREAD(&tcph, head + network_header + ihl);
        
        data.sport = tcph.source;
        data.dport = tcph.dest;
        
        // Submit individual Drop events to Perf Buffer.
        // The Python engine will filter or aggregate these to show "Process X had Y drops"
        events.perf_submit(args, &data, sizeof(data));
    }

    return 0;
}

// ============================================================================
// PROBES: HORIZONTAL INSPECTION (Fanotify)
// ============================================================================

/* * NOTE: Since fanotify tracepoints vary by kernel version, we rely on 
 * the logic that if a process spends time in `fanotify_read` or `fsnotify`,
 * it is the Inspector. The Python side correlates this via /proc/fdinfo 
 * flags (Blocking vs Async). 
 * * However, we can track 'fsnotify' calls to see volume of inspection.
 */

int kprobe__fsnotify(struct pt_regs *ctx) {
    // This function is called whenever a file event happens that is watched.
    // It's too high volume to log everything, but we can verify if the current 
    // process is triggering inspection.
    return 0;
}