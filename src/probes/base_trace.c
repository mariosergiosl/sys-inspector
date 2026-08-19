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

// Evento de consulta DNS, em canal PROPRIO.
//
// Nao cabe no evento comum: a pilha de um programa BPF tem 512 bytes no total, o
// evento comum ja ocupa quase tudo, e acrescentar um buffer de payload nele fez a
// sonda de descarte de pacote parar de carregar. Um evento pequeno e dedicado
// resolve sem espremer o que ja existe, e deixa claro que este canal carrega bytes
// crus a serem interpretados no espaco de usuario (D-030).
struct dns_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    // [2026-08-19] Era 96. Virou 128 por uma razao que NAO e capacidade: a
    // mascara "n & (tamanho - 1)", que o verificador exige para aceitar leitura
    // de tamanho variavel, so funciona quando o tamanho e POTENCIA DE DOIS.
    // Com 96, a mascara vira "n & 95", que nao e contigua em bits: um envio de
    // 40 bytes lia 40 & 95 = 8 bytes, e o parser montava nome a partir de
    // zeros. Medido: nomes saiam como "te" seguido de bytes nulos.
    //
    // Isso e a MESMA familia do defeito original desta sonda e do SAFE_KREAD:
    // uma conta de tamanho errada que nao levanta erro nenhum, so entrega dado
    // fabricado. Com 128 a mascara e "n & 127", contigua, e a leitura passa a
    // valer o que foi pedido.
    u8  payload[128];
    u16 payload_len;
};
BPF_PERF_OUTPUT(dns_events);

// Evento de ClientHello TLS, para extrair o SNI (C-022).
//
// Mesmo molde do DNS, e pelo mesmo motivo: bytes crus num canal proprio, parse
// no Python (D-030). Duas diferencas, as duas deliberadas.
//
// 1. O BUFFER NAO FICA NA PILHA. Um programa BPF tem 512 bytes de pilha no
//    TOTAL, e o SNI pode estar depois do byte 200 do ClientHello (a extensao
//    server_name vem depois de random, session_id e da lista de cifras). Um
//    buffer util aqui ja estoura a pilha sozinho. A saida e um mapa PERCPU de
//    um elemento so, usado como area de rascunho: mora no mapa, nao na pilha, e
//    por ser por-CPU nao precisa de trava.
// 2. A leitura e CLAMPADA pelo tamanho do envio, nunca fixa. Ler um tamanho
//    fixo maior que o buffer do processo e a mesma familia de defeito do
//    SAFE_KREAD que media o ponteiro: a leitura falha inteira (nao ha leitura
//    parcial) e a sonda passa a nao entregar nada, indistinguivel de "nao houve
//    ClientHello". A mascara "& (tamanho - 1)" existe porque o verificador do
//    kernel so aceita tamanho variavel quando consegue provar o limite.
struct tls_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u16 payload_len;
    u8  payload[512];
};
BPF_PERCPU_ARRAY(tls_rascunho, struct tls_event_t, 1);
BPF_PERF_OUTPUT(tls_events);

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

// Onde o msghdr guarda os bytes que o processo mandou enviar.
//
// Extraido da sonda de DNS, que foi onde o problema apareceu e foi resolvido, e
// agora compartilhado com a sonda de TLS/SNI. O motivo de existir como funcao e
// que este conhecimento tem VERSAO: o campo `iov` virou `__iov` no kernel 6.4, e
// manter a guarda de versao copiada em duas sondas e a receita da divergencia
// silenciosa -- uma delas seria corrigida um dia e a outra nao.
//
// ATENCAO ao usar: o ponteiro devolvido NAO e necessariamente o buffer. O membro
// e uma UNIAO cujo conteudo depende do tipo do iterador:
//
//   ITER_UBUF  -> o ponteiro JA E o buffer do usuario (envio de segmento unico)
//   ITER_IOVEC -> o ponteiro e um VETOR; o buffer esta no primeiro elemento
//
// Quem chama resolve isso TENTANDO ler como buffer direto e caindo para o vetor
// se falhar, e nao lendo `iter_type`: o valor do enum muda entre versoes de
// kernel, e usar o resultado da propria leitura como discriminante vale em
// qualquer versao, sem tabela para manter.
static void *ponteiro_do_msg_iter(struct msghdr *msg) {
    void *ponteiro = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    SAFE_KREAD_N(&ponteiro, sizeof(ponteiro), &msg->msg_iter.__iov);
#else
    SAFE_KREAD_N(&ponteiro, sizeof(ponteiro), &msg->msg_iter.iov);
#endif
    return ponteiro;
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

// Conexao ACEITA. O par do bind: bind diz que abriu porta, accept diz que alguem
// entrou. Sem isto uma escuta maliciosa parece inofensiva ate ser usada.
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'A';
    data.ip_ver = 4;
    data.daddr = sk->__sk_common.skc_daddr;
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.sport = sk->__sk_common.skc_num;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// ptrace: injecao e leitura de memoria alheia. Um processo lendo a memoria de
// outro e legitimo em depurador e quase nada mais; num host de producao e um dos
// sinais mais diretos de roubo de credencial e de injecao de codigo.
int syscall__ptrace(struct pt_regs *ctx, long request, long pid_alvo) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'P';
    data.inspector_pid = (u32)pid_alvo;   // quem esta sendo lido
    data.prio = (int)request;             // operacao pedida
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__process_vm_readv(struct pt_regs *ctx, long pid_alvo) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'P';
    data.inspector_pid = (u32)pid_alvo;
    data.prio = -1;                       // marca a via alternativa do ptrace
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// memfd_create: arquivo que existe so em memoria, nunca toca o disco. E a base da
// execucao fileless, e o coletor de disco por definicao nao alcanca.
int syscall__memfd_create(struct pt_regs *ctx, const char __user *nome) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'G';
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), nome);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// mprotect concedendo execucao a memoria gravavel. E o momento exato em que um
// shellcode se torna executavel; o coletor de /proc so ve o RESULTADO, e depois.
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
int syscall__mprotect(struct pt_regs *ctx, unsigned long inicio,
                      size_t tamanho, unsigned long prot) {
    if (!(prot & PROT_EXEC)) return 0;     // so interessa quando vira executavel
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'Z';
    data.mem_vsz = (u64)tamanho;
    data.prio = (int)prot;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// bpf(): rootkit baseado em eBPF. A ferramenta usa eBPF; um atacante tambem pode.
// Nao registrar isto seria deixar cego justamente o mecanismo que nos sustenta.
int syscall__bpf(struct pt_regs *ctx, int cmd) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'B';
    data.prio = cmd;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Apagar e renomear: anti-forense. Log removido no meio de um incidente e o
// proprio incidente. O diff entre capturas ve o arquivo sumir, mas nao ve QUEM.
int kprobe__vfs_unlink(struct pt_regs *ctx) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'U';
    data.prio = 0;                         // 0 = apagou
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__vfs_rename(struct pt_regs *ctx) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'U';
    data.prio = 1;                         // 1 = renomeou
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Troca de namespace: fuga de conteiner. setns entra num namespace alheio,
// unshare cria um novo. Os dois aparecem em escape e em exploit de userns, como
// o da ficha AM-001.
int syscall__setns(struct pt_regs *ctx, int fd, int tipo_ns) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'C';
    data.prio = tipo_ns;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__unshare(struct pt_regs *ctx, unsigned long flags) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'C';
    data.prio = (int)flags;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// kexec_load: troca o kernel que sera carregado. E persistencia abaixo de tudo
// que a ferramenta observa, e sobrevive ao reboot que o operador daria como cura.
int syscall__kexec_load(struct pt_regs *ctx) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'K';
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Consulta DNS: o NOME do destino, que hoje falta.
//
// A ferramenta ve o IP de toda conexao, e nao ve o dominio. Inteligencia de
// ameaca trabalha por NOME: as listas de C2 casam dominio, nao endereco. Sem
// isto, "conectou em 185.x.x.x" nao cruza com nada.
//
// Nome de dominio e METADADO, o "com quem", nao o "o que" foi dito: por isso
// permanece no escopo mesmo depois da D-029, que tirou captura de conteudo.
//
// O programa NAO decodifica DNS. Copia um pedaco de tamanho fixo do datagrama e
// entrega; o Python decodifica o nome. E a regra da D-030: o eBPF entrega bytes
// delimitados, o espaco de usuario interpreta. Decodificar aqui exigiria laco
// sobre rotulos com compressao dentro do verificador, que e o que fazia este item
// parecer o mais dificil da lista.
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t tamanho) {
    // Interessa apenas o trafego de resolucao. A porta de destino vive no socket
    // quando ele esta conectado, e no endereco do msghdr quando nao.
    u16 dport = sk->__sk_common.skc_dport;
    dport = ((dport >> 8) | (dport << 8));   // ordem de rede -> ordem do host

    if (dport != 53) {
        struct sockaddr_in *destino = NULL;
        SAFE_KREAD_N(&destino, sizeof(destino), &msg->msg_name);
        if (!destino) return 0;
        u16 porta_msg = 0;
        SAFE_KREAD_N(&porta_msg, sizeof(porta_msg), &destino->sin_port);
        porta_msg = ((porta_msg >> 8) | (porta_msg << 8));
        if (porta_msg != 53) return 0;
    }

    struct dns_event_t dns = {};
    dns.pid = bpf_get_current_pid_tgid() >> 32;
    if (dns.pid == FILTER_PID) return 0;
    bpf_get_current_comm(&dns.comm, sizeof(dns.comm));

    // Onde estao os bytes do datagrama.
    //
    // O campo foi renomeado no kernel (`iov` virou `__iov` no 6.4), e o que ali
    // existe depende do TIPO do iterador, que e uma UNIAO:
    //
    //   ITER_UBUF  -> o ponteiro JA E o buffer do usuario (envio de segmento unico,
    //                 que e o caso de toda consulta DNS por sendto)
    //   ITER_IOVEC -> o ponteiro e um VETOR, e o buffer esta no primeiro elemento
    //
    // Foi exatamente aqui que a primeira versao falhou em silencio: ela supunha
    // sempre o vetor e desreferenciava mais uma vez, lendo lixo. A sonda anexava,
    // disparava, e nunca entregava nome nenhum, que e indistinguivel de "nenhuma
    // consulta aconteceu".
    //
    // O tipo poderia ser lido de `iter_type`, mas o valor do enum MUDA entre
    // versoes de kernel (neste, ITER_UBUF e 5). Em vez de fixar um numero que
    // envelhece, usa-se o resultado da propria leitura como discriminante: se ler
    // do ponteiro como buffer de usuario funciona, era ITER_UBUF. Isso vale em
    // qualquer versao, sem tabela para manter.
    void *ponteiro = ponteiro_do_msg_iter(msg);
    if (!ponteiro) return 0;

    // [2026-08-19] O tamanho da leitura passou a vir do ENVIO, e nao mais fixo
    // em sizeof(payload). A versao anterior lia sempre 96 bytes; uma consulta
    // curta ("a.com" da uns 28 bytes) so era lida por sorte, porque o resto dos
    // 96 caia na mesma pagina ja mapeada. Quando nao cai, bpf_probe_read_user
    // falha a leitura INTEIRA (nao existe leitura parcial) e a sonda deixa de
    // entregar, que e indistinguivel de "nenhuma consulta aconteceu" -- o mesmo
    // desfecho do defeito original desta sonda. A mascara existe porque o
    // verificador so aceita tamanho variavel com limite provado.
    u32 n = (u32)tamanho;
    if (n > sizeof(dns.payload) - 1) n = sizeof(dns.payload) - 1;
    dns.payload_len = (u16)n;

    // Leitura de USUARIO: o buffer pertence ao processo, nao ao kernel.
    if (bpf_probe_read_user(&dns.payload, n & (sizeof(dns.payload) - 1), ponteiro)) {
        // Nao era buffer direto: tratar como vetor e buscar o primeiro segmento.
        void *base = NULL;
        if (bpf_probe_read_kernel(&base, sizeof(base),
                                  &((const struct iovec *)ponteiro)->iov_base))
            return 0;
        if (!base) return 0;
        if (bpf_probe_read_user(&dns.payload, n & (sizeof(dns.payload) - 1), base))
            return 0;
    }

    dns_events.perf_submit(ctx, &dns, sizeof(dns));
    return 0;
}

// SNI: o NOME do destino quando a conexao e TLS (C-022).
//
// O DNS entrega o nome quando o processo resolve. Isso deixa dois buracos que a
// pericia sente: quem resolve por cache (ou por IP fixo, ou por DoH) nunca gera
// consulta DNS, e num host com varios servicos nao ha como amarrar a resolucao
// que aconteceu antes ao fluxo que aconteceu depois. O SNI fecha os dois: ele
// viaja EM CLARO dentro do proprio ClientHello, no mesmo socket da conexao, e
// portanto e o nome dito PELA conexao, nao ao lado dela.
//
// Continua sendo METADADO, o "com quem", nao o "o que": a D-029 tirou conteudo
// do escopo e a nota dela ja registra que DNS e SNI nao caem nessa regra.
//
// Nao decodifica nada aqui, so entrega bytes (D-030). O parse do ClientHello,
// que e um encadeamento de campos de tamanho variavel, fica no Python.
//
// tcp_sendmsg e uma das funcoes mais quentes do kernel, entao a filtragem e em
// tres degraus, do mais barato para o mais caro:
//   1. porta de destino 443, lida direto do socket (sem tocar em memoria de
//      usuario);
//   2. tres bytes do inicio do buffer, o suficiente para reconhecer um registro
//      de handshake TLS (0x16) da versao 3.x -- isso descarta TODO o trafego de
//      dados ja cifrado, que e a esmagadora maioria dos envios numa conexao;
//   3. so entao a copia do bloco maior, e ainda assim para o mapa de rascunho.
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t tamanho) {
    u16 dport = sk->__sk_common.skc_dport;
    dport = ((dport >> 8) | (dport << 8));   // ordem de rede -> ordem do host
    if (dport != 443) return 0;

    // Um ClientHello nao cabe em menos que isto (5 de registro + 4 de handshake
    // + 2 de versao + 32 de random). Menor que isso nao ha o que parsear.
    if (tamanho < 44) return 0;

    void *ponteiro = ponteiro_do_msg_iter(msg);
    if (!ponteiro) return 0;

    // Resolve o buffer real. Mesma licao da sonda de DNS: o membro da uniao pode
    // ja SER o buffer (segmento unico) ou ser um vetor. Aqui a tentativa custa
    // tres bytes, entao o degrau 2 do filtro e o proprio discriminante.
    void *base = ponteiro;
    u8 cabeca[3] = {};
    if (bpf_probe_read_user(&cabeca, sizeof(cabeca), base)) {
        if (bpf_probe_read_kernel(&base, sizeof(base),
                                  &((const struct iovec *)ponteiro)->iov_base))
            return 0;
        if (!base) return 0;
        if (bpf_probe_read_user(&cabeca, sizeof(cabeca), base)) return 0;
    }
    // 0x16 = registro de handshake; 0x03 = familia TLS 1.x na camada de
    // registro (todas as versoes, inclusive a 1.3, se apresentam como 3.x aqui).
    if (cabeca[0] != 0x16 || cabeca[1] != 0x03) return 0;

    int zero = 0;
    struct tls_event_t *ev = tls_rascunho.lookup(&zero);
    if (!ev) return 0;

    ev->pid = bpf_get_current_pid_tgid() >> 32;
    if (ev->pid == FILTER_PID) return 0;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    // Tamanho vindo do ENVIO, nunca fixo: ver o comentario da struct.
    u32 n = (u32)tamanho;
    if (n > sizeof(ev->payload) - 1) n = sizeof(ev->payload) - 1;
    ev->payload_len = (u16)n;
    if (bpf_probe_read_user(&ev->payload, n & (sizeof(ev->payload) - 1), base))
        return 0;

    tls_events.perf_submit(ctx, ev, sizeof(*ev));
    return 0;
}

// mount e pivot_root: o que faltava da fuga de conteiner (C-023).
//
// setns e unshare, que ja existem, contam metade da historia: eles mostram o
// processo TROCANDO de namespace. A outra metade e o que ele faz depois de
// trocar, e e ai que mora a fuga: montar o sistema de arquivos do host dentro do
// conteiner (mount), ou trocar a propria raiz (pivot_root). Sem estas duas, a
// arvore registra "mudou de namespace" e para exatamente antes do passo que
// transforma isolamento quebrado em acesso ao host.
//
// Os dois eventos compartilham o type_id porque respondem a mesma pergunta ("o
// que este processo fez com a arvore de montagem"); prio separa qual foi.
int syscall__mount(struct pt_regs *ctx, const char __user *origem,
                   const char __user *destino, const char __user *tipo,
                   unsigned long flags) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'T';
    data.prio = 0;                          // 0 = mount
    data.mem_vsz = (u64)flags;              // MS_BIND, MS_RDONLY, etc.
    // O DESTINO e o que importa para a pericia: e onde o conteudo passou a
    // aparecer. A origem sem o destino nao diz onde o dado ficou acessivel.
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), destino);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__pivot_root(struct pt_regs *ctx, const char __user *nova_raiz,
                        const char __user *raiz_antiga) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'T';
    data.prio = 1;                          // 1 = pivot_root
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), nova_raiz);
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