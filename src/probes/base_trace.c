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
 * VERSION: 0.70.08 (Patched for Kernel 6.x/SLES16 Compatibility)
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

// [PATCH] Compatibility Macro for Memory Reads (SLES 12/15 vs SLES 16)
// Kernel 5.8+ enforces strict separation between user/kernel memory reads.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    #define SAFE_KREAD(dst, src) bpf_probe_read_kernel(dst, sizeof(dst), src)
#else
    #define SAFE_KREAD(dst, src) bpf_probe_read(dst, sizeof(dst), src)
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
    struct sockaddr_in *daddr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    
    // [PATCH] Using SAFE_KREAD for Kernel 6.x compatibility
    SAFE_KREAD(&data.daddr, &daddr->sin_addr.s_addr);
    SAFE_KREAD(&data.dport, &daddr->sin_port);
    
    // Get Source Info from Socket
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.sport = sk->__sk_common.skc_num;

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