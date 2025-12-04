/*
 * FILE: src/sys_inspector/bpf_program.c
 * DESCRIPTION: C source eBPF for Sys-Inspector.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/mm_types.h>
#include <bcc/proto.h>

// Replace 00000 with Python PID (Will be handled by Python loader)
#define FILTER_PID 00000

struct event_data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char type_id;
    u32 saddr; u32 daddr; u16 sport; u16 dport;
    u64 mem_vsz;
    u64 mem_peak_rss;
    u64 io_bytes;
    
    // Process Priority
    int prio;
};

// Event Buffer (For detailed logs like Exec/Open)
BPF_PERF_OUTPUT(events);

// Stats Maps (For high-volume metrics aggregation)
// Key: PID, Value: Count
BPF_HASH(tcp_retrans_map, u32, u64);
BPF_HASH(tcp_drop_map, u32, u64);
BPF_HASH(net_bytes_sent, u32, u64);
BPF_HASH(net_bytes_recv, u32, u64);


// --- PROCESS LIFECYCLE ---

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    struct event_data_t data = {};
    data.pid = pid;
    
    // Parent PID extraction
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    
    // Priority (Nice value calculation: prio - 120)
    data.prio = task->prio;

    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);

    data.type_id = 'E'; // Execve
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// --- FILE I/O ---

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    struct event_data_t data = {};
    data.pid = pid;
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    data.prio = task->prio;
    
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);
    
    // Update Memory Usage (RSS)
    if (task->mm) {
        data.mem_peak_rss = task->mm->hiwater_rss * 4096; // Pages to Bytes
    }

    data.type_id = 'O'; // Open
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// --- NETWORK ---

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    struct event_data_t data = {};
    data.pid = pid;
    
    // Extract socket details
    u16 dport = sk->__sk_common.skc_dport;
    data.dport = ntohs(dport);
    data.daddr = sk->__sk_common.skc_daddr;
    
    // Comm & Metadata
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;
    data.prio = task->prio;
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.type_id = 'N'; // Network Connect
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// --- DISK I/O METRICS ---

// Helper to populate basic info for Return Probes
static int populate_basic_info(struct event_data_t *data) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 1; // Skip

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->pid = pid;
    data->ppid = task->real_parent->tgid;
    data->uid = bpf_get_current_uid_gid();
    data->prio = task->prio;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // Capture memory peak
    if (task->mm) {
        data->mem_peak_rss = task->mm->hiwater_rss * 4096;
    }
    return 0;
}

int kretprobe__vfs_read(struct pt_regs *ctx) {
    struct event_data_t data = {};
    ssize_t ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        if (populate_basic_info(&data)) return 0;
        data.type_id = 'R'; // Read
        data.io_bytes = ret;
        // Optimization: Only send event if IO > 4KB to reduce noise
        if (data.io_bytes > 4096) events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

int kretprobe__vfs_write(struct pt_regs *ctx) {
    struct event_data_t data = {};
    ssize_t ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        if (populate_basic_info(&data)) return 0;
        data.type_id = 'W';
        data.io_bytes = ret;
        if (data.io_bytes > 4096) events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// --- TRAFFIC ACCOUNTING ---

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;
    
    u64 zero = 0, *val;
    val = net_bytes_sent.lookup_or_try_init(&pid, &zero);
    if (val) { (*val) += size; }
    return 0;
}

int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;
    if (copied <= 0) return 0;

    u64 zero = 0, *val;
    val = net_bytes_recv.lookup_or_try_init(&pid, &zero);
    if (val) { (*val) += copied; }
    return 0;
}