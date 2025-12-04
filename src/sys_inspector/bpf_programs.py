# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/sys_inspector/bpf_programs.py
# DESCRIPTION: C source eBPF. Includes Process, File I/O, and Network Stats.
#              Process Priority (prio) extraction and Traffic Monitoring.
# VERSION: 0.30.3
# ===============================================================================

BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/mm_types.h>
#include <bcc/proto.h>

// Replace 00000 with Python PID
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

// Traffic Maps (Bytes sent/recv)
BPF_HASH(net_bytes_sent, u32, u64);
BPF_HASH(net_bytes_recv, u32, u64);

// --- HELPERS ---

static int populate_basic_info(struct event_data_t *data) {
    u64 id = bpf_get_current_pid_tgid();
    data->pid = id >> 32;

    if (data->pid == FILTER_PID) return 1;

    data->uid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->ppid = task->real_parent->tgid;

    data->prio = task->prio;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    if (task->mm) {
        data->mem_vsz = task->mm->total_vm << 12;
        data->mem_peak_rss = task->mm->hiwater_rss << 12;
    }
    return 0;
}

// --- PROBES (SYSCALLS & KPROBES) ---

int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'E';
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'O';
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct event_data_t data = {};
    if (populate_basic_info(&data)) return 0;
    data.type_id = 'N';
    struct sockaddr_in *daddr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    bpf_probe_read(&data.daddr, sizeof(data.daddr), &daddr->sin_addr.s_addr);
    bpf_probe_read(&data.dport, sizeof(data.dport), &daddr->sin_port);
    data.saddr = sk->__sk_common.skc_rcv_saddr;
    data.sport = sk->__sk_common.skc_num;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kretprobe__vfs_read(struct pt_regs *ctx) {
    struct event_data_t data = {};
    ssize_t ret = PT_REGS_RC(ctx);
    if (ret > 0) {
        if (populate_basic_info(&data)) return 0;
        data.type_id = 'R';
        data.io_bytes = ret;
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

// --- NETWORK TRACEPOINTS (Health) ---

TRACEPOINT_PROBE(tcp, tcp_retransmit_skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID) return 0;

    u64 zero = 0, *val;
    val = tcp_retrans_map.lookup_or_try_init(&pid, &zero);
    if (val) (*val)++;
    return 0;
}

TRACEPOINT_PROBE(skb, kfree_skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == FILTER_PID || pid == 0) return 0;

    u64 zero = 0, *val;
    val = tcp_drop_map.lookup_or_try_init(&pid, &zero);
    if (val) (*val)++;
    return 0;
}
"""
