# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/sys_inspector/bpf_programs.py
# DESCRIPTION: C source eBPF. Added Process Priority (prio) extraction.
# ===============================================================================

BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/mm_types.h>

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

    // New: Process Priority
    int prio;
};

BPF_PERF_OUTPUT(events);

static int populate_basic_info(struct event_data_t *data) {
    u64 id = bpf_get_current_pid_tgid();
    data->pid = id >> 32;

    if (data->pid == FILTER_PID) return 1;

    data->uid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->ppid = task->real_parent->tgid;

    // Extract Priority (Nice value logic is derived from this)
    // In kernel: prio < 100 is realtime, 100-139 is normal user space.
    // Standard nice 0 is usually prio 120.
    data->prio = task->prio;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    if (task->mm) {
        data->mem_vsz = task->mm->total_vm << 12;
        data->mem_peak_rss = task->mm->hiwater_rss << 12;
    }
    return 0;
}

// --- HOOKS ---

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
"""
