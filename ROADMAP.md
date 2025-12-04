# Project Roadmap

This document outlines the development trajectory of **Sys-Inspector**.

## ✅ Completed (v0.30.x)

- [x] **Core eBPF Integration**
    - Replace `psutil` with `bcc` (kprobes/tracepoints).
    - Capture `execve`, `openat`, `tcp_connect`.
- [x] **Advanced Forensics**
    - Real-time MD5 Hashing.
    - Context Awareness (SSH Source, Sudo User).
    - Detection of "Unsafe" library loading (`LD_PRELOAD` / `/tmp`).
- [x] **Network Monitoring**
    - TCP Retransmission detection (Network Health).
    - Bandwidth accounting per process (RX/TX).
    - Network Topology (Gateway/DNS).
- [x] **UI/UX & Reporting**
    - Self-contained HTML Report.
    - **Hierarchical Storage Topology** (Disk/Part/LVM tree).
    - **Recursive Alerting** (Child -> Parent propagation).
    - Dark Mode & Sticky Headers.
- [x] **Code Quality**
    - Pylint 10/10 Compliance.
    - Flake8 Compliance.
    - Modular Architecture (`src/sys_inspector`).

## 🚧 In Progress / Next Steps

- [ ] **Container Awareness**
    - Detect if a PID belongs to a Docker/Kubernetes container.
    - Extract Pod Name / Container ID namespaces.
- [ ] **Long-term Storage**
    - Option to export data to JSON/SQLite for historical comparison.
    - Compare two reports (Diff View).

## 🔮 Future Ideas

- [ ] **Remote Dashboard**
    - A lightweight Golang/Python server to aggregate reports from multiple agents.
- [ ] **eBPF CO-RE (Compile Once – Run Everywhere)**
    - Migrate from BCC (Python compiler) to `libbpf` for portability across kernel versions without needing kernel headers installed.
- [ ] **GPU Monitoring**
    - Attach to NVIDIA driver tracepoints to detect unauthorized crypto-mining.