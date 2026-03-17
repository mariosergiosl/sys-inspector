# Project Roadmap

This document outlines the development trajectory of **Sys-Inspector**.

## ✅ Completed (v0.90.x)

- [x] **Remote Dashboard & Fleet View**
  - Integrated Web Server via Flask.
  - Centralized view for multiple agents.
- [x] **Forensic Time Machine**
  - SQLite persistent storage for snapshots.
  - Historical timeline navigation in the UI.

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

## 🚧 In Progress / Next Steps

- [ ] **Container Awareness**
  - Detect if a PID belongs to a Docker/Kubernetes container.
  - Extract Pod Name / Container ID namespaces.
- [ ] **Long-term Centralized Server**
  - Dedicated ingestion server to receive payloads from hundreds of remote agents securely.

## 🔮 Future Ideas

- [ ] **eBPF CO-RE (Compile Once – Run Everywhere)**
  - Migrate from BCC (Python compiler) to `libbpf` for portability across kernel versions without needing kernel headers installed.
- [ ] **GPU Monitoring**
  - Attach to NVIDIA driver tracepoints to detect unauthorized crypto-mining.
- [ ] **Role-Based Access Control (RBAC)**
  - Add authentication and authorization to the Fleet View Dashboard.
