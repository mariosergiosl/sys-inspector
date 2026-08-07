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

## ✅ Completed (v0.91.x, unreleased)

- [x] **Forensic evidence chain**
  - Canonical digest, agent-signed captures, hash chaining between captures.
  - Case ID, operator, `boot_id` and `machine_id` recorded with every capture.
- [x] **Findings model**
  - Single severity scale across every collector; stable fingerprints.
  - Persistence enumeration (systemd, cron, ld.so.preload, udev, PAM, keys).
  - Package provenance (`rpm -qf` / `rpm -Vf`) used to judge findings.
- [x] **Hidden process detection**
  - Cross-checks `/proc` against what the kernel answers for a signal.
  - Divergence is the finding; confirmed across rounds to rule out short-lived
    processes.
- [x] **Store-and-forward transport**
  - Agent-side outbox with exponential backoff; server-side ingest queue with
    priority and digest-based deduplication.
  - The server never connects to an agent: the agent asks and writes.
- [x] **Remote actions, delivered reliably**
  - Closed list of queued actions, full request audit log.
  - At-least-once delivery with agent-side idempotency, so an action is never
    lost and never runs twice.
- [x] **Capture comparison**
  - What changed between two captures: processes that appeared, disappeared or
    were altered, and findings gained or lost.
  - Behaviour over time: whether an artefact ran once or runs on every capture.
- [x] **Detection self-check**
  - Verifies that what the test scenario generated was actually captured,
    separating "not applicable on this host" from a genuine detection miss.

## 🚧 In Progress / Next Steps

- [ ] **Detection assurance loop**
  - Agents report their capabilities so the server knows what can be measured
    on each host.
  - The test scenario declares what it ran, with the signal each check should
    produce; the server cross-checks generation against detection.
  - A calibration instrument, explicitly not forensic evidence: it runs on the
    inspected host and can be tampered with.
- [ ] **Super-timeline**
  - A single ordered stream of every event (process spawn, persistence created,
    connection opened, finding raised), so sequence becomes visible.
- [ ] **Correlation rules**
  - Turn several weak signals into one conclusion that no single signal
    supports on its own.
- [ ] **SCAP / compliance cross-reference**
  - Static policy deviation combined with observed runtime execution, to answer
    whether a deviation was actually exercised.
- [ ] **Dual eBPF backends**
  - BCC and libbpf/CO-RE available side by side, not one replacing the other,
    so results from two independent capture methods can be compared.
- [ ] **Role-separated packaging**
  - Distinct agent, server and common packages, so an inspected host does not
    carry server code.
- [ ] **Container awareness**
  - Detect whether a PID belongs to a container; surface pod and container
    identity alongside the process.

## 🔮 Future Ideas

- [ ] **Red-team scenario suite**
  - Each attack technique becomes a declared test case with an expected signal,
    turning "this tool detects technique X" into something provable rather than
    claimed.
- [ ] **GPU Monitoring**
  - Attach to NVIDIA driver tracepoints to detect unauthorized crypto-mining.
- [ ] **Role-Based Access Control (RBAC)**
  - Add authentication and authorization to the Fleet View Dashboard.
  - v0.90.16: optional HTTP Basic Auth and HTTPS landed as a first step (single credential; full role-based authorization is still pending).
