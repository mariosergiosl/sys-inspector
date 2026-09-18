# Project Roadmap

This document outlines the development trajectory of **Sys-Inspector**.

## ✅ Completed (v1.1.0)

- [x] **One execution path** (breaking change). The `snapshot`, `live` and
  `local-live` modes were removed. A single machine now runs the agent and the
  server side by side; a one-off capture is `--mode daemon --once`.
- [x] **HTTPS as the only transport.** The plaintext path was removed from the
  code, not merely disabled. The server refuses to start if TLS cannot be
  enabled, and the agent always speaks HTTPS.
- [x] **Report interface rebuilt around the process tree.** Real table header,
  resizable columns in both the report and the manager panel, column geometry
  coming from a single source, scrolling confined to the tree.
- [x] **Every field always visible.** A field with no value is shown in one of
  three states, so "looked and found nothing" is never confused with "did not
  look".
- [x] **Rootkit indicators**, from the kernel and from user space, alongside the
  existing hidden-process detection.
- [x] **Directed evidence acquisition**, bounded so that the agent collects
  enough to identify and direct the analyst, never the bulk that proves.
- [x] **Network event formatting extracted from the eBPF loop**, so address and
  protocol rendering can be tested without a kernel.
- [x] **Single badge registry**, replacing three divergent copies of the same
  map.
- [x] **Test scenario repaired and instrumented.** The scenario script was not
  running at all on the target, and the agent reported "capturing anyway",
  which made the failure invisible. Both were fixed and both are now covered by
  tests.

## ✅ Completed (v1.0.0 - first stable release)

- [x] **Answer contract per finding** (confidence: confirmed/probable/heuristic; custody: what was preserved).
- [x] **Distributed agent/server fleet** (pull model, encrypted outbox, prioritized ingestion, audited command queue, per-agent capabilities, HTTPS).
- [x] **Manager command stepper** (enqueued -> on the agent -> done/failed, live timer).
- [x] **Report as an investigation** (how-to-read strip, severity legend with action, evidence tooltips, two-way Findings <-> ATT&CK coupling).
- [x] **Runtime and anti-forensic detection** (hidden processes, thread divergence, W+X memory, replaced binary, untrusted libraries, immutable files).
- [x] **Version single source of truth** across screens, custody stamp, spec and scripts.
- [x] **Packaging split by role** (base, agent, server, scenarios).

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

## ✅ Completed (v0.91.x)

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

- [~] **Detection assurance loop** *(partly delivered)*
  - Agents report their capabilities so the server knows what can be measured
    on each host.
  - The test scenario declares what it ran, with the signal each check should
    produce; the server cross-checks generation against detection.
  - A calibration instrument, explicitly not forensic evidence: it runs on the
    inspected host and can be tampered with.
- [ ] **Super-timeline**
  - A single ordered stream of every event (process spawn, persistence created,
    connection opened, finding raised), so sequence becomes visible.
- [x] **Correlation rules** *(delivered in v1.0.0)*
  - Turn several weak signals into one conclusion that no single signal
    supports on its own. Four rules run over real captured events: active
    command channel, persistence created after activity, the same artefact seen
    across several hosts, and a sequence of techniques read as one progression.
- [ ] **SCAP / compliance cross-reference**
  - Static policy deviation combined with observed runtime execution, to answer
    whether a deviation was actually exercised.
- [ ] **Dual eBPF backends**
  - BCC and libbpf/CO-RE available side by side, not one replacing the other,
    so results from two independent capture methods can be compared.
- [x] **Role-separated packaging** *(delivered in v1.0.0)*
  - Distinct agent, server and common packages, so an inspected host does not
    carry server code. Four packages are published per release: base, agent,
    server and scenarios.
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
  - v0.90.16 landed optional HTTP Basic Auth and HTTPS as a first step. As of
    v1.1.0 HTTPS is mandatory and authentication is always on, but there is
    still a single credential: role-based authorization remains pending.
