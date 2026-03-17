# Migration Strategy: Memusage to Sys-Inspector

**Date:** 2026-03-16
**Version:** 1.1
**Context:** Architectural evolution from User Space monitoring to Kernel Space observability.

## 1. Executive Overview

The sys-inspector project represents a complete re-engineering of the legacy memusage tool. The goal is to transition from a passive monitoring model (polling) to an active observability model (event-driven) using eBPF (Extended Berkeley Packet Filter).

This change aims to eliminate granularity and performance limitations inherent in repetitive /proc filesystem reading, allowing the capture of short-lived events and real-time I/O telemetry.

## 2. Migration Matrix (From-To)

The table below maps the fundamental characteristics of the legacy project and its counterpart in the new architecture.

| Feature            | Memusage (Legacy)                | Sys-Inspector (New v0.90)       | Technical Rationale                                                                                                   |
| :---               | :---                             | :---                            | :---                                                                                                                  |
| **Data Source** | /proc reading via psutil.        | Kernel instrumentation via eBPF. | /proc offers only current state (snapshot). eBPF captures events at the exact moment they occur.          |
| **Mechanism** | Polling (Loop sampling).         | Event-Driven (Hooks).           | Polling consumes unnecessary CPU and misses processes that start and end between cycles.                 |
| **Privileges** | Common User (User Space).        | **Root (sudo)** required.       | The bpf() syscall requires CAP_SYS_ADMIN to load secure bytecode into the Kernel.                         |
| **Structure** | Monolithic script.               | Modular Package (src/ layout).  | Separation of concerns (BPF Loader vs Formatting) and ease of unit testing.                               |
| **Deploy** | Standalone script.               | RPM Package via OBS.            | Standardization for Enterprise Linux distribution.                                                       |
| **Dev Environment**| Local Linux.                     | Hybrid (Win Host + Linux Guest).| Required for JIT compilation of C code and specific Kernel headers.                                       |

## 3. Design Decisions and Constraints

### 3.1. Coding Constraints

* **Encoding:** Strictly **US-ASCII**. No accents or special characters in comments, strings, or variables to ensure universal build compatibility.
* **Standard:** Strict PEP 8 for Python.
* **Headers:** Mandatory standardized comment blocks for Bash and Python files.

### 3.2. Packaging Strategy (OBS/RPM)

Sys-inspector adopts the src/ directory layout to avoid accidental local directory imports during testing.
The .spec file declares native build dependencies:

* python3-bcc (Runtime and Bindings).
* clang / llvm (BPF JIT Compiler).
* kernel-default-devel (Kernel Headers matching uname -r).

## 4. Critical Functionality Analysis

### 4.1. Process Monitoring

* **Legacy:** Iterated over psutil.process_iter().
* **New:** Hooks on execve (entry) and exit_group (exit) syscalls.
* **Gain:** Detection of "ephemeral" processes and accurate ancestry (PPID) guaranteed by the Kernel.

### 4.2. I/O and Open Files Monitoring

* **Legacy:** Snapshot of /proc/[pid]/fd. Inefficient for heavy loads.
* **New:** Tracepoints on vfs_read, vfs_write, and vfs_open.
* **Gain:** Ability to see which file is generating I/O at the exact moment of writing.

## 5. Roadmap

1. Environment Validation: Simple trace execution (execve). (Completed)
2. Modularization: Separate C code (BPF) from Python logic. (Completed)
3. I/O Implementation: Create hooks for open files monitoring. (Completed)
4. Multi-Agent Fleet: Centralized Web Dashboard and Persistence. (Completed - v0.90)
