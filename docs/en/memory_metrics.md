# Understanding Memory Metrics in Linux (VSZ vs RSS)

When analyzing processes like the libuv-worker (VSCode Server) or Java, it is common to observe huge discrepancies between allocated memory and used memory. Sys-Inspector differentiates both:

## 1. VSZ (Virtual Memory Size)

* Definition: It is the total virtual memory that the process can access. It includes:
  * Program code.
  * Shared libraries (libc, etc).
  * Allocated but unused memory (preventive mallocs).
  * Memory-mapped files.
* VSCode Scenario: VSCode reserves a huge virtual addressing area (e.g., 32GB) for future operations, but does not consume this from physical RAM.
* Interpretation: A high VSZ does NOT necessarily indicate a memory leak or a problem.

## 2. Peak RSS (Resident Set Size - Peak)

* Definition: It is the maximum amount of physical RAM that the process occupied during its lifetime.
* Composition: Only the memory pages that are currently in the RAM sticks.
* Importance: This is the real value that impacts the server capacity. If RSS reaches the machine limit, swapping or OOM Kill occurs.

In Sys-Inspector:
The VSZ column shows the promise of use.
The PK_RSS column shows the real physical consumption.
