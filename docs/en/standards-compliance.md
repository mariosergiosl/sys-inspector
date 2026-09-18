# Compliance with forensic standards and practices

> This document states **what the tool covers, what it covers partially, and what
> it does not cover** against current digital forensics standards and practice.
>
> **Rule for this document:** every row carries the evidence (file, mechanism or
> backlog item) backing the claim. A compliance table without evidence is worse
> than no table, because it promises what nobody checked.
>
> This is a **fleet forensics** tool, not a bench tool (decision D-024). It
> collects enough to **identify and direct**, never the mass that proves
> (decision D-032). Several "not covered" rows below are deliberate, and are
> marked as such.

## Legend

| Mark | Meaning |
|---|---|
| **Covered** | Implemented and verified by test or measurement on a real host |
| **Partial** | Partly implemented; what is missing is stated in the row |
| **Not covered** | Not implemented. If it is a decision, the decision is cited |
| **Out of scope** | Deliberately not this tool's job |

---

## 1. RFC 3227 — Guidelines for Evidence Collection and Archiving

IETF document (2002) establishing the **order of volatility**: collect first what
disappears first.

| Item | Status | Evidence |
|---|---|---|
| Registers, cache and memory first | **Out of scope** | Raw memory capture is bench work (D-032). The tool points at the suspect region and refers it onward (`src/core/acquisition.py`, `referral` field in `src/core/findings.py`) |
| Routing table, ARP cache, process table, kernel statistics | **Covered** | `src/collectors/system_inventory.py` and `src/collectors/process_tree.py`; eBPF probes in `src/probes/base_trace.c` |
| Temporary file systems | **Partial** | Detects execution from `/tmp`, `/dev/shm`, `/var/tmp`, `/run/shm` (`UNSAFE_EXEC_PREFIXES`). Does not preserve the full content of those paths |
| Disk | **Partial** | Hash and excerpt of suspect files, with a full copy when it fits the byte ceiling (`Acquirer.acquire_file`). Disk imaging is bench work |
| Remote logging and monitoring | **Covered** | Central delivery over HTTPS with a token (`src/core/outbox.py`, decision D-033) |
| Physical configuration and network topology | **Covered** | `get_net_info()` and `get_hw_info()` in `system_inventory.py` |
| Archival media | **Out of scope** | |
| **Record the clock and its drift** | **Partial** | `clock_offset` exists (decision D-019), but there is a known case of a host desynchronised after boot with the offset left unmeasured |

**Honest gap.** Order of volatility assumes continuous observation of what is
volatile. Today the probes stay attached but the perf buffer is only drained
during the capture window (item `F-241`): between windows, volatile events are
lost without notice. This is the largest distance between this tool and the
standard.

---

## 2. NIST SP 800-86 — Integrating Forensic Techniques into Incident Response

Organises the work into four phases: **collection, examination, analysis and
reporting**.

| Phase | Status | Evidence |
|---|---|---|
| Collection | **Covered** | 33 eBPF instrumentation points and 8 static collectors |
| Examination (extract the relevant from the volume) | **Covered** | `src/core/findings.py` (`Finding` model with a single severity scale and a stable fingerprint), deduplication and severity ordering |
| Analysis (correlate across sources) | **Partial** | `src/core/correlation.py` correlates static findings with runtime and builds ATT&CK chains. Correlation **across captures** of the same series is weak (items `C-156` and `F-218`) |
| Reporting | **Partial** | HTML report with Findings, Processes and ATT&CK tabs. Missing the report as an exportable **file** (item `C-149`) and the executive report (`F-061`) |
| Timeline as a product of analysis | **Partial** | A timeline screen and `src/core/events.py` exist, but events are **derived from the capture** (`events_from_capture`), so they inherit the snapshot's blindness (item `C-155`) |

---

## 3. NIST SP 800-92 — Computer Security Log Management

The core point of this standard for this tool: **the durable log is separate from
current state**. The memory of what happened does not live in the photograph.

| Item | Status | Evidence |
|---|---|---|
| Durable, append-only log | **Partial** | The capture series is digest-chained and never takes a raw `DELETE`: removal is by tombstone (`src/core/retention.py`). But the record is of **periodic state**, not of events |
| Declared and enforced retention | **Covered** | Granular retention per capture type, by tombstone |
| Protection against tampering | **Covered** | Capture encrypted with the analyst's public key (RSA-4096) and signed by the agent (RSA-3072), in `src/core/crypto.py` and `src/core/custody.py` |
| Time synchronisation across sources | **Partial** | See `clock_offset` above |
| Centralisation | **Covered** | Agent/server model with store-and-forward |

**Declared distance.** This is the standard the tool is furthest from, **by
design** rather than by neglect: it is a periodic observer, not a continuous log
collector. Item `C-155` discusses inverting that; item `C-156` discusses
extracting more from what already exists without storing more.

---

## 4. ISO/IEC 27037 — Identification, collection, acquisition and preservation

| Item | Status | Evidence |
|---|---|---|
| Device identification | **Covered** | Agent UUID, hostname, every FQDN and address (`collect_host_names`) |
| Acquisition with verifiable integrity | **Covered** | SHA-256 of the object with the **hash scope declared** (`full` or `excerpt`), so a partial hash is never read as identifying the whole object |
| Preservation and chain of custody | **Covered** | `src/core/custody.py`: digest of the cleartext content, agent signature, and a link to the previous capture |
| Continuity of the signing identity | **Covered** | The agent key lives where state lives, next to the database, not in the configuration directory, which is recreated on redeploy. Every capture carries the fingerprint of the key that signed it, and a new key is never born in silence: the record states whether it already existed, was inherited from an earlier path, or was created (`C-158`) |
| Record of who, when and how | **Partial** | The capture records the agent, the instant and the collector version. Missing the **dual time** (when it happened vs when it was observed), item `C-157` |
| Document acquisition limitations | **Covered** | When the byte budget runs out, or the object is not a regular file, the custody record states the reason instead of omitting it |
| Minimise alteration of the target | **Covered** | The agent writes no report on the inspected host, and the scenario generator plants discrete artefacts without altering the behaviour of the rest of the host (decision D-025) |

---

## 5. Industry practice used as reference

Not standards, but the state of practice. They place this tool on the map.

| Practice | How this tool compares |
|---|---|
| **osquery**: scheduled queries run in **differential** mode by default, emitting added and removed rows rather than full snapshots | This tool stores the full snapshot and computes the difference afterwards (`src/core/snapshot_diff.py`). The choice is tied to custody: the evidence is the whole signed capture, not the delta. Cost: the transition between two photographs is inferred, not observed |
| **Sysmon**: discrete event written to the system log with its own timestamp | Partly equivalent in the eBPF probes, but the event is aggregated into the process tree before becoming a record (item `C-155`) |
| **Super timeline** (log2timeline/plaso): merge many sources into a single timeline | A timeline screen exists, fed by one source (the capture itself). Merging with external host sources is open work |
| **Bitemporality** (Snodgrass; application-time periods in SQL:2011) | Not implemented. Item `C-157` |

---

## 6. What this tool deliberately does NOT do

Recorded so that absence is not read as oversight.

| Does not do | Decision that removed it |
|---|---|
| Bulk raw memory capture (LiME and similar) | D-032; removed from scope on 2026-08-19 |
| Memory image analysis (Volatility) | Bench work, the step after the report |
| Full traffic capture | D-032: saying "500 MB went to IP X" is the job; the content is bench work |
| Blocking, containment or active response | The tool is forensic, not EDR (D-024) |
| Infer which findings came from the test scenario | D-034: only the script name is mapped; the rest must be legitimate discovery, otherwise the proof is circular |

---

## References

- IETF **RFC 3227**, *Guidelines for Evidence Collection and Archiving*: https://www.rfc-editor.org/rfc/rfc3227
- NIST **SP 800-86**, *Guide to Integrating Forensic Techniques into Incident Response*: https://csrc.nist.gov/pubs/sp/800/86/final
- NIST **SP 800-92**, *Guide to Computer Security Log Management*: https://csrc.nist.gov/pubs/sp/800/92/final
- **ISO/IEC 27037:2012**, *Guidelines for identification, collection, acquisition and preservation of digital evidence*: https://www.iso.org/standard/44381.html
- **osquery**, result logging modes (differential and snapshot): https://osquery.readthedocs.io/en/stable/deployment/logging/
- **plaso / log2timeline**: https://plaso.readthedocs.io/
