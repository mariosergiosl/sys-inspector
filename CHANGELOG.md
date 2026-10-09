# Changelog

All notable changes to the **Sys-Inspector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Four defects, all found **on the bench** while bringing the lab up for 1.3.0,
none by reading code. Three of them were inside the fix for the signing key
that disappeared on redeploy, which already had tests, review and a green CI.

### Fixed

- **Key inheritance failed precisely on the well-configured agent.** The path
  to inherit the old key from was derived from `private_key_path`, which is the
  **analyst's** key. A correct agent does not have it: it receives only the
  public half, because it must encrypt and must not be able to decrypt. On
  those hosts the path became `"."`, relative to the process working directory,
  the inheritance found nothing and the agent generated a new key. The defect
  the fix exists to prevent would have survived inside the fix itself, and only
  on the best-configured agents. It now looks in three places, ending at the
  public key, which every agent has by definition.

- **Declaring half the key pair regenerated the other half over it.** With only
  `agent_private_key_path` set, the private half came from the declared
  directory and the public half from the database directory. The pair ended up
  split, the code concluded it was incomplete, and generated a new identity
  **over the one the operator had declared**. Declaring either half now fixes
  the directory for both.

- **The correct agent configuration was refused at startup**, with
  `Failed to provision cryptographic keys: 'private_key_path'`. The
  provisioning routine already handled this properly, only generating a pair
  when the **public** key is missing, but `main.py` read the private path with
  a direct dictionary access and raised before reaching it. In practice every
  agent was forced to declare a path for the key it must not have. The
  analyst's private key is now optional at startup, and the decryption utility
  explains the absence instead of raising.

### Documentation

- **`verify_tls` is documented in `conf/config.yaml`.** Against a self-signed
  certificate the delivery simply failed, the agent logged `Delivery failed`
  with no reason, and the only explanation lived in the source. A setting that
  decides whether evidence reaches the server cannot live only in the code. It
  ships on, and the comment states what is given up by turning it off: proof of
  **who** is on the other end, not secrecy.

### Known gap this exposed

- **A failed delivery does not say why it failed.** A rejected certificate, a
  closed port, a wrong token and a server that is down all produce the same log
  line. That is the message separating "the lab is misconfigured" from
  "evidence is being lost", and today it separates nothing.

## [1.3.0] - 2026-09-18

Chain of custody that survives a redeploy, an agent that can be idle, and
two screen numbers that finally explain themselves.

### Fixed

- **The signing identity now survives a redeploy, and a change is declared**
  (`C-158`). The key that signs captures was resolved from the analyst key's
  directory, that is, from **configuration**, and configuration gets recreated.
  Observed during the lab cleanup on 2026-08-20: a plain change of deployment
  directory silently moved one agent's public key from `13e2eb55...` to
  `dcab6e89...`.

  The asymmetry was the defect. The UUID lives next to the database and
  survived; the key did not. Anyone verifying the chain would see the **same
  agent signing with two different keys**, with nothing explaining the change,
  which in a forensic exhibit is exactly the signal the opposing side looks for,
  and we were producing it ourselves.

  - The identity is **state**, and now lives where state lives: next to the
    database, alongside `.agent_id`. An explicitly configured path still wins.
  - The key is **inherited** from the previous location when the new one is
    empty. Without this, the fix itself would have changed the key across the
    whole fleet at once. It is a copy, not a move, so an older process still
    pointing at the old path keeps signing with the same key.
  - Every custody record now carries `agent_key_fingerprint` (SHA-256 of the
    SubjectPublicKeyInfo) and `agent_key_event` (`existing`, `migrated` or
    `created`). The fingerprint is present on **every** capture, not only when
    it changes: a field that shows up only on the bad day is a field nobody
    knows how to read. A new key is legitimate; being born silently is not.

  The new fields are inside the signed area: a tamperable custody field would be
  worse than no field.

- **The network badge arithmetic now adds up on screen** (`F-243`).
  Investigated and closed: it was **not** a counting error. The badge always
  summed the **subtree** (the process plus every descendant), while the detail
  panel always showed the process's **own** counters. Both numbers were right in
  their own scope, and they read as a contradiction because the scope was
  written nowhere.

  The fix writes the scope rather than changing the count: the panel shows both
  readings, labelled, including the total the badge displays; the badge tooltip
  breaks the number into drops plus retransmits and separates the process's own
  from its descendants'; and the badge legend, which said "network failures of
  the process", now states that it covers descendants too.

### Added

- **Idle mode for the agent** (`C-105`), off by default. Until now the daemon
  was not idle at all: it ran the heavy capture (eBPF, inventory, findings,
  encryption) on **every** cycle and only then talked to the server. Across a
  real estate that means paying the cost of a forensic capture all the time on
  machines where nothing happened.

  With `daemon.idle_mode` on, the cycle only talks to the server, and the heavy
  capture happens for a **reason**: the first cycle after start, the cadence in
  `daemon.capture_every`, or a command from the analyst. A cycle that does not
  capture writes **why**, with the time remaining: an idle agent and a stuck
  agent must not look alike to whoever reads the log at three in the morning.

  A commanded capture also resets the cadence, so an on-demand capture is not
  followed seconds later by a scheduled one.

  Turning it on changes what an agent does in the field, which is a decision for
  whoever operates it, not a side effect of an upgrade.

  **Stated limit, so the gain is not overstated:** this does not make the cycle
  cheap on its own. The check-in still forks `chronyc` and probes the host every
  round; that is item `C-106`, still open. What is solved here is the heavy
  capture no longer being mandatory every cycle. The cost reduction itself has
  **not** been measured on real hardware yet.

### Known gap opened by this change

- The **capture-level** custody record is still not shown in the report
  (`C-160`). The report shows custody per finding. The fields above are
  therefore visible to whoever queries the database, and not to whoever reads
  the exhibit, which is precisely who needs them.

## [1.2.0] - 2026-09-18

The report stops being only a screen and becomes an **exhibit**: it can be
downloaded, navigated across captures, and it answers when it has nothing to
show.

### Added

- **The report as a file again** (`C-149`). New route
  `GET /download/<uuid>?capture=<id>`, with `Content-Disposition`, reachable from
  the report bar and from a column of its own on the History screen. The file is
  named `sys-inspector_<host>_<YYYYMMDD-HHMMSS>.html`, carrying the **collection**
  time rather than the download time.

  Removing the execution modes in 1.1.0 had silently taken this away: obtaining
  the report came to depend on the browser's "save as", which produces an
  artefact with no origin stamp. In a forensic tool the report is the exhibit
  attached to the case.

  It lives on the server, not on the agent: an agent writing to the inspected
  host contaminates the target, the agent encrypts with the public key and cannot
  read what it collected, and the agent has no web server, so a download would
  mean opening a port on the most privileged process in the fleet.

- **Navigation between captures in the report bar** (`F-234`). Previous, next,
  jump to latest, and "capture N of M". The count is chronological, oldest to
  newest. An arrow with nowhere to go stays visible and dimmed instead of
  disappearing, because the edge of the collection is information. A single
  capture still states "capture 1 of 1".

- **A filter with no results now answers** (`F-244`). It states how many
  processes were examined and that the absence is the answer. Previously the
  tree simply emptied, and from the screen "no results" and "broken" were
  indistinguishable; that ambiguity had a correct filter reported as a defect.

### Changed

- **The pivot to the process now appears on every finding that concerns one**
  (`F-242`). It used to come only from the correlation, which fills in when the
  *reported path* is being executed; findings that name a PID directly
  (writable-and-executable memory, hidden process, thread divergence) were left
  without the shortcut, which were precisely the most specific ones. Measured
  before: 5 pivots across 33 cards.

  A finding that is not about a process still carries no button, and that
  absence keeps informing.

- **The screen and the file are built by one code path.** Two builds would be
  the silent-copy defect this project has already paid for, and here the cost
  would be higher: the attached exhibit would stop being the exhibit that was
  read.

### Documentation

- `docs/internal/architecture.md` and `docs/internal/diagrams.md` brought up to
  the current code (`C-148`): the real module map, the 33 eBPF probes and the two
  remaining controllers. Probes and score bits are now cited by **name** instead
  of by `file:line`, because every line citation from the previous revision had
  already expired.
- `docs/internal/cobertura-ameacas.md`: detection surface revised against 1.1.0,
  from 30 to 33 probes and from 9 to 25 `anomaly_score` bits, plus the rootkit
  collector and directed acquisition.
- `ROADMAP.md` records the 1.1.0 delivery and corrects the RBAC note: HTTPS and
  authentication are no longer optional.
- `F-216` closed without work: searched across the whole repository and the whole
  git history, there are no UML PNGs and there never were. The project's diagrams
  have always been Mermaid, which is text.

## [1.1.0] - 2026-08-20

Minor release with **breaking configuration changes**. The tool now has a single
execution path (agent plus server), HTTPS is the only transport, and the report
interface was reworked from what the process tree actually needs.

### Migration required

- **`mode: snapshot`, `mode: live` and `mode: local-live` no longer exist.** Use
  `mode: daemon` for the collector and `mode: server` for the dashboard; for a
  single machine, install both on the same host. A one-off capture that used to
  be `--mode snapshot --interval 20` is now `--mode daemon --once`.
- **`tls_enabled` and `use_tls` were REMOVED from the configuration**, not turned
  on by default. A configuration file carrying them keeps working (they are
  ignored), but plaintext is no longer reachable: the server refuses to start if
  TLS cannot be enabled, and the agent always speaks HTTPS.

### Added

- **Directed acquisition.** A suspect file or memory region is hashed, excerpted
  and, when it fits the declared byte budget, copied - with the hash SCOPE
  recorded, so a partial hash is never read as identifying the whole object.
- **Referral to bench analysis.** Every finding can state which analysis
  concludes what it cannot, why, and on which object. The tool collects enough to
  identify and direct, never the mass that proves (D-032), and that is only
  honest when it also says who finishes the job.
- **Rootkit hunting**, crossing the three module lists and the kernel taint, plus
  judgement of every library listed in `/etc/ld.so.preload` by package provenance.
- **SNI, `mount` and `pivot_root` probes**, completing "who with" where DNS does
  not reach (cache, fixed IP, DoH) and the container-escape step that follows a
  namespace change.
- **`--once`** on the agent: one capture cycle and exit, so a first run still
  fits on one line.
- **Report interface**: the inventory block collapses to give the tree the
  screen, columns are resizable by dragging the divider in the header, and the
  tree scrolls in both axes with the header staying in place.
- **Standards compliance document** (`docs/pt-BR/conformidade-normas.md` and
  `docs/en/standards-compliance.md`), stating what the tool covers of RFC 3227,
  NIST SP 800-86, NIST SP 800-92 and ISO/IEC 27037 - and what it does not.

### Fixed

- **The chaos generator did not run at all.** `chaos_maker.sh` carried CRLF line
  endings; bash reads a carriage return as part of the token and the script died
  on its first brace, so every scenario round measured an empty host. Worse, the
  daemon reported "capturing anyway" instead of failing, so a capture with
  nothing in it looked like the tool failing to detect. The command now fails
  loudly, with the reason and the tail of the log.
- **Two signals shared one icon.** `UNSAFE` and `KEXEC_LOAD` were both drawn as a
  radioactive symbol, which made a correct filter look broken.
- **Detail blocks that vanished.** Process Ancestry, Executable Provenance,
  Security Forensics and the probe-signal fields disappeared when they had no
  value. They now always render, in one of three states: a value, "looked and
  found nothing", or "not collected by this capture".
- **A hostile `/etc/ld.so.preload` could hang the agent.** Acquisition opened any
  path it was given; a named pipe planted there blocks forever. Non-regular files
  are refused, and opening is non-blocking.
- **Server protections.** HTTP Basic auth and the identifier allowlist, plus the
  legacy `/upload` route which was the only ingestion path with no token check.

### Changed

- **One execution path.** Three parallel implementations of the act of collecting
  became one; the two defective callers that silently skipped memory forensics
  stopped existing rather than being repaired.
- **Fleet screen**: severities in a single cell, every FQDN and address shown,
  the agent's status named as such with its last contact, and Last Seen, Next,
  Uptime and Status grouped under one label because they answer one question.
- **Flake8 runs on the whole repository**, not only `src/`.

### Known gaps

Recorded so their absence is not read as oversight: the report exists as a served
page and not yet as a downloadable file; the finding-to-process shortcut appears
only where the denounced path is currently executing; a filter that matches
nothing gives no feedback; and the user manual describing the new controls is
still pending.

## [1.0.1] - 2026-08-17

Patch release: forensic file-ownership now works on dpkg-based systems, plus repository and CI housekeeping.

### Fixed

- **File provenance on Debian/Ubuntu.** Package-owner resolution fell back to `dpkg` only when `rpm` was absent, but a host can carry the `rpm` binary with an empty database. Ownership now queries `rpm` first and falls back to `dpkg`, resilient to usrmerge and alternatives symlinks, so `/bin/sh` and friends resolve correctly. Content verification (`rpm -V`) runs only when `rpm` truly owns the file, instead of reading empty output as "intact" and masking tampering on a dpkg host.

### Changed

- **Continuous Integration is green again.** The Code Quality workflow had been failing on a package-ownership test since early August; with it fixed, the accumulated flake8/pylint backlog was cleared (dead imports, a lambda assignment, a wrapped comment) and style-only checks (E121, E226, W504, C0209) are ignored with a documented rationale.

## [1.0.0] - 2026-08-13

First stable release. The tool now runs as a distributed agent/server fleet with a normalized evidence model, a forensic report that reads as an investigation, and a single source of version truth.

### Added

- **Answer contract per finding.** Every finding now declares a **confidence** level (confirmed / probable / heuristic), so the report never presents a heuristic as a fact, and a **custody** level (none / metadata / hash / full) that states what was actually preserved of the artifact. The confidence badge sits next to the severity and modulates how to read it.
- **Manager command progress as a stepper.** A command fired at an agent (capture, scenario, restart) shows its real state as a three-stop stepper (enqueued -> on the agent -> done/failed) with the current stop highlighted, a live timer and the full result in the tooltip, so the automatic capture cadence is never confused with a command in flight.
- **Report didactics and cross-tab coupling.** A "how to read" strip (Findings -> Processes -> ATT&CK), a per-finding severity legend with the operator action, tooltips explaining each evidence field, and clickable pivots in both directions between a finding and its ATT&CK technique.
- **Distributed fleet.** Pull-model agents forward encrypted captures to a central server with a store-and-forward outbox, a prioritized ingestion queue, an audited command queue, per-agent capability reporting, and HTTPS with an auto self-signed certificate.
- **Runtime and anti-forensic detection.** Hidden processes (`/proc` vs kernel), thread-count divergence, writable-and-executable memory, on-disk binary replacement, untrusted loaded libraries, and immutable files in writable directories (ATT&CK T1222.002).
- **Cross-host time.** The clock offset of each agent is measured (via chrony) and travels with the capture, a prerequisite for a comparable timeline across machines.

### Changed

- **Version is a single source of truth** (`src/version.py`). Every surface that shows or stamps a version reads it: the Live web UI, the live and snapshot reports, the custody stamp, the RPM spec, `setup.py` and the scenario/install scripts. A guard test prevents the drift from returning.
- **Severity is read from a single named-signal decoder** (`risk.py`): the anomaly score is a bit field of distinct signals, not a magnitude, which fixes a gravity inversion where a defunct process outranked a deleted binary executing from `/dev/shm`.
- **Packaging split by role**: base, agent, server and scenarios, so an inspected host never installs the web server it does not run.

### Fixed

- The chaos test scenario no longer contaminates the host it measures: `/etc/ld.so.preload` points at a system-path library and a single dedicated process carries the runtime signal.
- Persistence events are emitted on the timeline, so the temporal correlation rules have real material to fire on.
- Report rendering escapes every host-controlled value; the pivot from a finding opens the originating capture, not the most recent one.

## [0.91.0] - 2026-08-06

### Changed - License

- **Relicensed from GPL-3.0-only to AGPL-3.0-only.** Sys-Inspector can be operated as a network service (multi-agent server and web dashboard), and the AGPL extends the copyleft to that case: anyone who runs a modified version and offers it to users over a network must make the corresponding source of their modified version available to those users. Under GPL alone, a modified version could be offered as a hosted service without ever sharing the changes. Relicensed by the sole copyright holder; the trademark policy in TRADEMARK.md is unaffected.

### Added

- **Finding entity**: a normalized unit of evidence shared by every collector, with a single severity scale (Info to Critical), an explicit `source` so the analyst can tell a runtime observation from a static check, the MITRE ATT&CK technique, the raw evidence attached, and a stable fingerprint for cross-capture deduplication.
- **Persistence enumeration**: systemd units, cron/at entries, `rc.local` and profile scripts, `/etc/ld.so.preload`, kernel module autoload, udev rules, PAM stacks and per-user `authorized_keys`. Baseline items are reported as informational; severity is raised only on real indicators (execution from user-writable paths, world-writable files, hidden names, recent modification).
- Findings are collected by the snapshot, daemon and live modes and travel inside the encrypted payload.
- First automated test suite (pytest), wired into the CI workflow alongside flake8 and pylint.

### Changed

- All execution modes now share a single storage layer, a single data shape and a single behavior: captures are always encrypted, including in live mode.
- Agent identity is stable and shared across modes.

### Fixed

- Snapshot hot columns (CPU, memory, PID count, alert score) were always stored as zero, which defeated timeline and alert sorting; `insert_snapshot` also returned `True` instead of the row id.
- The alert badge rendered a raw score number that repeated on every ancestor of the worst process; it now shows a severity level.
- Host-controlled data (command lines, file and library paths, usernames, cgroup paths) was interpolated into the HTML report without escaping, so a quote in a command line could break out of a tooltip attribute and leak text into the report. Evidence text is still shown faithfully, but is now inert.
- Live and server modes were calling a storage API that did not exist and could not render captures; both work again.
- Packaging issues reported by rpmlint (script shebangs, line endings, summary, SUSE rc link).

## [Unreleased]

### Documentation

- Documented the new opt-in dashboard authentication and HTTPS in the README and in a dedicated `docs/en/dashboard_security.md`.
- Updated the README feature list to v0.90.16 and corrected the project structure (`scripts/` vs `tools/`).
- Adopted the i18n layout: English `README.md` with a language selector, Portuguese `README.pt-BR.md`, and narrative docs split into `docs/en/` and `docs/pt-BR/`.

## [0.90.16] - 2026-07-12

### Security

- **Dashboard Authentication (opt-in):** Added optional HTTP Basic Auth to the Fleet/Inspector dashboard, working over both HTTP and HTTPS. Disabled by default (`network.auth.enabled: false`) so existing deployments are unaffected. Credentials are stored as a PBKDF2 hash in `config.yaml`; generate it with `tools/gen_password.py` (run it on the host that serves the dashboard). When enabled without a hash, the server fails closed and rejects all requests.
- **Dashboard HTTPS (opt-in):** Added optional TLS for the dashboard (`network.tls_enabled: false` by default). When enabled, if the configured certificate/key are missing, a self-signed pair is generated automatically on first start (`src/core/tls.py`), so HTTPS works with zero manual PKI. Operator-provided certificates in the configured paths are honored instead. If TLS setup fails, the server falls back to HTTP rather than crashing.
- **Dashboard XSS Prevention:** Agent-supplied fields (`hostname`, `ip_address`, `os_info`) and the URL agent id are now validated against an allowlist and escaped before being rendered in the Fleet and Inspector views. A compromised agent can no longer inject script into the analyst's browser.
- **Setup Script Hardening:** `ensure_environment()` now resolves `setup_env.sh` only from fixed trusted locations (the packaged `tools/` directory and `/usr/bin/setup_env.sh`) instead of searching `$PATH`. This prevents execution of a malicious `setup_env.sh` when the agent runs as root.

### Changed

- **Toolbar active-state indicator:** The report toolbar now visually marks which sort (Process By) and which filter (Filters) are currently applied, using a reddish outline on the active badge. Sort and filter are independent, so both can be highlighted at once. The indicator uses `outline` (not `border`) to avoid any layout shift of neighboring icons. Clearing the filter keeps the active sort highlighted.
- **Symmetric toolbar:** The Process By sort buttons are now rendered as bare icons, matching the Filters block (the previous gray button boxes were an incidental style difference, not a semantic distinction).

### Fixed

- **Packaging Conflict:** Removed the divergent `[project]` table from `pyproject.toml` (stale version and an invalid `inspector:main` entry point) that could break the `sys-inspector` console script depending on the build backend. `setup.py` is now the single source of truth for package metadata.
- **Log Level:** The application now honors `general.log_level` from `config.yaml`. Previously the level was hardcoded to `INFO` and the configured value was ignored.
- **Leaf-node expander:** Leaf rows in the process tree emitted a literal `toggleBranch({node.pid})` because the string was not an f-string; the expander now uses the real PID.
- **Duplicate EDR-WAIT badge:** The frozen-process (EDR-WAIT) badge was emitted twice (once by the tag loop, once by a dedicated block); the redundant block was removed so it renders once.
- **WARN score tooltip:** The anomaly-score badge showed a placeholder ("Check Details"); it now lists the actual score reasons, noting when a higher score was bubbled up from a child process.
- **False-positive NET ERR on kernel threads:** TCP drop/retransmit events fired in softirq context were attributed to the running kernel thread (`ksoftirqd`, `kthreadd`) instead of the socket owner, flagging kernel threads with NET ERR. Kernel threads (PID 2 and its subtree) are now excluded from NET ERR badges, scores and tree aggregation; the socket-owning processes remain flagged correctly.

## [0.90.00] - 2026-03-16

### Added

- **Multi-Agent Architecture:** Transitioned from a single-run script to a continuous Daemon architecture.
- **Fleet View Dashboard:** Centralized Web UI (`/`) to monitor multiple connected agents and their online/offline status via heartbeat.
- **Time Machine (Forensic History):** Integrated SQLite storage with retention policies to allow browsing historical snapshots via the Web UI.
- **Live Pause Control:** Added the ability to pause the live incoming data stream for detailed forensic analysis of a specific moment.
- **Flask Web Server:** Embedded lightweight web server to serve the dashboards dynamically.

### Changed

- **Entry Point:** Deprecated `inspector.py` in favor of a unified `main.py` orchestrator supporting multiple modes (`snapshot`, `live`, `daemon`, `server`, `local-live`).
- **Database Engine:** Enabled SQLite WAL (Write-Ahead Logging) mode by default to support high-concurrency between the collector daemon and the web server.

### Fixed

- Resolved `[Errno 24] Too many open files` caused by unclosed database connections during continuous polling.

## [0.30.9] - 2025-12-05

### Added

- **Recursive Badge Propagation:** Alerts (`WARN`, `UNSAFE`, `NET ERR`, `SSH`) now "bubble up" from child processes to their parents in the HTML tree view. This allows quick identification of problematic branches even if the root process seems healthy.
- **Hierarchical Storage Topology:** The storage inventory now correctly maps the dependency tree: `Physical Disk -> Partition -> LVM/FS -> Mount Point`.
- **Network Topology:** Added automatic detection of Default Gateway and DNS Servers in the inventory header.
- **Logo Support:** The report generator now looks for `/etc/sys-inspector/logo.png`. If found, it converts the image to Base64 and embeds it in the report header.
- **Chaos Maker (English):** Fully translated `chaos_maker.sh` to English and improved cleanup routines. Added specific simulation for "Unsafe Library Loading".

### Changed

- **Default Arguments:** `inspector.py` can now be run without arguments.
  - Default Duration: `20` seconds.
  - Default Output: `/var/log/sys-inspector/sys-inspector_v{VER}_{HOST}_{DATE}.html`.
- **HTML Report Layout:**
  - Added "Storage Topology" print button.
  - Added `[UNSAFE]` filter button to the controls bar.
  - Improved readability of Disk I/O details.
- **Code Quality:**
  - Complete refactoring of `inspector.py` and `report_generator.py` to achieve **10/10 Pylint** score.
  - Resolved global variable warnings and reduced function complexity (Cyclomatic Complexity).
  - Strictly formatted with `flake8`.

### Fixed

- Fixed layout breakage when a disk had multiple partitions.
- Fixed `flake8` warnings regarding whitespace around operators and multiple statements on one line.
- Fixed `pylint` warnings about global variable usage in BPF callback handlers.

## [0.20.0] - 2025-11-28

### Added

- **Core eBPF Architecture:** Replaced legacy `psutil` polling with event-driven Kernel probes (kprobes/kretprobes) for `execve`, `openat`, `vfs_read`, `vfs_write`, and `tcp_v4_connect`.
- **Enterprise HTML Reporting:**
  - Interactive "Accordion" style process tree.
  - Sticky Header for easy navigation in large reports.
  - Visual Badges for CPU Load, Priority (Nice), and Anomaly Scores.
  - Embedded CSS/JS (Single-file portability).
- **Deep Forensics:**
  - Real-time MD5 hash calculation of executed binaries.
  - Context capture: SSH Origin IP, Sudo User, and Multiplexer (Tmux) detection.
  - Anomaly Detection: Heuristics for execution from `/tmp`, `/dev/shm`, deleted binaries, and suspicious environment variables (`LD_PRELOAD`).
- **Storage Topology Mapping:**
  - Correlation of open files to physical devices.
  - Explicit **HCTL (Host:Channel:Target:LUN)** display for SAN/Mainframe zoning analysis.
  - Persistent path resolution (`/dev/disk/by-path`).
- **Accurate Metrics:**
  - Distinction between Virtual Memory (VSZ) and Physical Memory (RSS).
  - CPU Usage % calculation based on tick deltas during capture window.
  - Lifetime I/O stats vs Window I/O stats.

### Changed

- **Project Structure:** Modularized into `src/sys_inspector` package layout (PEP 8 compliant).
- **Quality Assurance:** Strict adherence to Pylint (10/10) and Flake8 standards.
- **License:** Project released under GPL-3.0-only.

### Fixed

- Solved "Feedback Loop" where the inspector traced its own I/O operations.
- Fixed library enumeration to capture dynamic libs at process spawn time.
- Fixed visual layout issues in HTML header preventing overlap of values.

---

## [0.1.0] - 2025-11-28

### Initial

- Proof of Concept (PoC) for eBPF integration.
- Basic `execve` snooping.
