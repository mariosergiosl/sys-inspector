# The report and the Manager screen

> How to operate the tool's two screens, and why each control exists.
>
> This document covers what version 1.1.0 changed in the interface. It does not
> repeat what each finding means (that is in the report itself, as tooltips) nor
> the architecture (see `docs/en/`).

## 1. Manager screen (the hosts)

The first screen: one row per agent.

### 1.1 Host identity

**HOSTNAME / UUID**, **IP** and **FQDN** identify the machine. The UUID is stable
and survives a change of name or address, so it is what ties one host's captures
together over time.

From 1.1.0, **IP and FQDN show every value**, not just the primary one. The first
address is the one used on the route to the server, which is what the server
actually sees; the others appear below it, smaller. The same applies to names:
`/etc/hosts` aliases and reverse DNS come in as extra lines.

**Why it matters:** the same host shows up under different names in different
systems (inventory, ticket, firewall). Showing one name hides half of what ties
the machine to the report.

### 1.2 Severity

One cell with the four counters side by side: Critical, High, Medium and Low from
the **latest capture**. Zero stays visible, only dimmed. A counter that
disappears leaves the operator unable to tell zero from a screen that stopped
reporting.

### 1.3 The "Agent: presence and rhythm" block

Four columns under one label, because they answer one question:

| Column | Answers |
|---|---|
| **Last Seen** | when the last capture arrived, local time and UTC |
| **Next / cadence** | when the next one is expected, from the agent's own cycle |
| **Uptime** | how long the host has been up, and how long the agent has collected |
| **Agent status** | whether the agent spoke to the server within the expected interval, and how long ago |

The status is the **agent's**, not the host's. A host can be up with the agent
mute, and that is precisely the interesting case: so the column says "agent
active" or "agent silent", not just a colour.

### 1.4 Action column

Five icons: open the report, previous captures, request a capture now, test
scenario (lab only) and restart the agent. Beside them, that agent's command
queue count, clickable.

Below the icons, the state of the last command, in stages.

### 1.5 Resizable columns

Every column has a **draggable divider** on the right edge of its title. The mark
highlights on hover and the cursor changes to the resize cursor.

### 1.6 Calendars: Timeline and Captures / Collections

Two buttons in the navigation bar open month calendars, and the same two buttons
exist inside every host (in the report bar), already filtered to it. Above the
month, a selector switches between all hosts and each host.

Both use the same colours: the day border takes the colour of the highest
severity, and the strip shows the composition by severity (C critical, A high,
M medium, B low). Info is left out: it is inventory and appears in every capture.

**Timeline** ("Linha do tempo") opens on the calendar of **findings and
discoveries**. Each day shows the distinct findings (the same finding on the same
host counts once per day), how many are new (the first time that host shows that
finding) and how many other events happened. Clicking a day opens the list of
that day's events, the same list as before, with the sequence reading on top; a
reading repeated on every capture appears once, with "seen N times". The window
buttons (15min, 1h, 6h, 24h) still lead to the recent list.

**Captures / Collections** ("Capturas / Coletas") counts captures per day.
Capturing is the agent obtaining data from the host; collecting is the server
receiving what was captured, and the gap between the two moments is the
collection delay. Day marks: Δ for captures whose composition changed against the
previous capture of the same host, ≠ for captures whose total departs from the
host's usual value (the most common one), and ⚠ for gaps, intervals with no
capture much longer than usual. In the all-hosts view, the day says how many hosts
have something to look at.

Clicking a day shows a 24-hour strip with the number of captures per hour, in the
same colours; clicking an hour narrows the list. In the list, identical
consecutive captures collapse into one line ("N identical captures", first to last
time), which opens on demand; a capture that changed, or that follows a gap,
always starts a new group. Each capture links to its report and to its event
list.

## 2. Report (per agent)

### 2.1 Top bar

**Manager** button (back to the host list), the stamp of when the capture was taken
and how old it is, navigation between captures, the download button, and the
same commands as the previous screen for that agent.

**Navigation between captures.** Four controls: previous capture (older), next
(more recent), jump to the latest, and the current position as "capture N of M".
The count is chronological, oldest to newest, which is how a timeline reads; the
database returns them the other way round.

An arrow with nowhere to go stays **visible and dimmed** rather than
disappearing. The edge of the collection is information: an arrow that vanishes
changes the width of the bar and leaves the reader unsure whether they reached
the end or the screen broke. With a single capture there are no arrows, but the
count is still stated, because "capture 1 of 1" is also an answer.

**Capture type.** Next to the count, a badge says what kind of capture is on
screen: "completa" (the agent's normal cycle), "cenario de teste" (test
scenario, highlighted) or "ociosa" (idle-mode heartbeat). Each arrow's tooltip
says what kind of capture it leads to, so you can decide before clicking. A
capture is a test scenario capture when the agent saw `chaos_maker.sh` running
during it, whether the scenario was started from the button or by hand: its
findings were planted on purpose. A capture stored before the type existed shows
"tipo nao registrado" (type not recorded) and is not presumed complete.

**Downloading the report.** The floppy icon delivers the report as a **file**,
named `sys-inspector_<host>_<YYYYMMDD-HHMMSS>.html`. The timestamp in the name is
the **collection** time, not the download time: whoever receives the exhibit
needs to know which moment it describes without opening it.

Three properties matter:

- **It is always the complete version.** An exhibit whose content changed
  depending on who clicked could not be attached to any case.
- **It is the same build as the screen.** File and page come from one code path,
  so the attached exhibit is the exhibit that was read.
- **It carries no navigation bar.** That bar points at a server the reader of the
  case file cannot reach, and a dead button in a forensic document is worse than
  no button.

The download is also on the **History** screen, in its own column, so any
capture can be downloaded without opening it first.

The report lives on the **server**, not on the agent. This is not convenience:
an agent writing to the inspected host would contaminate the target, the agent
encrypts with the public key and **cannot read** what it collected, and the agent
has no web server, only outbound calls, so a download would mean opening a port
on the most privileged process in the fleet.

### 2.2 Show / hide inventory

The three top blocks (System, Storage Topology, Network Topology) collapse with
the **SHOW INVENTORY / HIDE INVENTORY** control.

**Why it exists:** those blocks take half the usable height and barely change
during an analysis, while the process tree, which is where the work happens, was
squeezed. The state is remembered by the browser, so someone working in the tree
does not have to collapse it on every report they open.

### 2.3 Tabs

**Findings** (what is wrong), **Processes** (who executes) and **ATT&CK** (which
technique). The "HOW TO READ" strip suggests that order.

A finding that concerns a process carries a **View process** button, which jumps
to it in the tree and highlights it. This happens in two cases: when the finding
**names the PID** (writable-and-executable memory, hidden process, thread count
divergence) and when the **reported path** is being executed by some captured
process.

If the process is no longer in the capture, the screen **says so** and suggests
looking in the agent's history, instead of simply not reacting. Absence is an
answer.

A finding that is not about a process (a kernel module, a file, a fleet-wide
pattern) still carries **no** button, and that absence informs as well: there is
no process to go to.

### 2.4 Process tree

- **Its own scrolling**: the tree scrolls inside its own box, in both axes, and
  the column header travels with it. The page itself does not scroll.
- **Resizable columns**: the same draggable divider as the Manager screen.
- **COMMAND TREE wraps to three lines**, so the argument at the end of a command
  line is not hidden behind an ellipsis. That is often where the path the binary
  was launched from lives.
- **ALERTS uses two lines** when there are many signals.

### 2.5 Process detail panel

Clicking a row opens the detail. **Every block always appears**, even with no
data:

| Block | When empty, it says |
|---|---|
| Executable Provenance | "no binary on disk (kernel process, or unreadable path)" |
| Process Ancestry | "no ancestor captured in this window" |
| Probe Signals | each field with an em dash, or "not captured" |
| Security Forensics | "no security reason fired for this process" |

**Why the tool insists on this (decision D-020):** an omitted field makes the
reader infer, and the two possible inferences lead to opposite places: "the host
did not have it" versus "the tool did not look". The second invalidates any
conclusion drawn from the absence. So every field appears, in one of three
states:

- **a value**: collection looked and found it;
- **an em dash** (`—`): looked and found nothing. The absence here is an
  observation, not a failure;
- **"not captured"**: this capture did not produce the field, which usually
  happens with a report generated by an agent older than the version that started
  collecting it. Nothing can be concluded from that absence.

### 2.6 Filters and badges

**The network failure badge counts the subtree.** The number next to ❌ sums TCP
retransmits and dropped packets **for this process and every descendant of it**,
including branches that have not been expanded. That is why a parent's badge can
be larger than the sum of the children visible on screen.

The detail panel shows both readings side by side, "Deste processo" (this
process) and "Com os descendentes" (with descendants), and states the total the
badge displays. Without those labels, a parent with badge 7 and detail 0 looked
like a counting error, when it was simply the parent having no drops of its own.

Each detected signal becomes a badge with its own icon in the tree, and the
FILTERS bar has one button per signal. **Every signal has a unique icon** and a
test enforces it: two signals drawn the same way are one signal to whoever reads
the screen, and a forensic report cannot have two different facts looking
identical.

**A filter with no results answers.** A filter matching no process writes on
screen how many processes were examined and that the absence is the answer,
instead of just emptying the tree. From the screen, "no results" and "broken"
used to be indistinguishable, and it was that ambiguity that got a correct
filter reported as a defect.

The notice sits in the document flow and stays until the filter changes, because
it describes the **current state** of the screen and not a passing event.

## 3. Known interface limitations

Recorded so their absence is not read as oversight.

**Resolved in 1.2.0.** The four limitations listed here up to 1.1.0 are gone: the
report has a download again, the **View process** button now appears on every
finding that concerns a process, navigation between captures moved into the
report bar, and a filter with no results now gives feedback. The record stays
here because it told the truth about the previous version, and an erased history
of limitations is no use to anyone reading an older report.

**Still open:**

- the comparison between two captures shows processes that **appeared** and not
  those that **disappeared**, which are often the more interesting ones;
- the **capture-level custody record** is not shown in the report. The report
  shows custody per finding, what was preserved of that object, but the record
  for the capture itself, with its digest, its link to the previous capture, the
  signature and the fingerprint of the signing key, lives only in the database.
  Whoever reads the exhibit does not see it.
