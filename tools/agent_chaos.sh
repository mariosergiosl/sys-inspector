#!/bin/bash
# ======================================================================================
# FILE: tools/agent_chaos.sh
# USAGE: agent_chaos.sh [duration_seconds]   (default 300)
# DESCRIPTION: Lab scenario planted on an agent host so the running daemon captures
#              it and forwards to the server. Plants persistence artifacts that
#              exercise the STATIC detectors, and launches chaos_maker so the
#              RUNTIME detectors have something to see.
#
#              WARNING: run only on a disposable test VM. It writes persistence
#              artifacts under /etc and launches noise processes.
#
# DESIGN NOTE (why this file changed):
#   The previous version wrote /etc/ld.so.preload pointing at a library under
#   /tmp. /etc/ld.so.preload is GLOBAL by definition: every process that starts
#   afterwards maps that library. Because the library was under /tmp, the runtime
#   unsafe-library detector then tagged EVERY real process on the host as
#   "untrusted library location". The host's own processes were being marked by a
#   side effect of the test, not by anything wrong with them. A forensic tool must
#   not modify the picture it is measuring.
#
#   The fix keeps BOTH detections working, isolated:
#     1. Static ld.so.preload detection (ATT&CK T1574.006): the preload file is
#        still written, but points at a library in a NORMAL system path
#        (/usr/local/lib). The persistence detector fires on the FILE regardless
#        of the library path, so coverage is unchanged; and because the library
#        is not under /tmp, no real process is flagged by the runtime detector.
#     2. Runtime unsafe-library detection: exactly ONE dedicated process loads a
#        library from a strange path (/dev/shm) through its OWN environment, so
#        only that process, the one this script plants, carries the runtime
#        signal. Nothing else on the host is touched.
#
# REQUIREMENTS: bash, coreutils. gcc is optional (used to build the stub library;
#               without it the ld.so.preload step is skipped and reported).
# BUGS: ---
# NOTES: US-ASCII only. Compatible with the lab SLES/Leap hosts.
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 2.0
# CREATED: 2026-08-07
# REVISION: 2026-08-07 isolate the unsafe-library signal to a single process
# ======================================================================================

set -u

# --------------------------------------------------------------------------------------
# CONSTANTS
# --------------------------------------------------------------------------------------
VERSION="2.0"
MARK="/tmp/chaos_persist"                     # strange path: only OUR process maps it
SYS_LIB_DIR="/usr/local/lib"                  # normal path: preload here does NOT taint
SYS_LIB="${SYS_LIB_DIR}/libhealthcheck.so"    # innocuous name, mirrors real-world evasion
SHM_LIB="/dev/shm/libinject.so"               # strange path for the single tainted proc
PRELOAD_FILE="/etc/ld.so.preload"
SVC_FILE="/etc/systemd/system/evil-backdoor.service"
CRON_EVIL="/etc/cron.d/evil-cron"
CRON_HIDDEN="/etc/cron.d/.hidden-cron"
MINER="/dev/shm/miner.sh"
CHAOS_HOME="/opt/sys-inspector"

#=== FUNCTION ==========================================================================
# NAME:         usage
# DESCRIPTION:  Print usage and exit.
#=======================================================================================
usage() {
    echo "Usage: agent_chaos.sh [duration_seconds]   (default 300)"
    echo "  Plants an authorized lab scenario for the sys-inspector daemon to capture."
    echo "  Run ONLY on a disposable test VM."
    echo "  --help     show this message"
    echo "  --version  show version"
}

#=== FUNCTION ==========================================================================
# NAME:         cleanup_previous
# DESCRIPTION:  Remove any artifact left by an earlier run, so the scenario starts
#               from a known state and the host is left clean when nothing runs.
#=======================================================================================
cleanup_previous() {
    echo "--- Cleaning previous artifacts ---"
    ps -eo pid,args | grep "[c]haos_maker" | awk '{print $1}' | xargs -r kill 2>/dev/null
    pkill -f "${MINER}" 2>/dev/null
    pkill -f "${MARK}/tainted.sh" 2>/dev/null
    rm -rf "${MARK}"
    rm -f "${PRELOAD_FILE}" "${SYS_LIB}" "${SHM_LIB}" "${MINER}"
    rm -f "${CRON_EVIL}" "${CRON_HIDDEN}" "${SVC_FILE}"
}

#=== FUNCTION ==========================================================================
# NAME:         plant_static_persistence
# DESCRIPTION:  Write the inert persistence artifacts that exercise the STATIC
#               detectors (systemd unit, cron entries). These are files under /etc;
#               they do not change the runtime behaviour of other processes.
#=======================================================================================
plant_static_persistence() {
    echo "--- Planting static persistence artifacts ---"
    mkdir -p "${MARK}"

    printf '#!/bin/bash\nsleep 3600\n' > "${MARK}/implant.sh"
    chmod +x "${MARK}/implant.sh"

    cat > "${SVC_FILE}" <<EOF
[Unit]
Description=System Health Helper
[Service]
ExecStart=${MARK}/implant.sh
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    echo "*/5 * * * * root ${MINER}" > "${CRON_EVIL}"
    echo '* * * * * root /usr/bin/id' > "${CRON_HIDDEN}"
}

#=== FUNCTION ==========================================================================
# NAME:         plant_preload
# DESCRIPTION:  Configure /etc/ld.so.preload with a stub library in a NORMAL system
#               path. This exercises the ld.so.preload persistence detector
#               (T1574.006) WITHOUT tainting every process: the runtime detector only
#               flags libraries under /tmp, /dev/shm or /var/tmp, and this one is not
#               there. If gcc is absent the step is skipped and reported.
#=======================================================================================
plant_preload() {
    if ! command -v gcc >/dev/null 2>&1; then
        echo "--- gcc absent: skipping ld.so.preload artifact (reported) ---"
        return 0
    fi
    echo "--- Configuring ld.so.preload with a system-path library ---"
    mkdir -p "${SYS_LIB_DIR}"
    echo 'static void __attribute__((constructor)) init(void) { }' > "${MARK}/stub.c"
    if gcc -shared -fPIC -o "${SYS_LIB}" "${MARK}/stub.c" 2>/dev/null; then
        echo "${SYS_LIB}" > "${PRELOAD_FILE}"
    else
        echo "--- gcc failed to build stub: ld.so.preload not written ---"
    fi
}

#=== FUNCTION ==========================================================================
# NAME:         launch_tainted_process
# DESCRIPTION:  Launch exactly ONE process that maps a library from a strange path
#               (/dev/shm), through its OWN environment. This is what exercises the
#               runtime unsafe-library detector, and it is the ONLY process on the
#               host that carries the signal. The cron entry above references this
#               same running binary, so the correlation finding -> process is
#               deterministic (persistence is ACTIVE).
#=======================================================================================
launch_tainted_process() {
    echo "--- Launching the single tainted process ---"
    printf '#!/bin/bash\nwhile true; do sleep 5; done\n' > "${MINER}"
    chmod +x "${MINER}"

    if command -v gcc >/dev/null 2>&1; then
        echo 'static void __attribute__((constructor)) init(void) { }' > "${MARK}/inject.c"
        gcc -shared -fPIC -o "${SHM_LIB}" "${MARK}/inject.c" 2>/dev/null || true
    fi

    # Only this process gets LD_PRELOAD; nothing else on the host does.
    if [ -f "${SHM_LIB}" ]; then
        LD_PRELOAD="${SHM_LIB}" setsid "${MINER}" >/dev/null 2>&1 </dev/null &
    else
        setsid "${MINER}" >/dev/null 2>&1 </dev/null &
    fi
}

#=== FUNCTION ==========================================================================
# NAME:         find_chaos_maker
# DESCRIPTION:  Locate chaos_maker.sh wherever the install put it. The path is not
#               the same across hosts: a source deploy has it under
#               /opt/sys-inspector/tools, an RPM install exposes it as
#               /usr/bin/chaos_maker.sh, and the lab may have dropped it in /tmp.
#               Hardcoding one path made the scenario silently skip the runtime
#               chaos on the hosts that use another, which is exactly the kind of
#               "it ran" that turns out to be false.
# RETURNS:      prints the path on stdout, empty if not found.
#=======================================================================================
find_chaos_maker() {
    local c
    for c in /usr/bin/chaos_maker.sh \
             "${CHAOS_HOME}/tools/chaos_maker.sh" \
             /tmp/chaos_maker.sh \
             /usr/lib/python3.6/site-packages/tools/chaos_maker.sh; do
        [ -f "${c}" ] && { echo "${c}"; return 0; }
    done
    echo ""
}

#=== FUNCTION ==========================================================================
# NAME:         run_chaos
# DESCRIPTION:  Launch chaos_maker for the requested duration, so the runtime
#               detectors have live activity to capture. Writes a start marker to
#               the log so a later check can tell "launched and finished" apart
#               from "never launched".
# PARAMETER 1:  duration in seconds
#=======================================================================================
run_chaos() {
    local dur="$1"
    local maker
    maker="$(find_chaos_maker)"
    if [ -z "${maker}" ]; then
        echo "--- chaos_maker.sh not found on this host: runtime chaos NOT launched ---"
        echo "CHAOS_MAKER_NOT_FOUND $(date -u +%Y-%m-%dT%H:%M:%SZ)" > /tmp/chaos.log
        return 0
    fi
    echo "--- Launching chaos_maker from ${maker} for ${dur}s ---"
    {
        echo "CHAOS_MAKER_START $(date -u +%Y-%m-%dT%H:%M:%SZ) using ${maker} dur=${dur}"
    } > /tmp/chaos.log
    setsid nohup bash "${maker}" --all --duration "${dur}" \
        >>/tmp/chaos.log 2>&1 </dev/null &
}

# --------------------------------------------------------------------------------------
# ARGUMENT PARSING
# --------------------------------------------------------------------------------------
case "${1:-}" in
    --help)    usage; exit 0 ;;
    --version) echo "agent_chaos.sh ${VERSION}"; exit 0 ;;
esac

DUR="${1:-300}"

# --------------------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------------------
cleanup_previous
plant_static_persistence
plant_preload
launch_tainted_process
run_chaos "${DUR}"

echo "$(hostname): persistence planted + chaos for ${DUR}s"
echo "========================================"
echo " --- script concluido. --- "
echo "========================================"
