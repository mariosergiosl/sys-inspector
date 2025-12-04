#!/bin/bash
# ==============================================================================
# FILE: scripts/chaos_maker.sh
# DESCRIPTION: Generates CPU load, Disk I/O, and NETWORK DEGRADATION.
#              Uses 'tc' (Traffic Control) to simulate packet loss.
#
# WARNING: Run only on a test VM! Affects the entire VM network.
#
# To test the new network functionality (Retransmission/Drops),
# we need to simulate a bad network.
# On Linux, we use tc (Traffic Control) with the netem (Network Emulator) module.
# It allows intentionally injecting latency and packet loss into the
# network interface.
# ==============================================================================

# Config
TARGET_URL="http://google.com" # Something external to test TCP
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
TEMP_FILE="/tmp/.chaos_data"
FAKE_LIB="/tmp/libfake.so"

# Cleanup Function (Trap) - Runs when you press Ctrl+C
cleanup() {
    echo ""
    echo ">>> STOPPING THE CHAOS..."
    
    # 1. Kill child processes
    pkill -P $$ 
    # Kill loose python processes created by us
    pkill -f ".unsafe_proc.py"
    
    # 2. Clear network rules (Restores normal internet)
    if [ -n "$IFACE" ]; then
        echo ">>> Restoring interface $IFACE..."
        tc qdisc del dev $IFACE root netem 2>/dev/null
    fi
    
    # 3. Clear files
    rm -f $TEMP_FILE $FAKE_LIB /tmp/.unsafe_proc.py
    
    echo ">>> System clean. Bye!"
    exit 0
}

# Captures Ctrl+C and calls cleanup
trap cleanup SIGINT SIGTERM

echo ">>> STARTING CHAOS MAKER (PID $$)"
echo ">>> Target Network Interface: $IFACE"

# ------------------------------------------------------------------------------
# 1. NETWORK DEGRADATION (Simulates bad CrowdStrike/Firewall)
# ------------------------------------------------------------------------------
echo ">>> [NET] Injecting 20% packet loss and 100ms delay..."
# Adds rule: 100ms delay, 20% packet loss, 5% corrupt
tc qdisc add dev $IFACE root netem delay 100ms loss 20% corrupt 5% 2>/dev/null || \
tc qdisc change dev $IFACE root netem delay 100ms loss 20% corrupt 5%

# Traffic Generator (Failing Download Loop)
echo ">>> [NET] Starting HTTP traffic (wget loop)..."
(while true; do 
    wget -q --timeout=2 --tries=1 -O /dev/null $TARGET_URL
    sleep 0.5
done) &

# ------------------------------------------------------------------------------
# 2. DISK STRESS (I/O)
# ------------------------------------------------------------------------------
echo ">>> [DISK] Starting disk write ($TEMP_FILE)..."
(while true; do
    # Writes 100MB, syncs, and deletes
    dd if=/dev/zero of=$TEMP_FILE bs=1M count=100 status=none
    sync
    rm $TEMP_FILE
    sleep 1
done) &

# ------------------------------------------------------------------------------
# 3. PROCESS ANOMALY (Hidden & Fileless)
# ------------------------------------------------------------------------------
echo ">>> [PROC] Creating suspicious process in /dev/shm..."
cp /bin/sleep /dev/shm/.hidden_miner
/dev/shm/.hidden_miner 1000 &

# ------------------------------------------------------------------------------
# 4. LIBRARY ANOMALY (Unsafe Lib Load) - NEW v0.26
# ------------------------------------------------------------------------------
echo ">>> [LIB] Creating process with Unsafe Lib (/tmp)..."
# Copies a harmless system lib to /tmp to simulate a payload
cp /lib64/libz.so.1 $FAKE_LIB 2>/dev/null || cp /usr/lib64/libz.so.1 $FAKE_LIB

# Creates a python script that loads this lib explicitly
cat << 'EOF' > /tmp/.unsafe_proc.py
import time
import ctypes
import os
print(f"Malicious PID (Lib): {os.getpid()}")
try:
    # Loads lib from /tmp (This should trigger [UNSAFE] alert in inspector)
    ctypes.CDLL("/tmp/libfake.so")
except Exception as e:
    print(f"Error loading lib: {e}")
while True: time.sleep(1)
EOF

python3 /tmp/.unsafe_proc.py &

echo "----------------------------------------------------------------"
echo " CHAOS RUNNING! System is now slow and unstable."
echo " Run sys-inspector in another terminal to see:"
echo " 1. [NET ERR] TCP Retransmissions (Due to 20% loss)"
echo " 2. [WARN] Hidden process in /dev/shm"
echo " 3. [UNSAFE] Library loaded from /tmp in .unsafe_proc.py"
echo " 4. High Write I/O"
echo "----------------------------------------------------------------"
echo " PRESS CTRL+C TO STOP AND CLEAN EVERYTHING"
echo "----------------------------------------------------------------"

# Keeps script running
while true; do sleep 1; done