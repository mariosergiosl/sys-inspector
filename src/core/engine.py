# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: src/core/engine.py
# USAGE: python3 -m src.core.engine [OPTIONS]
# DESCRIPTION: Core collector engine for Sys-Inspector.
#              Handles eBPF lifecycle, event processing (Exec, I/O, Net, Drops),
#              and data aggregation.
#
#              UPDATED v0.70.04:
#              - ARCH: Implements Non-Blocking Threading (start/stop) for Manager.
#              - LOGIC: PRESERVED 100% of v0.61 event handling (E, O, N, R, W, D).
#              - COMPAT: Fixed load_probe_source() call.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 0.70.04
# ==============================================================================

import os
import sys
import time
import socket
import struct
import traceback
import threading
from bcc import BPF

# Internal Modules
from src.utils.config_loader import load_config
from src.probes.loader import load_probe_source
from src.collectors.process_tree import ProcessTree
from src.collectors.system_inventory import collect_full_inventory

class SysInspectorEngine:
    """
    The central controller for the Sys-Inspector agent.
    Manages the lifecycle of BPF probes and data collection loops.
    """

    def __init__(self, config_or_path="conf/config.yaml"):
        if isinstance(config_or_path, dict):
            self.config = config_or_path
        else:
            self.config = load_config(config_or_path)

        # Engine Components
        self.tree = ProcessTree() # Engine owns the tree
        self.bpf = None
        self.clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        
        # [v0.70] Threading Control
        self.running = False
        self.poll_thread = None
        self.lock = threading.Lock()

    def _init_bpf(self):
        """Compiles and loads the eBPF programs into the Kernel."""
        if self.bpf: return # Already initialized

        print("[*] Compiling eBPF probes...")
        # [FIX] Pass filename string explicitly
        source_code = load_probe_source("base_trace.c")
        
        try:
            self.bpf = BPF(text=source_code)
            
            # Attach Probes (Syscalls)
            self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("execve"), fn_name="syscall__execve")
            self.bpf.attach_kprobe(event=self.bpf.get_syscall_fnname("openat"), fn_name="syscall__openat")
            
            # Attach Probes (Network Connection Tracking)
            self.bpf.attach_kprobe(event="tcp_v4_connect", fn_name="kprobe__tcp_v4_connect")
            
            # Attach Probes (Disk I/O Latency)
            self.bpf.attach_kprobe(event="vfs_read", fn_name="kprobe__vfs_read")
            self.bpf.attach_kretprobe(event="vfs_read", fn_name="kretprobe__vfs_read")
            
            self.bpf.attach_kprobe(event="vfs_write", fn_name="kprobe__vfs_write")
            self.bpf.attach_kretprobe(event="vfs_write", fn_name="kretprobe__vfs_write")
            
            print("[+] eBPF Probes attached successfully.")
        except Exception as e:
            print(f"[ERROR] Failed to load eBPF: {e}")
            traceback.print_exc()
            # Don't exit here, allow Manager to handle it

    def _get_cpu_ticks(self, pid):
        try:
            with open(f"/proc/{pid}/stat", "r") as f:
                parts = f.read().split()
                return int(parts[13]) + int(parts[14])
        except: return 0

    def _update_cpu_stats(self, duration):
        """Calculates CPU usage percentage for all nodes."""
        for pid, node in self.tree.nodes.items():
            end_ticks = self._get_cpu_ticks(pid)
            if end_ticks > 0 and node.cpu_start_ticks > 0:
                delta = end_ticks - node.cpu_start_ticks
                try:
                    node.cpu_usage_pct = (delta / float(self.clk_tck)) / duration * 100.0
                except: pass

    def _check_heuristics(self, node):
        """Applies static anomaly detection rules."""
        score = 0
        if node.cmd.startswith(("/tmp", "/dev/shm")):
            score += 10
            if "UNSAFE" not in node.context_tags: node.context_tags.append("UNSAFE")
        
        if "(deleted)" in node.cmd:
            score += 5
            if "DELETED" not in node.context_tags: node.context_tags.append("DELETED")
            
        if any(x in node.cmd for x in ["nc ", "ncat", "socat", "curl ", "wget ", "nmap "]):
            score += 5
            if "NET_TOOL" not in node.context_tags: node.context_tags.append("NET_TOOL")
            
        node.anomaly_score += score

    def _handle_bpf_event(self, cpu, data, size):
        """Callback for eBPF perf buffer events (User Space processing)."""
        event = self.bpf["events"].event(data)
        pid = event.pid
        
        # Pass loginuid to process tree
        node = self.tree.add_or_update(
            pid, 
            event.ppid, 
            event.comm.decode('utf-8', 'replace'), 
            event.uid, 
            event.prio,
            event.loginuid
        )
        
        if node is None: return

        node.rss = max(node.rss, event.mem_peak_rss)

        ev_type = event.type_id.decode('utf-8', 'replace')
        filename = event.filename.decode('utf-8', 'replace')

        if ev_type == 'E': # Execve
            node.cmd = filename
            node.is_new = True
            node.update_static_info()
            self._check_heuristics(node)
            
        elif ev_type == 'O': # OpenAt
            if not filename.startswith(("/proc", "/sys", "/dev", "/run")):
                node.open_files.add(filename)
                
        elif ev_type == 'N': # Network Connect
            try:
                dst = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
                port = socket.ntohs(event.dport)
                conn_str = f"IPv4 -> {dst}:{port}"
                if conn_str not in node.connections: # Avoid duplicates
                     node.connections.append(conn_str) # v0.70 uses List for JSON compat
            except: pass
            
        elif ev_type == 'R': # Read
            node.read_bytes_delta += event.io_bytes
            if event.io_latency_ns > 0:
                node.io_latency_tot += event.io_latency_ns
                node.io_ops_count += 1
            
        elif ev_type == 'W': # Write
            node.write_bytes_delta += event.io_bytes
            if event.io_latency_ns > 0:
                node.io_latency_tot += event.io_latency_ns
                node.io_ops_count += 1

        elif ev_type == 'D': # Packet Drop
            try:
                src = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr))
                dst = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))
                proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
                proto_name = proto_map.get(event.proto, f"IP({event.proto})")
                sport = socket.ntohs(event.sport)
                dport = socket.ntohs(event.dport)
                
                drop_msg = f"DROP: {src}:{sport} -> {dst}:{dport} ({proto_name})"
                
                if hasattr(node, 'network_drops_details'):
                    node.network_drops_details.append(drop_msg)
                
                node.tcp_drops += 1
                node.anomaly_score += 5
                if "NET ERR" not in node.context_tags: node.context_tags.append("NET ERR")
                
            except Exception: pass

    def _collect_network_counters(self):
        """Reads BPF Maps for high-volume metrics."""
        if not self.bpf: return
        
        def get_map_val(bpf_map):
            for k, v in bpf_map.items():
                pid = k.value
                val = v.value
                node = self.tree.get(pid)
                if node: yield node, val

        for node, val in get_map_val(self.bpf["net_bytes_sent"]): node.net_tx_bytes = val
        for node, val in get_map_val(self.bpf["net_bytes_recv"]): node.net_rx_bytes = val
        for node, val in get_map_val(self.bpf["tcp_retrans_map"]):
            node.tcp_retrans = val
            if val > 0: 
                node.anomaly_score += 2
                if "NET ERR" not in node.context_tags: node.context_tags.append("NET ERR")
        for node, val in get_map_val(self.bpf["tcp_drop_map"]):
            node.tcp_drops = max(node.tcp_drops, val)
            if val > 0:
                node.anomaly_score += 5
                if "NET ERR" not in node.context_tags: node.context_tags.append("NET ERR")

    # --------------------------------------------------------------------------
    # [v0.70] NEW THREADING MODEL (Non-Blocking)
    # --------------------------------------------------------------------------

    def _poll_loop(self):
        """Background thread loop to drain perf buffers."""
        print("[DEBUG] BPF Polling Thread Started.")
        try:
            # Open Perf Buffers (Only once)
            self.bpf["events"].open_perf_buffer(self._handle_bpf_event)
            
            while self.running:
                # Poll with short timeout to check 'self.running'
                self.bpf.perf_buffer_poll(timeout=200)
                
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"[ERROR] BPF Poll Loop Error: {e}")
        finally:
            print("[DEBUG] BPF Polling Thread Stopped.")

    def start(self):
        """Starts the engine in background mode."""
        with self.lock:
            if self.running: return
            
            # 1. Init Static Data
            self.tree.scan_proc_fs()
            for pid, node in self.tree.nodes.items():
                node.cpu_start_ticks = self._get_cpu_ticks(pid)
            
            # 2. Load Probes
            self._init_bpf()
            
            # 3. Start Thread
            print("[*] Starting BPF Engine (Threaded)...")
            self.running = True
            self.poll_thread = threading.Thread(target=self._poll_loop)
            self.poll_thread.daemon = True
            self.poll_thread.start()

    def stop(self):
        """Stops the engine and aggregates stats."""
        with self.lock:
            if not self.running: return

            print("[*] Stopping BPF Engine...")
            self.running = False
            
            if self.poll_thread:
                self.poll_thread.join(timeout=2.0)
            
            # Finalize
            # We assume duration=1 just to trigger the math; 
            # Manager might pass actual duration if we changed signature, 
            # but usually manager calls this at end of interval.
            self._update_cpu_stats(duration=30) # Default/Approx
            self._collect_network_counters()
            self.tree.aggregate_stats()

    # --- Legacy Wrappers (Kept for compatibility) ---
    def run_snapshot(self, duration=30, output_file=None):
        """Blocking wrapper for old behavior."""
        self.start()
        time.sleep(duration)
        self.stop()
        
        # Legacy Reporting logic removed (moved to SnapshotController)

