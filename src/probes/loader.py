# -*- coding: utf-8 -*-
# ===============================================================================
# FILE: src/probes/loader.py
# DESCRIPTION: Utility to load and prepare eBPF C source code.
#              Handles runtime variable replacement (like PID filtering).
#
# OPTIONS:
#
# PARAMETERS:
#
# AUTHOR: Mario Luz (Refactoring Sys-Inspector Project)
# CHANGELOG:
# VERSION: 0.50.56
# ==============================================================================

import os
import sys


def load_probe_source(probe_name="base_trace.c"):
    """
    Reads the C source file from the probes directory and prepares it for BCC.

    It performs necessary runtime replacements, such as injecting the current
    PID into the FILTER_PID macro to prevent the agent from tracing itself.

    Args:
        probe_name (str): Filename of the C source (default: base_trace.c).

    Returns:
        str: The complete, compiled-ready C source code.

    Raises:
        FileNotFoundError: If the .c file cannot be found.
    """
    # Determine absolute path relative to this module
    current_dir = os.path.dirname(os.path.abspath(__file__))
    source_path = os.path.join(current_dir, probe_name)

    if not os.path.exists(source_path):
        raise FileNotFoundError(f"eBPF source file not found: {source_path}")

    try:
        with open(source_path, 'r', encoding='utf-8') as f:
            source_code = f.read()

        # Runtime Injection: Ignore Own PID
        # We replace the C macro definition directly in the source string.
        current_pid = os.getpid()
        source_code = source_code.replace(
            "#define FILTER_PID 00000",
            f"#define FILTER_PID {current_pid}"
        )

        return source_code

    except Exception as e:
        print(f"[ERROR] Failed to load probe {probe_name}: {e}")
        sys.exit(1)
