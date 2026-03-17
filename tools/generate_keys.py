# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tools/generate_keys.py
# DESCRIPTION: Utility helper to generate RSA Key Pairs for Sys-Inspector v0.70.
#              Wraps the src.core.crypto logic.
#
# USAGE: python3 tools/generate_keys.py
# ==============================================================================

import os
import sys

# Fix imports to allow running from root directory or tools directory
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.insert(0, project_root)

try:
    from src.core.crypto import generate_key_pair
except ImportError as e:
    print(f"[ERROR] Could not import src.core.crypto: {e}")
    print("       Run this script from the project root: python3 tools/generate_keys.py")
    sys.exit(1)

def main():
    print("--- Sys-Inspector Key Generator ---")
    
    # Ensure 'conf' directory exists
    conf_dir = os.path.join(project_root, "conf")
    if not os.path.exists(conf_dir):
        os.makedirs(conf_dir)
        print(f"[*] Created directory: {conf_dir}")

    priv_path = os.path.join(conf_dir, "private_key.pem")
    pub_path = os.path.join(conf_dir, "public_key.pem")

    # Check overwrite
    if os.path.exists(priv_path) or os.path.exists(pub_path):
        resp = input(f"[!] Keys already exist in {conf_dir}. Overwrite? (y/N): ")
        if resp.lower() != 'y':
            print("[*] Aborted by user.")
            sys.exit(0)

    try:
        generate_key_pair(priv_path, pub_path)
        print("\n[SUCCESS] Keys generated successfully:")
        print(f"   Private: {priv_path} (KEEP SECRET!)")
        print(f"   Public:  {pub_path}  (Distribute to Agents)")
    except Exception as e:
        print(f"\n[ERROR] Failed to generate keys: {e}")

if __name__ == "__main__":
    main()