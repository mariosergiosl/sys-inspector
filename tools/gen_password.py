# -*- coding: utf-8 -*-
# ==============================================================================
# FILE: tools/gen_password.py
# DESCRIPTION: Generate a password hash for the Sys-Inspector dashboard auth.
#              Prints a werkzeug PBKDF2 hash to paste into config.yaml under
#              network.auth.password_hash. Uses pbkdf2:sha256 for compatibility
#              with the older werkzeug shipped on SLES/openSUSE.
#
# USAGE: python3 tools/gen_password.py
# ==============================================================================

import sys
import getpass

try:
    from werkzeug.security import generate_password_hash
except ImportError as e:
    print(f"[ERROR] werkzeug not available: {e}")
    print("        Install Flask/werkzeug first (pip install flask).")
    sys.exit(1)


def main():
    """Prompt for a password twice and print its PBKDF2 hash for config.yaml."""
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: python3 tools/gen_password.py")
        print("Prompts for a password and prints a hash for config.yaml (network.auth).")
        sys.exit(0)

    pwd = getpass.getpass("New dashboard password: ")
    if not pwd:
        print("[ERROR] Empty password. Aborted.")
        sys.exit(1)

    confirm = getpass.getpass("Confirm password: ")
    if pwd != confirm:
        print("[ERROR] Passwords do not match. Aborted.")
        sys.exit(1)

    # pbkdf2:sha256 keeps the hash verifiable on older werkzeug (SLES/openSUSE).
    hashed = generate_password_hash(pwd, method="pbkdf2:sha256")
    print("\n[OK] Add these lines under network.auth in config.yaml:")
    print("    enabled: true")
    print(f'    password_hash: "{hashed}"')


if __name__ == "__main__":
    main()
