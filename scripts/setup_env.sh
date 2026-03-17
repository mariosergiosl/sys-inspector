#!/bin/bash
# ==============================================================================
# FILE: scripts/setup_env.sh
# USAGE: ./scripts/setup_env.sh [--install]
# DESCRIPTION: Environment validator for Sys-Inspector v0.80.
#              Checks for OS binaries, Python libraries (bcc, yaml, crypto, flask).
#              Can optionally install missing dependencies via zypper.
#
# OPTIONS:
#   --install    Attempts to install missing packages using zypper (root req).
#   --help       Displays this help message.
#
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 1.1.0 (Added Flask Support)
# ==============================================================================

# ------------------------------------------------------------------------------
# GLOBAL CONFIGURATION
# ------------------------------------------------------------------------------

# ANSI Colors (US-ASCII compatible)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Required binaries and their respective packages on openSUSE
# Format: "binary:package"
DEPENDENCIES=(
    "python3:python3"
    "ip:iproute2"
    "tc:iproute2"
    "lsblk:util-linux"
    "chattr:e2fsprogs"
    "gcc:gcc"
    "wget:wget"
    "iptables:iptables"
)

INSTALL_MODE=false

# ------------------------------------------------------------------------------
# HELPER FUNCTIONS
# ------------------------------------------------------------------------------

# NAME: log_msg
# DESCRIPTION: Standardized logging output.
# PARAMETER: $1 = Level (INFO, WARN, ERR, TYPE), $2 = Message
log_msg() {
    local level="$1"
    local msg="$2"
    local color="$NC"

    case "$level" in
        INFO) color="$GREEN" ;;
        WARN) color="$YELLOW" ;;
        ERR)  color="$RED" ;;
        TYPE) color="$CYAN" ;;
    esac

    echo -e "${color}[$level]${NC} $msg"
}

# NAME: check_root
# DESCRIPTION: Verifies if the user has root privileges.
# PARAMETER: None
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        return 1
    fi
    return 0
}

# NAME: check_python_bcc
# DESCRIPTION: Validates if the bcc library is importable in Python 3.
# PARAMETER: None
check_python_bcc() {
    python3 -c "from bcc import BPF" > /dev/null 2>&1
    return $?
}

# NAME: check_python_yaml
# DESCRIPTION: Verifies if the PyYAML library is installed and importable.
# PARAMETERS: None
check_python_yaml() {
    python3 -c "import yaml" >/dev/null 2>&1
}

# NAME: check_python_crypto
# DESCRIPTION: Verifies if the Python Cryptography library is installed.
# PARAMETERS: None
check_python_crypto() {
    python3 -c "import cryptography" >/dev/null 2>&1
}

# NAME: check_python_flask
# DESCRIPTION: Verifies if the Python Flask library is installed.
# PARAMETERS: None
check_python_flask() {
    python3 -c "import flask" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------
# MAIN LOGIC - PRE-FLIGHT CHECKS
# ------------------------------------------------------------------------------

if [[ "$1" == "--help" ]]; then
    grep "^# USAGE:" "$0" -A 10 | sed 's/^#//'
    exit 0
fi

if [[ "$1" == "--install" ]]; then
    INSTALL_MODE=true
fi

log_msg "TYPE" "Starting Sys-Inspector Environment Check..."

# ------------------------------------------------------------------------------
# 1. Binary Checks
# ------------------------------------------------------------------------------
MISSING_PKGS=()
for dep in "${DEPENDENCIES[@]}"; do
    bin="${dep%%:*}"
    pkg="${dep##*:}"
    
    if ! command -v "$bin" > /dev/null 2>&1; then
        log_msg "WARN" "Binary '$bin' NOT found (Expected package: $pkg)"
        MISSING_PKGS+=("$pkg")
    else
        log_msg "INFO" "Binary '$bin' is present."
    fi
done

# ------------------------------------------------------------------------------
# 2. Python BCC Check
# ------------------------------------------------------------------------------
if ! check_python_bcc; then
    log_msg "WARN" "Python library 'bcc' is NOT installed or functional."
    MISSING_PKGS+=("python3-bcc")
else
    log_msg "INFO" "Python BCC library is functional."
fi

# ------------------------------------------------------------------------------
# 3. Python PyYAML Check
# ------------------------------------------------------------------------------
if ! check_python_yaml; then
    log_msg "WARN" "Python library 'PyYAML' is NOT installed."
    MISSING_PKGS+=("python3-PyYAML")
else
    log_msg "INFO" "Python PyYAML library is functional."
fi

# ------------------------------------------------------------------------------
# 4. Python Cryptography Check
# ------------------------------------------------------------------------------
if ! check_python_crypto; then
    log_msg "WARN" "Python library 'cryptography' is NOT installed."
    MISSING_PKGS+=("python3-cryptography")
else
    log_msg "INFO" "Python Cryptography library is functional."
fi

# ------------------------------------------------------------------------------
# 5. Python Flask Check (Required for Web Controller)
# ------------------------------------------------------------------------------
if ! check_python_flask; then
    log_msg "WARN" "Python library 'flask' is NOT installed."
    MISSING_PKGS+=("python3-Flask")
else
    log_msg "INFO" "Python Flask library is functional."
fi

# ------------------------------------------------------------------------------
# 6. Decision & Installation
# ------------------------------------------------------------------------------
if [[ ${#MISSING_PKGS[@]} -eq 0 ]]; then
    log_msg "INFO" "All dependencies are satisfied. Environment is READY."
    exit 0
fi

if [[ "$INSTALL_MODE" == "false" ]]; then
    log_msg "ERR" "Missing dependencies found. Run with --install as root to fix."
    exit 1
fi

# Attempting installation
if ! check_root; then
    log_msg "ERR" "Root privileges are required to install packages."
    exit 1
fi

log_msg "TYPE" "Attempting to install missing packages: ${MISSING_PKGS[*]}"
zypper --non-interactive install "${MISSING_PKGS[@]}"
if [[ $? -eq 0 ]]; then
    log_msg "INFO" "Installation successful. Re-run script to verify."
else
    log_msg "ERR" "Installation failed. Check zypper logs."
    exit 1
fi

exit 0