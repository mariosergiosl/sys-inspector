#!/bin/bash
# --------------------------------------------------------------------------------------
# FILE: setup_venv.sh
# USAGE: sudo ./setup_venv.sh
# DESCRIPTION: Creates a Python virtual environment in a local Ext4 directory to
#              avoid VirtualBox shared folder symlink issues.
# OPTIONS: None
# AUTHOR: Assistant
# VERSION: 1.0
# --------------------------------------------------------------------------------------

set -euo pipefail

# Constants
VENV_DIR="/root/venvs/sys-inspector"

# --------------------------------------------------------------------------------------
# NAME: create_venv
# DESCRIPTION: Creates the virtual environment with access to system site-packages.
# PARAMETER: None
# --------------------------------------------------------------------------------------
create_venv() {
    echo ">>> Creating virtual environment at: ${VENV_DIR}"

    # Remove old venv if exists to ensure clean state
    if [[ -d "${VENV_DIR}" ]]; then
        echo "    Removing existing venv..."
        rm -rf "${VENV_DIR}"
    fi

    mkdir -p "$(dirname "${VENV_DIR}")"

    # --system-site-packages is CRITICAL for BCC to work
    if ! python3 -m venv "${VENV_DIR}" --system-site-packages; then
        echo "Error: Failed to create virtual environment." >&2
        return 1
    fi
}

# --------------------------------------------------------------------------------------
# NAME: install_python_tools
# DESCRIPTION: Upgrades pip and installs linting/formatting tools.
# PARAMETER: None
# --------------------------------------------------------------------------------------
install_python_tools() {
    echo ">>> Installing Python development tools..."
    
    local PIP_BIN="${VENV_DIR}/bin/pip"

    if ! "${PIP_BIN}" install --upgrade pip; then
        echo "Error: Failed to upgrade pip." >&2
        return 1
    fi

    # Black and Pylint are required by project standards
    if ! "${PIP_BIN}" install black pylint flake8; then
        echo "Error: Failed to install linters." >&2
        return 1
    fi
}

# --------------------------------------------------------------------------------------
# Execution Logic
# --------------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (to write to /root/venvs)." >&2
   exit 1
fi

create_venv
install_python_tools

echo "----------------------------------------------------------------"
echo "Setup Complete."
echo ""
echo "To activate the environment, run:"
echo "source ${VENV_DIR}/bin/activate"
echo "----------------------------------------------------------------"