#!/bin/bash
# ==============================================================================
# FILE: scripts/setup_venv.sh
# USAGE: sudo ./scripts/setup_venv.sh
# DESCRIPTION: Creates a Python virtual environment in Ext4 to bypass vboxsf issues.
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 1.2.0
# ==============================================================================

set -euo pipefail

VENV_DIR="/root/venvs/sys-inspector"

# NAME: create_venv
# DESCRIPTION: Initializes the isolated environment.
create_venv() {
    echo ">>> Creating virtual environment at: ${VENV_DIR}"
    if [[ -d "${VENV_DIR}" ]]; then
        rm -rf "${VENV_DIR}"
    fi
    mkdir -p "$(dirname "${VENV_DIR}")"
    # system-site-packages is vital for bcc access
    python3 -m venv "${VENV_DIR}" --system-site-packages
}

# NAME: install_python_tools
# DESCRIPTION: Installs linters, formatters and build tools.
install_python_tools() {
    echo ">>> Installing development tools..."
    local PIP_BIN="${VENV_DIR}/bin/pip"
    "${PIP_BIN}" install --upgrade pip
    "${PIP_BIN}" install black pylint flake8 build twine
}

# MAIN EXECUTION
if [[ $EUID -ne 0 ]]; then
   echo "Error: Root privileges required." >&2
   exit 1
fi

create_venv
install_python_tools

echo "----------------------------------------------------------------"
echo "Setup Complete. Activate with: source ${VENV_DIR}/bin/activate"
echo "----------------------------------------------------------------"