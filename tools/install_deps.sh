#!/bin/bash
# ==============================================================================
# FILE: scripts/install_deps.sh
# USAGE: sudo ./scripts/install_deps.sh
# DESCRIPTION: Installs system-level dependencies for eBPF (BCC) and Web UI.
#              Targets openSUSE Leap 15.6 / SLES 15/16.
# AUTHOR: Mario Luz (Sys-Inspector Project)
# VERSION: 1.2.0 (Integrated Web & US-ASCII)
# ==============================================================================

set -euo pipefail

# NAME: log_info
# DESCRIPTION: Standardized informational output.
log_info() {
    echo ">>> $1"
}

# NAME: install_packages
# DESCRIPTION: Refreshes repos and installs required system packages.
install_packages() {
    log_info "Refreshing package repositories..."
    zypper refresh

    log_info "Installing toolchain and core libraries..."
    # Standard build tools + eBPF/BCC + Flask/Crypto/YAML for the new architecture
    local PACKAGES=(
        "git" "clang" "llvm" "make" "gcc" "python3" "python3-pip" "python3-devel"
        "python3-bcc" "bcc-tools" "kernel-devel" "kernel-default-devel"
        "python3-Flask" "python3-cryptography" "python3-PyYAML"
    )

    zypper install --no-confirm "${PACKAGES[@]}"
}

# NAME: verify_kernel_headers
# DESCRIPTION: Ensures running kernel matches installed headers.
verify_kernel_headers() {
    local CURRENT_KERNEL=$(uname -r)
    local INSTALLED_HEADERS=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}\n' kernel-default-devel | head -n 1)

    log_info "Checking Kernel compatibility..."
    echo "    Running Kernel: ${CURRENT_KERNEL}"
    
    if [[ "${CURRENT_KERNEL}" != *"${INSTALLED_HEADERS}"* ]]; then
        echo "WARNING: Kernel headers mismatch ($INSTALLED_HEADERS vs $CURRENT_KERNEL)."
        echo "         Please REBOOT before running Sys-Inspector."
    else
        echo "    Kernel headers match running kernel. OK."
    fi
}

# MAIN EXECUTION
if [[ $EUID -ne 0 ]]; then
   echo "Error: Root privileges required." >&2
   exit 1
fi

install_packages
verify_kernel_headers
log_info "System dependencies installation complete."