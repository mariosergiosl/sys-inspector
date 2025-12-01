#!/bin/bash
# --------------------------------------------------------------------------------------
# FILE: install_deps.sh
# USAGE: sudo ./install_deps.sh
# DESCRIPTION: Installs system-level dependencies for eBPF (BCC) development on
#              openSUSE Leap 15.6. Includes kernel headers and compilers.
# OPTIONS: None
# AUTHOR: Assistant
# VERSION: 1.1
# --------------------------------------------------------------------------------------

set -euo pipefail

# --------------------------------------------------------------------------------------
# NAME: log_info
# DESCRIPTION: Prints informational messages to stdout.
# PARAMETER 1: Message string
# --------------------------------------------------------------------------------------
log_info() {
    echo ">>> $1"
}

# --------------------------------------------------------------------------------------
# NAME: install_packages
# DESCRIPTION: Refreshes repositories and installs required packages using zypper.
# PARAMETER: None
# --------------------------------------------------------------------------------------
install_packages() {
    log_info "Refreshing package repositories..."
    if ! zypper refresh; then
        echo "Error: Failed to refresh repositories." >&2
        return 1
    fi

    log_info "Installing eBPF/BCC toolchain and Python bindings..."
    # kernel-default-devel: Required for BPF compilation (must match running kernel)
    # clang/llvm: Compiler backend used by BCC
    # python3-bcc: System-level Python bindings
    # make/gcc: Standard build tools
    local PACKAGES=(
        "git"
        "clang"
        "llvm"
        "make"
        "gcc"
        "python3"
        "python3-pip"
        "python3-devel"
        "python3-bcc"
        "bcc-tools"
        "kernel-devel"
        "kernel-default-devel"
    )

    if ! zypper install --no-confirm "${PACKAGES[@]}"; then
        echo "Error: Failed to install packages." >&2
        return 1
    fi
}

# --------------------------------------------------------------------------------------
# NAME: verify_kernel_headers
# DESCRIPTION: Checks if installed headers match the running kernel version.
# PARAMETER: None
# --------------------------------------------------------------------------------------
verify_kernel_headers() {
    local CURRENT_KERNEL
    local INSTALLED_HEADERS
    
    CURRENT_KERNEL=$(uname -r)
    # Extract version-release from rpm query
    INSTALLED_HEADERS=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}\n' \
        kernel-default-devel | head -n 1)

    log_info "Checking Kernel compatibility..."
    echo "    Running Kernel: ${CURRENT_KERNEL}"
    # Simple check: The running kernel string typically contains the version-release
    if [[ "${CURRENT_KERNEL}" != *"${INSTALLED_HEADERS}"* ]]; then
        echo "WARNING: Kernel headers version ($INSTALLED_HEADERS) does not match"
        echo "         running kernel ($CURRENT_KERNEL)."
        echo "         Please REBOOT your system before continuing."
    else
        echo "    Kernel headers match running kernel. OK."
    fi
}

# --------------------------------------------------------------------------------------
# Execution Logic
# --------------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root." >&2
   exit 1
fi

install_packages
verify_kernel_headers

log_info "System dependencies installation complete."