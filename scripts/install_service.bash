#!/usr/bin/env bash
# ==============================================================================
# FILE: install_service.bash
# USAGE: sudo ./install_service.bash
# DESCRIPTION: Automates the activation of the Sys-Inspector systemd service
#              after a global pip installation.
# OPTIONS: None
# AUTHOR: Mario Luz
# VERSION: 1.0.0
# ==============================================================================

set -e

# ------------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
# ------------------------------------------------------------------------------
echo "[*] Checking privileges..."
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

SERVICE_FILE="/etc/systemd/system/sys-inspector.service"

echo "[*] Validating service file deployment..."
if [ ! -f "$SERVICE_FILE" ]; then
    echo "[ERROR] Service file not found at $SERVICE_FILE."
    echo "Ensure 'pip install sys-inspector' was executed globally first."
    exit 1
fi

# ------------------------------------------------------------------------------
# SERVICE ACTIVATION
# ------------------------------------------------------------------------------
echo "[*] Reloading systemd manager configuration..."
systemctl daemon-reload

echo "[*] Enabling sys-inspector.service to start on boot..."
systemctl enable sys-inspector.service

echo "[*] Starting sys-inspector.service..."
systemctl start sys-inspector.service

# ------------------------------------------------------------------------------
# STATUS VERIFICATION
# ------------------------------------------------------------------------------
echo "[*] Verifying service status..."
if systemctl is-active --quiet sys-inspector.service; then
    echo "[SUCCESS] sys-inspector daemon is active and running."
else
    echo "[WARNING] sys-inspector failed to start."
    echo "Check logs using: journalctl -u sys-inspector.service -e"
    exit 1
fi

echo "[*] Service installation and activation complete."
exit 0
