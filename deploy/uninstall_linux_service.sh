#!/usr/bin/env bash
# =============================================================================
# Automated Linux NIDS — Systemd Service Uninstaller
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=================================================================${NC}"
echo -e "${CYAN}   Automated Linux NIDS — Systemd Daemon Uninstaller             ${NC}"
echo -e "${CYAN}=================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This uninstaller must be run as root (or via sudo).${NC}"
   exit 1
fi

SERVICE_FILE="/etc/systemd/system/nids.service"
INSTALL_DIR="/opt/nids"

echo -e "[1/3] Stopping and disabling nids.service..."
systemctl stop nids.service || true
systemctl disable nids.service || true

echo -e "[2/3] Removing systemd unit definition..."
if [ -f "${SERVICE_FILE}" ]; then
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    systemctl reset-failed
fi

echo -e "[3/3] Removing deployed files at ${INSTALL_DIR} (optional)..."
read -p "Do you want to delete ${INSTALL_DIR}? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "${INSTALL_DIR}"
    echo -e "Removed ${INSTALL_DIR}."
fi

echo -e "${GREEN}=================================================================${NC}"
echo -e "${GREEN}✅ NIDS Service has been uninstalled.${NC}"
echo -e "${GREEN}=================================================================${NC}"
