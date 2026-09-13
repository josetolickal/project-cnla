#!/usr/bin/env bash
# =============================================================================
# Automated Linux NIDS — Systemd Service Installer
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=================================================================${NC}"
echo -e "${CYAN}   Automated Linux NIDS — Systemd Daemon Installer               ${NC}"
echo -e "${CYAN}=================================================================${NC}"

# Check for root / sudo privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This installer must be run as root (or via sudo).${NC}"
   exit 1
fi

INSTALL_DIR="/opt/nids"
SERVICE_FILE="/etc/systemd/system/nids.service"
CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "[1/6] Installing necessary Linux packages (libpcap, iptables, python3-venv)..."
if command -v pacman &> /dev/null; then
    pacman -Sy --noconfirm --needed libpcap iptables python python-pip curl
elif command -v apt-get &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq libpcap-dev iptables python3 python3-pip python3-venv curl
elif command -v dnf &> /dev/null; then
    dnf install -y -q libpcap-devel iptables python3 python3-pip curl
elif command -v yum &> /dev/null; then
    yum install -y -q libpcap-devel iptables python3 python3-pip curl
fi

echo -e "[2/6] Deploying application files to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
cp -r "${CURRENT_DIR}/src" "${INSTALL_DIR}/"
cp -r "${CURRENT_DIR}/data" "${INSTALL_DIR}/"
cp -r "${CURRENT_DIR}/models" "${INSTALL_DIR}/"
cp -r "${CURRENT_DIR}/logs" "${INSTALL_DIR}/"
cp "${CURRENT_DIR}/requirements.txt" "${INSTALL_DIR}/"

echo -e "[3/6] Setting up isolated Python virtual environment..."
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip --quiet
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet

echo -e "[4/6] Registering Systemd unit file..."
cp "${CURRENT_DIR}/deploy/nids.service" "${SERVICE_FILE}"
chmod 644 "${SERVICE_FILE}"

echo -e "[5/6] Granting network sniffing capabilities to Python binary..."
setcap cap_net_raw,cap_net_admin+eip "${INSTALL_DIR}/venv/bin/python3" || true

echo -e "[6/6] Reloading systemd daemon and starting service..."
systemctl daemon-reload
systemctl enable nids.service
systemctl restart nids.service

echo -e "${GREEN}=================================================================${NC}"
echo -e "${GREEN}✅ NIDS Service Successfully Installed and Started!              ${NC}"
echo -e "${GREEN}=================================================================${NC}"
echo -e "Status check:  ${CYAN}systemctl status nids.service${NC}"
echo -e "Stream logs:   ${CYAN}journalctl -u nids.service -f${NC}"
echo -e "Dashboard URL: ${CYAN}http://<your-server-ip>:5000${NC}"
