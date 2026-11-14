#!/usr/bin/env bash
# ==============================================================================
#  INDRA INFINITY SECURITY ∞ — INSTALLER SCRIPT FOR TERMUX & ANDROID
#  "NOTHING GETS THROUGH INFINITY."
#  Creador: Takizawa | Para: Indra
# ==============================================================================

set -e

BLUE='\033[0;34m'
CYAN='\033[0;36m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo " ██╗███╗   ██╗██████╗ ██████╗  █████╗ "
echo " ██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗"
echo " ██║██╔██╗ ██║██║  ██║██████╔╝███████║"
echo " ██║██║╚██╗██║██║  ██║██╔══██╗██╔══██║"
echo " ██║██║ ╚████║██████╔╝██║  ██║██║  ██║"
echo " ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"
echo "        INFINITY SECURITY ∞           "
echo -e "${NC}"
echo -e "${PURPLE}[+] Initializing Indra Infinity Security Environment Setup (by Takizawa)...${NC}"

# 1. Detection of Termux / Android Environment
IS_TERMUX=false
if [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
    IS_TERMUX=true
    echo -e "${GREEN}[+] Termux environment detected (Version: ${TERMUX_VERSION:-Unknown})${NC}"
else
    echo -e "${YELLOW}[!] Not running inside Termux; standard Linux/Unix POSIX mode activated.${NC}"
fi

# 2. Package Manager Updates & Prerequisite Packages
if [ "$IS_TERMUX" = true ]; then
    echo -e "${CYAN}[*] Updating Termux packages and installing dependencies...${NC}"
    pkg update -y || apt-get update -y
    pkg install -y python python-pip git curl wget openssl clang libffi make binutils || true
fi

# 3. Check Python 3
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo -e "${RED}[-] Python 3 is not installed. Please install Python 3.10+ first.${NC}"
    exit 1
fi

PY_BIN=$(command -v python3 || command -v python)
PY_VER=$($PY_BIN --version 2>&1)
echo -e "${GREEN}[+] Using $PY_VER at $PY_BIN${NC}"

# 4. Create Directory Hierarchy
echo -e "${CYAN}[*] Provisioning directory structure...${NC}"
mkdir -p database logs reports backups quarantine config
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
    echo -e "${YELLOW}[!] Created .env from .env.example — review it before production use.${NC}"
fi
if [ ! -f config/license.key ] && [ -z "$INDRA_LICENSE_KEY" ]; then
    echo -e "${YELLOW}[!] No license key found. Place it in config/license.key or set INDRA_LICENSE_KEY.${NC}"
fi

# 5. Dependencies Installation
echo -e "${CYAN}[*] Installing verified Python dependencies...${NC}"
if [ "$IS_TERMUX" != true ]; then
    $PY_BIN -m pip install --upgrade pip setuptools wheel
fi
PY_BIN="$PY_BIN" bash ./install_deps.sh

# 6. Database and Config Initialization Check
echo -e "${CYAN}[*] Initializing Indra Infinity SQLite Database & Core Schemas...${NC}"
$PY_BIN -c "
import sys
try:
    from backend.database import init_db
    init_db()
    print('    [+] Database schemas initialized successfully.')
except Exception as e:
    print('    [!] Warning: database init deferred or encountered:', e)
"

# 7. Make scripts executable
chmod +x start.sh stop.sh status.sh update.sh backup.sh 2>/dev/null || true

echo -e "${GREEN}${BOLD}"
echo "=========================================================================="
echo " [+] INDRA INFINITY SECURITY ∞ INSTALLED SUCCESSFULLY!"
echo "=========================================================================="
echo -e "${NC}"
echo -e "To start the system (Backend + Dashboard + Six Eyes):"
echo -e "   ${BOLD}bash start.sh${NC}"
echo -e "To run the interactive Indra Terminal CLI:"
echo -e "   ${BOLD}python -m terminal.shell${NC} or ${BOLD}indra${NC}"
echo -e "To stop background services:"
echo -e "   ${BOLD}bash stop.sh${NC}"
echo ""
