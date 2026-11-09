#!/usr/bin/env bash
# Installs everything the framework needs on Kali / Debian (APT only, no pip).
set -euo pipefail
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

$SUDO apt update
$SUDO apt install -y python3 python3-flask nmap whatweb nikto sslscan wkhtmltopdf curl docker.io
$SUDO systemctl enable --now docker || true
mkdir -p "$HOME/VAPT-Project"/{recon,scans,evidence,reports,scripts,logs}

echo
echo "Setup complete."
echo "  Start practice labs : ./scripts/labs.sh start"
echo "  Start the app       : python3 vapt_app.py   (http://127.0.0.1:5000)"
